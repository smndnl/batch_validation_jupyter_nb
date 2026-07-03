from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Optional
from collections import deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_API_ENDPOINT_TEMPLATE = "/tax/calculation/v1/spaces/{space_id}/taxCall"
DEFAULT_OAUTH_ENDPOINT = "/oauth2/client_credential/gettoken"
DEFAULT_INPUT_SHEET = ""
DEFAULT_TIMEOUT_SECONDS = 60

ENGINE_API = {
    "uat" : "https://api.uat.btx.eu.banqup.com",
    "cve" :  "https://api.cve.btx.eu.banqup.com" 
}

DEFAULT_NA_VALUES = [
    "",
    " ",
    "#N/A",
    "#N/A N/A",
    "#NA",
    "-1.#IND",
    "-1.#QNAN",
    "-NaN",
    "-nan",
    "1.#IND",
    "1.#QNAN",
    "<NA>",
    "N/A",
    "NA",
    "NaN",
    "None",
    "n/a",
    "nan",
]

DATE_COLUMNS = ["taxRelevantDate", "documentDate", "postingDate", "paymentDate", "deliveryDate"]

FULL_OUTPUT_SHEET = "full_output"
COMPARISON_SHEET = "comparisons"
INPUT_DATA_SHEET = "input_data"
ROW_ID_COLUMN = "row_id"

FULL_OUTPUT_COLUMNS = [
    "API Input",
    "API Output",
    "Timestamp",
    "Response Time (ms)",
]

COMPARISON_COLUMNS = [
    ROW_ID_COLUMN,
    "API Input",
    "API Output",
    "Timestamp",
    "Comparison field",
    "Expected value",
    "Engine value",
]


@dataclass
class ValidationStats:
    rows_total: int
    rows_processed: int
    api_calls: int
    success_count: int
    failure_count: int
    mismatch_count: int
    comparison_count: int
    average_response_time_ms: float
    elapsed_time_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OAuthClientCredentials:
    def __init__(self, config: dict[str, Any], session: requests.Session, timeout_seconds: int) -> None:
        self.config = config
        self.session = session
        self.timeout_seconds = timeout_seconds
        self._access_token: str | None = None
        self._expires_at: float | None = None

    def _fetch_new_token(self) -> str:
        client_id = (
            self.config.get("client_id")
        )
        client_secret = (
            self.config.get("client_secret")
        )
        token_url = _build_endpoint_url(base_url = ENGINE_API[self.config.get("selected_env","uat")], endpoint_template = DEFAULT_OAUTH_ENDPOINT) 

        if not client_id or not client_secret:
            raise ValueError(
                "Missing OAuth client credentials. Provide client_id/client_secret in config screen."
            )
        if not token_url:
            raise ValueError("Missing OAuth token URL. Set token_url in config screen.")

        token_payload = {"grant_type": "client_credentials", 
                         "client_id" :str(client_id), 
                         "client_secret" : str(client_secret)}
        scope = self.config.get("oauth_scope") or os.getenv("OAUTH_SCOPE")
        if scope:
            token_payload["scope"] = str(scope)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PostmanRuntime/7.51.1"
            }
        response = self.session.post(
            str(token_url),
            headers=headers,
            data=token_payload,
            timeout=self.timeout_seconds,
            verify=True,
        )
        response.raise_for_status()

        data = response.json()
        access_token = data.get("access_token")
        if not access_token:
            raise ValueError("Token endpoint response did not include access_token.")

        expires_at_raw = data.get("expires_at")
        self._access_token = str(access_token)

        if expires_at_raw:
            # Parse ISO-8601 timestamps like "2026-02-03T20:15:20.465Z"
            try:
                # Python's fromisoformat doesn't accept trailing "Z", so normalize it
                expires_dt = datetime.fromisoformat(str(expires_at_raw).replace("Z", "+00:00"))
            except Exception as e:
                raise ValueError(f"Invalid expires_at format: {expires_at_raw!r}") from e
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            self._expires_at = expires_dt.timestamp()
        else:
            expires_in = data.get("expires_in")
            if expires_in is None:
                raise ValueError("Token endpoint response did not include expires_at or expires_in.")
            self._expires_at = time.time() + float(expires_in)

        return self._access_token
    
    def refresh_token_if_needed(self) -> None:
        now = time.time()
        refresh_buffer_seconds = 10
        if self._access_token and self._expires_at and now < (self._expires_at - refresh_buffer_seconds):
            return

        self._fetch_new_token()
    
    def get_token(self) -> str:
        self.refresh_token_if_needed()
        if not self._access_token:
            raise ValueError("OAuth access token is not available.")
        return self._access_token

class RateLimiter:
    def __init__(self, max_requests=300, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
    
    def wait_if_needed(self):
        """Wait if necessary to comply with rate limit"""
        current_time = time.time()
        
        # Remove requests older than time_window
        while self.requests and self.requests[0] < current_time - self.time_window:
            self.requests.popleft()
        
        # If we're at the limit, wait until we can make another request
        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.time_window - current_time + 0.1  # Small buffer
            if sleep_time > 0:
                time.sleep(sleep_time)
                # Clean up again after waiting
                current_time = time.time()
                while self.requests and self.requests[0] < current_time - self.time_window:
                    self.requests.popleft()
        
        # Record this request
        self.requests.append(current_time)

def run_validation(input_excel_bytes: bytes, *, config: dict) -> bytes:
    """Run validation and return output Excel bytes.

    Stable function signature consumed by both desktop and web UIs.
    """
    output_bytes, _stats = run_validation_with_details(input_excel_bytes, config=config)
    return output_bytes


def run_validation_with_details(input_excel_bytes: bytes, *, config: dict) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(input_excel_bytes, (bytes, bytearray)):
        raise ValueError("input_excel_bytes must be bytes.")

    runtime_config = dict(config or {})
    process_mode = str(runtime_config.get("process_mode", "both")).strip().lower()
    space_id = runtime_config.get("space_id")

    timeout_seconds = DEFAULT_TIMEOUT_SECONDS
    base_url = str(ENGINE_API[runtime_config.get("selected_env", "uat")])
    endpoint_template = str(runtime_config.get("api_endpoint_template", DEFAULT_API_ENDPOINT_TEMPLATE))
    endpoint_url = _build_endpoint_url(base_url=base_url, endpoint_template=endpoint_template, space_id=str(space_id))

    progress_callback = runtime_config.get("progress_callback")
    _emit_progress(progress_callback, stage="ingestion", message="Reading input Excel file...")

    df_raw = _read_input_dataframe(input_excel_bytes=input_excel_bytes)
    df_input, df_comparison, output_template = _split_input_sections(df_raw)
    df_input_with_row_id = _with_row_id(df_input)
    _emit_progress(progress_callback, stage="ingestion", message="Input data loaded.")
    
    # Count how many input lines to process - limit to 20k tax calls
    if len(df_input) > 20000:
        raise ValueError("Input data has to contain max. 20 thousand lines")
    
    mapping_file, mapping_output_file = _resolve_mapping_paths(runtime_config)
    mapping_dict, bool_columns, double_columns = _load_mapping(mapping_file)
    mapping_output_dict = _load_output_mapping(mapping_output_file)
    _emit_progress(progress_callback, stage="mapping", message="Mappings loaded.")

    start_time = time.time()
    api_calls = 0
    success_count = 0
    response_times: list[float] = []
    skipped_rows: set[int] = set()

    output_df = output_template.copy().reset_index(drop=True)
    template_columns = _unique_ordered(output_df.columns)
    output_mapping_columns = _unique_ordered(mapping_output_dict.keys())
    managed_columns = [ROW_ID_COLUMN] + FULL_OUTPUT_COLUMNS + output_mapping_columns + ["Comparables"]
    if len(output_df.columns) > 0:
        output_df = output_df.loc[:, ~output_df.columns.isin(managed_columns)].copy()
    output_df[ROW_ID_COLUMN] = df_input_with_row_id[ROW_ID_COLUMN].to_numpy()
    additional_columns = [
        column
        for column in (FULL_OUTPUT_COLUMNS + output_mapping_columns + ["Comparables"])
        if column not in output_df.columns
    ]
    if additional_columns:
        # Add all missing columns in one shot to avoid DataFrame fragmentation warnings.
        output_df = pd.concat(
            [
                output_df,
                pd.DataFrame(None, index=output_df.index, columns=additional_columns),
            ],
            axis=1,
        )

    session = requests.Session()
    # Fetch new token every few minutes - not after each call!
    auth = OAuthClientCredentials(runtime_config, session=session, timeout_seconds=timeout_seconds)
    # Initialize rate limiter for 300 RPM
    rate_limiter = RateLimiter(max_requests=300, time_window=60)
    total_calls_to_make = _count_rows_to_call(df_input_with_row_id)
    completed_calls = 0
    emit_every = max(1, total_calls_to_make // 200) if total_calls_to_make else 1
    _emit_progress(
        progress_callback,
        stage="api_calls",
        message=f"Starting tax calculation calls (0/{total_calls_to_make})",
        completed=0,
        total=total_calls_to_make,
    )

    for row_position, (_, row) in enumerate(df_input_with_row_id.iterrows()):
        if _should_skip_row(row.get("Skip test")):
            skipped_rows.add(row_position)
            output_df.at[row_position, "API Input"] = "SKIPPED"
            continue

        payload = _build_payload(
            row=row,
            mapping_dict=mapping_dict,
            boolean_columns=bool_columns,
            double_columns=double_columns,
        )

        api_calls += 1
        response_timestamp = None
        response_time_ms = None
        comparables_dict: dict[str, tuple[Any, Any]] = {}

        try:
            # Apply rate limiting before making the API call
            rate_limiter.wait_if_needed()
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Audit-Trail": "false",
                "Authorization": f"Bearer {auth.get_token()}",
                "User-Agent" : "'PostmanRuntime/7.51.1"
            }

            api_start = time.time()
            response = session.post(
                endpoint_url,
                headers=headers,
                json=payload,
                timeout=timeout_seconds,
                verify=False
            )
            response_time_ms = (time.time() - api_start) * 1000
            response_timestamp = response.headers.get("date")
            response_times.append(response_time_ms)

            if response.status_code == 200:
                success_count += 1
                response_json = response.json()
                flattened = _flatten_json(response_json)
                comparables_dict = _build_comparables(df_comparison, row_position, mapping_output_dict, flattened)
                _populate_full_output_fields(
                    output_df=output_df,
                    row_position=row_position,
                    flattened_output=flattened,
                    output_mapping=mapping_output_dict,
                )

                output_df.at[row_position, "API Input"] = json.dumps(payload, indent=2, default=str)
                output_df.at[row_position, "API Output"] = json.dumps(response_json, indent=2, default=str)
                output_df.at[row_position, "Timestamp"] = response_timestamp
                output_df.at[row_position, "Response Time (ms)"] = round(response_time_ms, 2)
                output_df.at[row_position, "Comparables"] = comparables_dict
            else:
                output_df.at[row_position, "API Input"] = json.dumps(payload, indent=2, default=str)
                output_df.at[row_position, "API Output"] = f"HTTP {response.status_code}: {response.text}"
                output_df.at[row_position, "Timestamp"] = response_timestamp
                output_df.at[row_position, "Response Time (ms)"] = round(response_time_ms, 2)
                if output_mapping_columns:
                    output_df.at[row_position, output_mapping_columns[0]] = response.text

                expected_bad_request = _get_expected_bad_request(df_comparison, row_position)
                if expected_bad_request is True:
                    success_count += 1
                comparables_dict = {"BAD REQUEST CHECK": (expected_bad_request, "BAD REQUEST")}
                output_df.at[row_position, "Comparables"] = comparables_dict

        except Exception as exc: 
            output_df.at[row_position, "API Input"] = json.dumps(payload, indent=2, default=str)
            output_df.at[row_position, "API Output"] = f"{type(exc).__name__}: {exc}"
            output_df.at[row_position, "Timestamp"] = response_timestamp
            output_df.at[row_position, "Response Time (ms)"] = round(response_time_ms, 2) if response_time_ms else None
            if output_mapping_columns:
                output_df.at[row_position, output_mapping_columns[0]] = f"{type(exc).__name__}: {exc}"
            output_df.at[row_position, "Comparables"] = {f"{type(exc).__name__} Error": (None, type(exc).__name__)}
        finally:
            completed_calls += 1
            if (
                completed_calls == 1
                or completed_calls == total_calls_to_make
                or completed_calls % emit_every == 0
            ):
                _emit_progress(
                    progress_callback,
                    stage="api_calls",
                    message=f"Tax calculation calls: {completed_calls}/{total_calls_to_make}",
                    completed=completed_calls,
                    total=total_calls_to_make,
                )

    if skipped_rows:
        output_df = output_df.drop(index=list(skipped_rows)).reset_index(drop=True)
    input_data_df = df_input_with_row_id.reset_index(drop=True)

    _emit_progress(progress_callback, stage="post_processing", message="Processing output data...")
    full_output_columns = _unique_ordered([ROW_ID_COLUMN] + template_columns + output_mapping_columns)
    full_output_df = output_df.reindex(columns=full_output_columns).copy()
    
    mismatch_df, comparison_count = _build_mismatch_dataframe(output_df, template_columns=template_columns)
    _emit_progress(progress_callback, stage="post_processing", message="Output data processed.")

    average_response_time = float(np.mean(response_times)) if response_times else 0.0
    elapsed_time = round(time.time() - start_time, 3)

    stats = ValidationStats(
        rows_total=len(df_input),
        rows_processed=len(full_output_df),
        api_calls=api_calls,
        success_count=success_count,
        failure_count=max(0, api_calls - success_count),
        mismatch_count=len(mismatch_df),
        comparison_count=comparison_count,
        average_response_time_ms=round(average_response_time, 2),
        elapsed_time_seconds=elapsed_time,
    )

    output_bytes = _write_output_workbook(
        process_mode=process_mode,
        input_data_df=input_data_df,
        full_output_df=full_output_df,
        mismatch_df=mismatch_df,
    )
    _emit_progress(progress_callback, stage="done", message="Validation finished.")

    return output_bytes, stats.to_dict()


def run_batch_validation(
    input_xlsx: Path | str,
    *,
    environment: str,
    space_id: str,
    process_mode: str = "both",
    output_dir: Path | str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Run a workbook validation from a notebook-friendly file path.

    The mapping workbooks are resolved beside this file, so the whole client
    folder can be renamed or moved as long as these files stay together:
    - validation_engine.py
    - json_mapper.xlsx
    - json_mapper_output.xlsx
    - the notebook
    """
    engine_dir = Path(__file__).resolve().parent
    input_path = Path(input_xlsx).expanduser().resolve()
    resolved_output_dir = Path(output_dir or (engine_dir / "outputs")).expanduser().resolve()
    selected_environment = environment.strip().lower()
    selected_process_mode = process_mode.strip().lower()

    if not input_path.exists():
        raise FileNotFoundError(f"Input workbook not found: {input_path}")
    if input_path.suffix.lower() != ".xlsx":
        raise ValueError("input_xlsx must point to an .xlsx file.")
    if selected_environment not in {"uat", "cve"}:
        raise ValueError("environment must be 'uat' or 'cve'.")
    if selected_process_mode not in {"comparisons_only", "full_output", "both"}:
        raise ValueError("process_mode must be 'comparisons_only', 'full_output', or 'both'.")
    if not space_id.strip():
        raise ValueError("space_id is required.")

    def _default_progress(event: dict[str, Any]) -> None:
        stage = event.get("stage", "working")
        message = event.get("message", "Working...")
        print(f"{stage:>16}: {message}")

    config = {
        "selected_env": selected_environment,
        "space_id": space_id.strip(),
        "process_mode": selected_process_mode,
        "mapping_file": engine_dir / "json_mapper.xlsx",
        "mapping_output_file": engine_dir / "json_mapper_output.xlsx",
        "client_id": client_id,
        "client_secret": client_secret,
        "progress_callback": progress_callback or _default_progress,
        "requested_by": "jupyter-notebook",
    }

    output_bytes, stats = run_validation_with_details(input_path.read_bytes(), config=config)
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = resolved_output_dir / f"validation_result_{timestamp}.xlsx"
    output_path.write_bytes(output_bytes)
    return {"output_path": output_path, "stats": stats}


def _read_input_dataframe(input_excel_bytes: bytes, sheet_name: Optional[str] = 0) -> pd.DataFrame:
    try:
        return pd.read_excel(
            BytesIO(input_excel_bytes),
            sheet_name=sheet_name,
            keep_default_na=False,
            na_values=DEFAULT_NA_VALUES,
            dtype=str,
        )
    except ValueError as exc:
        if "Worksheet" in str(exc):
            raise ValueError(
                f"Input workbook must contain sheet '{sheet_name}'."
            ) from exc
        raise


def _split_input_sections(df_raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    callindicator_columns = [i for i, col in enumerate(df_raw.columns) if "callIndicator" in str(col)]
    if not callindicator_columns:
        raise ValueError("Could not find columns containing 'callIndicator' in the uploaded file.")

    first_call_start = callindicator_columns[0]
    divider_indices = [
        i
        for i in range(first_call_start, len(df_raw.columns))
        if _is_divider_column(df_raw.columns[i])
    ]

    if divider_indices:
        divider_index = divider_indices[0]
        df_input = df_raw.iloc[:, first_call_start:divider_index].copy()
        df_comparison = df_raw.iloc[:, divider_index + 1 :].copy()
    else:
        df_input = df_raw.iloc[:, first_call_start:].copy()
        df_comparison = pd.DataFrame(index=df_raw.index)

    if "Skip test" in df_raw.columns and "Skip test" not in df_input.columns:
        df_input["Skip test"] = df_raw["Skip test"]

    if not df_comparison.empty:
        renamed = [
            ".".join(col.split(".")[:-1]) if str(col).split(".")[-1] == "1" else col
            for col in df_comparison.columns
        ]
        df_comparison.columns = renamed

    df_input = _normalize_date_columns(df_input)
    df_comparison = _normalize_date_columns(df_comparison)

    output_template = df_raw.iloc[:, : min(6, len(df_raw.columns))].copy()
    if output_template.empty:
        output_template = pd.DataFrame(index=df_raw.index)

    return df_input, df_comparison, output_template


def _normalize_date_columns(df: pd.DataFrame) -> pd.DataFrame:
    normalized = df.copy()
    for col in DATE_COLUMNS:
        if col not in normalized.columns:
            continue
        series = normalized[col]
        parsed = pd.to_datetime(series, format="ISO8601", errors="coerce")
        unresolved = parsed.isna() & series.notna()
        if unresolved.any():
            parsed.loc[unresolved] = pd.to_datetime(series[unresolved], errors="coerce")
        normalized[col] = parsed.dt.strftime("%Y-%m-%d")
    return normalized


def _build_payload(
    row: pd.Series,
    mapping_dict: dict[str, str],
    boolean_columns: set[str],
    double_columns: set[str],
) -> dict[str, Any]:
    payload: dict[str, Any] = {}

    for template_col, json_path in mapping_dict.items():
        if template_col not in row:
            continue

        value = row[template_col]
        if pd.isna(value):
            continue

        if template_col in boolean_columns:
            value = _coerce_bool(value)
        elif template_col in double_columns:
            value = _coerce_float(value)

        nested = _create_nested_dict(json_path.split("."), value, {})
        if nested:
            _merge_dicts(nested, payload)

    return payload


def _coerce_bool(value: Any) -> Any:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
        return value
    return bool(value)


def _coerce_float(value: Any) -> Any:
    converted = pd.to_numeric(value, errors="coerce")
    if pd.isna(converted):
        return "CONVERSION_ERROR"
    if isinstance(converted, np.integer):
        return int(converted)
    if isinstance(converted, np.floating):
        return float(converted)
    return converted


def _create_nested_dict(keys: list[str], value: Any, existing: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if pd.isna(value):
        return None
    if not keys:
        return value

    key = keys[0]
    list_match = re.match(r"(\w+)\[(\d+)\]", key)

    if list_match:
        list_key, index_str = list_match.groups()
        index = int(index_str)
        if existing is None:
            existing = {}
        if list_key not in existing:
            existing[list_key] = []
        while len(existing[list_key]) <= index:
            existing[list_key].append({})
        existing[list_key][index] = _create_nested_dict(keys[1:], value, existing[list_key][index])
        return existing

    if existing is None:
        existing = {}
    if key not in existing:
        existing[key] = {}
    existing[key] = _create_nested_dict(keys[1:], value, existing[key])
    return existing


def _merge_dicts(source: dict[str, Any], destination: dict[str, Any]) -> None:
    for key, value in source.items():
        if value is None:
            continue

        if isinstance(value, dict):
            destination.setdefault(key, {})
            _merge_dicts(value, destination[key])
        elif isinstance(value, list):
            destination.setdefault(key, [])
            while len(destination[key]) < len(value):
                destination[key].append({})
            for index, item in enumerate(value):
                _merge_dicts(item, destination[key][index])
        else:
            destination[key] = value


def _flatten_json(value: Any, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    items: dict[str, Any] = {}
    if isinstance(value, dict):
        if parent_key.split(sep)[-1] == "transactionMemos":
            items[parent_key] = value
            return items
        for key, nested_value in value.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            items.update(_flatten_json(nested_value, new_key, sep=sep))
    elif isinstance(value, list):
        if len(value) == 0:
            items[parent_key] = value
        for index, nested_value in enumerate(value):
            new_key = f"{parent_key}[{index}]" if parent_key else str(index)
            items.update(_flatten_json(nested_value, new_key, sep=sep))
    else:
        items[parent_key] = value
    return items


def _build_comparables(
    df_comparison: pd.DataFrame,
    row_position: int,
    output_mapping: dict[str, str],
    flattened_output: dict[str, Any],
) -> dict[str, tuple[Any, Any]]:
    if df_comparison.empty or row_position >= len(df_comparison):
        return {}

    comparison_row = df_comparison.iloc[row_position]
    comparison_dict = comparison_row.dropna().to_dict()
    comparables: dict[str, tuple[Any, Any]] = {}

    for key, expected_value in comparison_dict.items():
        output_path = output_mapping.get(key)
        engine_value = flattened_output.get(output_path, "Field n/a") if output_path else "Field n/a"
        comparables[key] = (expected_value, engine_value)

    return comparables


def _populate_full_output_fields(
    output_df: pd.DataFrame,
    row_position: int,
    flattened_output: dict[str, Any],
    output_mapping: dict[str, str],
) -> None:
    for template_column, json_path in output_mapping.items():
        if template_column in FULL_OUTPUT_COLUMNS:
            continue
        output_df.at[row_position, template_column] = flattened_output.get(json_path)


def _build_mismatch_dataframe(
    output_df: pd.DataFrame,
    *,
    template_columns: list[str],
) -> tuple[pd.DataFrame, int]:
    if "Comparables" not in output_df.columns or output_df.empty:
        return pd.DataFrame(columns=_comparison_output_columns(template_columns)), 0

    working = output_df.copy()
    working["Comparison field"] = working["Comparables"].apply(
        lambda value: list(value.keys()) if isinstance(value, dict) and value else []
    )
    exploded = working.explode("Comparison field")
    exploded = exploded[exploded["Comparison field"].notna()].copy()

    if exploded.empty:
        return pd.DataFrame(columns=_comparison_output_columns(template_columns)), 0

    exploded["Expected value"] = exploded.apply(
        lambda row: row["Comparables"].get(row["Comparison field"], (None, None))[0]
        if isinstance(row["Comparables"], dict)
        else None,
        axis=1,
    )
    exploded["Engine value"] = exploded.apply(
        lambda row: row["Comparables"].get(row["Comparison field"], (None, None))[1]
        if isinstance(row["Comparables"], dict)
        else None,
        axis=1,
    )
    exploded["Result"] = exploded.apply(
        lambda row: _compare_values(row["Expected value"], row["Engine value"]),
        axis=1,
    )

    comparison_count = int(len(exploded))
    mismatches = exploded[exploded["Result"] != True].copy()  # noqa: E712
    mismatches = mismatches.drop(columns=["Comparables", "Result"], errors="ignore")

    comparison_columns = _comparison_output_columns(template_columns)
    for column in comparison_columns:
        if column not in mismatches.columns:
            mismatches[column] = None
    mismatches = mismatches[comparison_columns]
    mismatches.reset_index(drop=True, inplace=True)

    return mismatches, comparison_count


def _compare_values(expected_value: Any, engine_value: Any) -> bool | None:
    if pd.isna(expected_value) or expected_value == "":
        return None

    expected_text = str(expected_value).strip()
    expected_lower = expected_text.lower()

    if engine_value == "BAD REQUEST":
        return expected_text in {"True", "TRUE", "true"}

    if isinstance(engine_value, list) and len(engine_value) == 0:
        return expected_lower.startswith("\\is_null") or expected_lower == "null"

    if pd.isna(engine_value) or engine_value == "Field n/a":
        return expected_lower.startswith("\\is_null") or expected_lower == "null"

    if expected_lower.startswith("\\is_null") or expected_lower == "null":
        return pd.isna(engine_value)

    if expected_lower.startswith("\\is_not_null"):
        return not pd.isna(engine_value)

    if expected_lower.startswith("\\contains"):
        text = expected_text.replace("\\contains", "", 1).strip().lower()
        return text in str(engine_value).lower()

    if expected_lower.startswith("\\not_contains"):
        text = expected_text.replace("\\not_contains", "", 1).strip().lower()
        return text not in str(engine_value).lower()

    if expected_lower.startswith("\\not_equal"):
        text = expected_text.replace("\\not_equal", "", 1).strip()
        try:
            return float(text) != float(engine_value)
        except Exception:  # noqa: BLE001
            return text.lower() != str(engine_value).strip().lower()

    try:
        return float(expected_value) == float(engine_value)
    except Exception:  # noqa: BLE001
        return str(expected_value).strip().lower() == str(engine_value).strip().lower()


def _write_output_workbook(
    process_mode: str,
    input_data_df: pd.DataFrame,
    full_output_df: pd.DataFrame,
    mismatch_df: pd.DataFrame,
) -> bytes:
    output_buffer = BytesIO()
    with pd.ExcelWriter(output_buffer, engine="openpyxl") as writer:
        if process_mode in {"comparisons_only", "both"}:
            _safe_to_excel(mismatch_df, writer, COMPARISON_SHEET)
        if process_mode in {"full_output", "both"}:
            _safe_to_excel(full_output_df, writer, FULL_OUTPUT_SHEET)
        _safe_to_excel(input_data_df, writer, INPUT_DATA_SHEET)    

    output_buffer.seek(0)
    return output_buffer.getvalue()


def _safe_to_excel(df: pd.DataFrame, writer: pd.ExcelWriter, sheet_name: str) -> None:
    if df is None or df.empty:
        placeholder = pd.DataFrame([{"info": "No rows to export."}])
        placeholder.to_excel(writer, sheet_name=sheet_name, index=False)
        return
    df.to_excel(writer, sheet_name=sheet_name, index=False)


def _comparison_output_columns(template_columns: list[str]) -> list[str]:
    standard_columns = [column for column in COMPARISON_COLUMNS if column != ROW_ID_COLUMN]
    return _unique_ordered([ROW_ID_COLUMN] + template_columns + standard_columns)


def _load_mapping(path: Path) -> tuple[dict[str, str], set[str], set[str]]:
    mapping_df = pd.read_excel(path)
    mapping_dict = dict(zip(mapping_df["Template column"], mapping_df["JSON schema name"]))
    bool_columns = set(mapping_df[mapping_df["dataType"] == "BOOLEAN"]["Template column"].tolist())
    double_columns = set(mapping_df[mapping_df["dataType"] == "DOUBLE"]["Template column"].tolist())
    return mapping_dict, bool_columns, double_columns


def _load_output_mapping(path: Path) -> dict[str, str]:
    mapping_df = pd.read_excel(path)
    return dict(zip(mapping_df["Template column"], mapping_df["JSON schema name"]))


def _resolve_mapping_paths(config: dict[str, Any]) -> tuple[Path, Path]:
    repo_root = Path(__file__).resolve().parent.parent
    mapping_file = Path(config.get("mapping_file") or (repo_root / "json_mapper.xlsx"))
    mapping_output_file = Path(config.get("mapping_output_file") or (repo_root / "json_mapper_output.xlsx"))

    if not mapping_file.exists():
        raise FileNotFoundError(f"Mapping file not found: {mapping_file}")
    if not mapping_output_file.exists():
        raise FileNotFoundError(f"Output mapping file not found: {mapping_output_file}")

    return mapping_file, mapping_output_file


def _is_divider_column(column_name: Any) -> bool:
    if pd.isna(column_name):
        return True
    name = str(column_name)
    return name == "" or "Unnamed" in name


def _build_endpoint_url(base_url: str, endpoint_template: str, * , space_id: str | None = None) -> str:
    if "{space_id}" in endpoint_template:
        escaped_space_id = requests.utils.quote(space_id, safe="")
        endpoint = endpoint_template.format(space_id=escaped_space_id)
    else:
        endpoint = endpoint_template
    return f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"


def _should_skip_row(value: Any) -> bool:
    if value is None or pd.isna(value):
        return False
    return str(value).strip().lower() in {"true", "1", "yes"}


def _get_expected_bad_request(df_comparison: pd.DataFrame, row_position: int) -> bool | None:
    if df_comparison.empty or row_position >= len(df_comparison) or "BAD REQUEST" not in df_comparison.columns:
        return None

    value = df_comparison.iloc[row_position].get("BAD REQUEST")
    if value is None or pd.isna(value):
        return None
    return str(value).strip().lower() in {"true", "1", "yes"}


def _with_row_id(df_input: pd.DataFrame) -> pd.DataFrame:
    result = df_input.copy()
    # Always use a deterministic generated row_id for matching input/output rows.
    if ROW_ID_COLUMN in result.columns:
        result = result.drop(columns=[ROW_ID_COLUMN])
    result.insert(0, ROW_ID_COLUMN, np.arange(1, len(result) + 1))
    return result


def _count_rows_to_call(df_input: pd.DataFrame) -> int:
    if "Skip test" not in df_input.columns:
        return int(len(df_input))

    skip_mask = df_input["Skip test"].apply(_should_skip_row)
    return int((~skip_mask).sum())


def _emit_progress(
    progress_callback: Any,
    *,
    stage: str,
    message: str,
    completed: int | None = None,
    total: int | None = None,
) -> None:
    if not callable(progress_callback):
        return
    payload: dict[str, Any] = {"stage": stage, "message": message}
    if completed is not None:
        payload["completed"] = completed
    if total is not None:
        payload["total"] = total
    progress_callback(payload)


def _unique_ordered(values: Any) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result
