"""CSV export of audit events, with validation and spreadsheet-formula protection."""
from __future__ import annotations

import csv
import io

import pandas as pd

from database.store import EVENT_COLUMNS

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value):
    """Neutralise text that a spreadsheet could execute as a formula (CSV injection)."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def events_to_csv(df: pd.DataFrame) -> str:
    """Serialise events to CSV text. Raises ValueError if required columns are missing."""
    if df is None:
        raise ValueError("No data to export.")
    missing = [c for c in EVENT_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Cannot export: missing column(s) {', '.join(missing)}.")
    out = df[EVENT_COLUMNS].copy()
    for col in out.columns:
        if out[col].dtype == object or str(out[col].dtype).startswith("str"):
            out[col] = out[col].map(sanitize_cell)
    buf = io.StringIO()
    out.to_csv(buf, index=False, quoting=csv.QUOTE_MINIMAL)
    return buf.getvalue()


def validate_csv(text: str, expected_rows: int) -> list[str]:
    """Re-read exported text and check header, row count and row width. Returns a list of problems."""
    problems: list[str] = []
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return ["The CSV is empty."]
    if rows[0] != EVENT_COLUMNS:
        problems.append("The CSV header does not match the audit-log columns.")
    if len(rows) - 1 != expected_rows:
        problems.append(f"Expected {expected_rows} data row(s) but found {len(rows) - 1}.")
    if any(len(r) != len(EVENT_COLUMNS) for r in rows):
        problems.append("At least one row has the wrong number of columns.")
    return problems
