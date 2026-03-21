import json
import csv
import os
from datetime import datetime


def _generate_filename(extension: str) -> str:
    """
    Generates a timestamped filename to avoid overwriting existing exports.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"password_analysis_{timestamp}.{extension}"


def _flatten_dict(d: dict, parent_key: str = "", sep: str = "_") -> dict:
    """
    Recursively flattens a nested dictionary into a single level.
    Nested keys are joined with the separator.
    Lists are joined with | for CSV compatibility.
    """
    items = {}
    for key, value in d.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(_flatten_dict(value, new_key, sep))
        elif isinstance(value, list):
            items[new_key] = "|".join(str(v) for v in value)
        else:
            items[new_key] = value
    return items


def export_json(results: dict | list, filepath: str = None) -> str:
    """
    Exports one or more analysis results to a JSON file.
    Returns the filepath written to.
    """
    if not filepath:
        filepath = _generate_filename("json")

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        return filepath
    except PermissionError:
        raise PermissionError(
            f"Permission denied writing to {filepath}. "
            f"Try a different location."
        )


def export_csv(results: dict | list, filepath: str = None) -> str:
    """
    Exports one or more analysis results to a CSV file.
    Accepts a single result dict or a list of result dicts.
    Column names are derived automatically from the result structure.
    List values are joined with | for CSV compatibility.
    Returns the filepath written to.
    """
    if not filepath:
        filepath = _generate_filename("csv")

    # normalize to list regardless of input type
    if isinstance(results, dict):
        results = [results]

    rows = [_flatten_dict(result) for result in results]
    fieldnames = rows[0].keys()

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return filepath
    except PermissionError:
        raise PermissionError(
            f"Permission denied writing to {filepath}. "
            f"Try a different location."
        )
