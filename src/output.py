import json
import csv
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.table import Table
from rich.text import Text


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


console = Console()


def _make_key_value_table(rows: list) -> Table:
    """
    Creates a borderless key-value table for use inside panels.
    Each row is a tuple of (key, value, value_style).
    """
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="white")
    table.add_column()
    for key, value, style in rows:
        table.add_row(key, f"[{style}]{value}[/{style}]")
    return table


def _rating_style(rating: str) -> str:
    """Maps a rating string to a Rich color style."""
    return {
        "very weak": "red",
        "weak": "yellow",
        "moderate": "yellow",
        "strong": "green",
        "very strong": "green",
        "invalid": "white",
    }.get(rating, "dim")


def _nist_style(status: str) -> str:
    """Maps a NIST status string to a Rich color style."""
    return {
        "compliant": "green",
        "non_compliant": "red",
        "incomplete": "yellow",
    }.get(status, "dim")


def _build_nist_panel(nist: dict, hibp: dict) -> Panel:
    """Builds the NIST compliance panel."""
    status = nist.get("status", "")
    failures = nist.get("failures", [])
    notes = nist.get("notes", [])
    style = _nist_style(status)

    content = Text()
    content.append(f"status: ", style="white")
    content.append(f"{status}\n", style=f"bold {style}")

    if failures:
        content.append("\n")
        for failure in failures:
            content.append(f"  x  {failure}\n", style="red")

    if notes:
        for note in notes:
            content.append(f"  !  {note}\n", style="yellow")

    if not failures and not notes:
        content.append("  \u2713  no failures", style="green")

    return Panel(
        content,
        title="[bold]nist sp 800-63-4 compliance[/bold]",
        border_style=style
    )


def _build_shannon_panel(shannon: dict) -> Panel:
    """Builds the Shannon entropy panel."""
    rows = [
        ("observed", f"{shannon.get('entropy_bits', 0)} bits", "white"),
        ("maximum", f"{shannon.get('max_entropy_bits', 0)} bits", "dim"),
        ("rating", shannon.get("rating", ""),
         _rating_style(shannon.get("rating", ""))),
    ]
    return Panel(
        _make_key_value_table(rows),
        title="[bold]shannon entropy[/bold]",
        border_style="blue"
    )


def _build_zxcvbn_panel(zxcvbn: dict) -> Panel:
    """Builds the zxcvbn panel."""
    rows = [
        ("score", f"{zxcvbn.get('score', 0)} / 4", "white"),
        ("crack time", zxcvbn.get("crack_time", ""), "white"),
        ("rating", zxcvbn.get("rating", ""),
         _rating_style(zxcvbn.get("rating", ""))),
    ]
    return Panel(
        _make_key_value_table(rows),
        title="[bold]zxcvbn[/bold]",
        border_style="blue"
    )


def _build_patterns_panel(patterns: dict) -> Panel:
    """Builds the pattern detection panel."""
    dictionary = patterns.get("dictionary_check", {})
    repeated = patterns.get("repeated_chars_check", {})
    walks = patterns.get("keyboard_walks_check", {})

    def pattern_row(label: str, result: dict):
        if result.get("found"):
            matches = ", ".join(result.get("matches", []))
            return f"  [red]detected — {matches}[/red]"
        return "  [green]clean[/green]"

    content = Text.from_markup(
        f"[white]dictionary[/white]         "
        f"{pattern_row('dictionary', dictionary)}\n"
        f"[white]repeated characters[/white] "
        f"{pattern_row('repeated', repeated)}\n"
        f"[white]keyboard walks[/white]      "
        f"{pattern_row('walks', walks)}"
    )

    any_found = patterns.get("patterns_found", False)
    return Panel(
        content,
        title="[bold]pattern detection[/bold]",
        border_style="red" if any_found else "green"
    )


def display_result(result: dict) -> None:
    """
    Renders the analysis result to the terminal using Rich.
    Handles the empty password failure case and all edge cases.
    Only called for single password analysis — not batch mode.
    """
    # handle empty password failure case
    if "failure" in result:
        console.print(Panel(
            f"[red]  x  {result['failure']}[/red]",
            title="[bold]error[/bold]",
            border_style="red"
        ))
        return

    password = result.get("password", "")
    hibp = result.get("hibp", {})
    patterns = result.get("patterns", {})
    strength = result.get("strength", {})

    console.print(
        f"\n[white]  analyzing: {password}[/white]\n"
    )

    # nist panel with full width
    console.print(_build_nist_panel(strength.get("nist", {}), hibp))

    # shannon and zxcvbn panels side by side
    console.print(Columns([
        _build_shannon_panel(strength.get("shannon", {})),
        _build_zxcvbn_panel(strength.get("zxcvbn", {})),
    ], expand=True))

    # pattern detection panel with full width
    console.print(_build_patterns_panel(patterns))

    # footer
    console.print(
        "[dim]  breach check: haveibeenpwned.com  |  "
        "pattern source: seclist 10k  |  "
        "nist sp 800-63-4[/dim]\n"
    )
