import json
from typing import List

import pandas as pd

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from scanner.llm import VerifiedFinding

console = Console()

SEVERITY_COLOURS = {
    "critical": "bold red",
    "high": "orange3",
    "medium": "yellow",
    "low": "blue",
}


def _severity_text(severity: str) -> Text:
    colour = SEVERITY_COLOURS.get(severity, "white")
    return Text(severity.upper(), style=colour)


def print_report(findings: List[VerifiedFinding]) -> None:
    real = [f for f in findings if f.is_real]
    false_positives = [f for f in findings if not f.is_real]

    console.print()
    console.rule("[bold]Security Scan Report[/bold]")
    console.print()

    if not findings:
        console.print("[green]No findings. Your repo looks clean![/green]")
        return

    table = Table(box=box.ROUNDED, show_lines=True, highlight=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("File", overflow="fold", max_width=40)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Rule", width=22)
    table.add_column("Match", overflow="fold", max_width=30)
    table.add_column("Real?", justify="center", width=6)
    table.add_column("Confidence", justify="center", width=10)
    table.add_column("Explanation", overflow="fold", max_width=40)
    table.add_column("Fix", overflow="fold", max_width=40)

    for vf in findings:
        f = vf.finding
        real_text = Text("YES", style="bold red") if vf.is_real else Text("NO", style="green")
        table.add_row(
            _severity_text(f.severity),
            f.file_path,
            str(f.line_number),
            f.rule_name,
            f.match,
            real_text,
            vf.confidence,
            vf.explanation,
            vf.fix,
        )

    console.print(table)
    console.print()
    console.print(f"[bold]Summary:[/bold] {len(findings)} findings total — "
                  f"[bold red]{len(real)} real[/bold red], "
                  f"[green]{len(false_positives)} false positives[/green]")
    console.print()


def save_json(findings: List[VerifiedFinding], output_path: str) -> None:
    data = [
        {
            "severity": vf.finding.severity,
            "file": vf.finding.file_path,
            "line": vf.finding.line_number,
            "rule": vf.finding.rule_name,
            "match": vf.finding.match,
            "line_content": vf.finding.line_content,
            "is_real": vf.is_real,
            "confidence": vf.confidence,
            "explanation": vf.explanation,
            "fix": vf.fix,
        }
        for vf in findings
    ]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]JSON report saved to {output_path}[/dim]")


def save_excel(findings: List[VerifiedFinding], output_path: str) -> None:
    data = [
        {
            "Severity": vf.finding.severity,
            "File": vf.finding.file_path,
            "Line": vf.finding.line_number,
            "Rule": vf.finding.rule_name,
            "Match": vf.finding.match,
            "Line Content": vf.finding.line_content,
            "Is Real": vf.is_real,
            "Confidence": vf.confidence,
            "Explanation": vf.explanation,
            "Fix": vf.fix,
        }
        for vf in findings
    ]
    df = pd.DataFrame(data)
    df.to_excel(output_path, index=False)
    console.print(f"[dim]Excel report saved to {output_path}[/dim]")