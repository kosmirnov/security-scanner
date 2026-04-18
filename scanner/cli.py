import asyncio
import subprocess

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.git import get_files
from scanner.rules import scan_content
from scanner.llm import verify_findings
from scanner.report import print_report, save_json, save_excel
from scanner.agents.pr_review_agent import generate_questions, generate_verdict

console = Console()


@click.group()
def cli():
    """Security Scanner — detect secrets and insecure patterns in your codebase."""
    pass


@cli.command()
@click.argument("target")
@click.option("--output-json", default=None, help="Save report as JSON to this path.")
@click.option("--output-excel", default=None, help="Save report as Excel to this path.")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM verification (faster, more false positives).")
def scan(target, output_json, output_excel, no_llm):
    """Scan a local repo path or remote git/Bitbucket URL for security issues.

    TARGET can be a local directory path or a remote git URL.

    Examples:\n
        python main.py scan ./my-repo\n
        python main.py scan https://github.com/org/repo\n
        python main.py scan git@bitbucket.org:org/repo.git --output-excel report.xlsx
    """
    all_findings = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        task = progress.add_task("Scanning files...", total=None)

        for file_path, content in get_files(target):
            findings = scan_content(file_path, content)
            all_findings.extend(findings)

        progress.update(task, description=f"Found {len(all_findings)} raw findings. Running LLM verification...")

    if not all_findings:
        console.print("[green]No findings detected. Your repo looks clean![/green]")
        return

    if no_llm:
        console.print(f"[yellow]Skipping LLM verification (--no-llm flag set).[/yellow]")
        from scanner.llm import VerifiedFinding
        verified = [
            VerifiedFinding(finding=f, is_real=True, confidence="unknown",
                            explanation="LLM verification skipped.", fix="")
            for f in all_findings
        ]
    else:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
            progress.add_task("Verifying findings with Claude...", total=None)
            verified = verify_findings(all_findings)

    print_report(verified)

    if output_json:
        save_json(verified, output_json)

    if output_excel:
        save_excel(verified, output_excel)


@cli.command()
def review():
    """Run a viva voce code review on the last commit — answer questions to approve the PR."""

    # get the diff from the last commit
    result = subprocess.run(["git", "diff", "HEAD~1"], capture_output=True, text=True)
    diff = result.stdout.strip()

    if not diff:
        console.print("[yellow]No diff found. Make sure you have at least one commit.[/yellow]")
        return

    # generate questions from the diff
    console.print("\n[bold cyan]Analysing your diff...[/bold cyan]")
    questions = asyncio.run(generate_questions(diff))

    # prompt the user to answer each question
    answers = []
    console.print("\n[bold yellow]Answer the following questions to get your PR approved:[/bold yellow]\n")
    for i, question in enumerate(questions, start=1):
        console.print(f"[bold]Q{i}:[/bold] {question}")
        answer = click.prompt("Your answer")
        answers.append(answer)
        console.print()

    # evaluate answers and return verdict
    console.print("[bold cyan]Evaluating your answers...[/bold cyan]")
    verdict = asyncio.run(generate_verdict(diff, questions, answers))

    if verdict.decision == "APPROVE":
        console.print(f"\n[bold green]✓ {verdict.decision}[/bold green]")
    else:
        console.print(f"\n[bold red]✗ {verdict.decision}[/bold red]")

    console.print(f"[dim]{verdict.feedback}[/dim]")
