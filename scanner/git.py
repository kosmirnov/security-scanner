import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Tuple

from scanner.rules import SKIP_EXTENSIONS, SKIP_DIRS


def _should_skip(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False


def walk_local(repo_path: str) -> Generator[Tuple[str, str], None, None]:
    """Yield (relative_path, content) for each scannable file in a local repo."""
    root = Path(repo_path).resolve()
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if _should_skip(rel):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            yield str(rel), content
        except Exception:
            continue


def clone_and_walk(repo_url: str) -> Generator[Tuple[str, str], None, None]:
    """Clone a remote git/Bitbucket repo into a temp dir and walk it."""
    tmp_dir = tempfile.mkdtemp(prefix="sec-scanner-")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, tmp_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
        yield from walk_local(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def get_files(target: str) -> Generator[Tuple[str, str], None, None]:
    """Auto-detect whether target is a local path or remote URL."""
    if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
        yield from clone_and_walk(target)
    else:
        yield from walk_local(target)