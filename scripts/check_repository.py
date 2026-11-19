"""Repository hygiene checks; not tests of the future signing backend."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
required = ["README.md", "LICENSE", "SECURITY.md", ".github/CODEOWNERS", ".github/workflows/ci.yml"]
for name in required:
    assert (root / name).is_file(), f"Required file missing: {name}"
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
for name in filter(None, files):
    p = Path(name)
    assert not any(part in {"node_modules", ".local", "secrets", "backups", ".terraform"} for part in p.parts), f"Forbidden tracked directory: {name}"
    assert not (p.name.startswith(".env") and p.name != ".env.example"), f"Environment file tracked: {name}"
    assert p.suffix.lower() not in {".pem", ".key", ".p12", ".pfx", ".jks", ".tfstate"}, f"Sensitive file type: {name}"
    assert (root / p).stat().st_size < 40 * 1024 * 1024, f"Large file must be reviewed: {name}"
print("Repository hygiene OK; secret scanning runs separately.")
