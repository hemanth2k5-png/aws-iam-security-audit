import zipfile
from pathlib import Path

FILES = ["main.py", "report.py", "history.py", "lambda_handler.py"]
OUT = Path("audit-lambda.zip")

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
    for name in FILES:
        zf.write(name)
    for path in sorted(Path("checks").glob("*.py")):
        zf.write(path, path.as_posix())

print(f"Built {OUT} ({OUT.stat().st_size} bytes)")