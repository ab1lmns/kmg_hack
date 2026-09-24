"""Run the idempotent lab-only AD seed script through the existing SSH alias."""

import base64
import subprocess
from pathlib import Path


script = Path(__file__).with_name("Seed-DemoAD.ps1").read_text(encoding="utf-8")
encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
result = subprocess.run(
    ["ssh", "-o", "BatchMode=yes", "infraradar-dc", "powershell.exe",
     "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
    capture_output=True,
    text=True,
    timeout=120,
    check=False,
)
print(result.stdout.strip())
if result.returncode:
    print(result.stderr.strip())
raise SystemExit(result.returncode)
