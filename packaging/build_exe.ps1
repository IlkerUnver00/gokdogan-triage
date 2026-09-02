# Build a standalone, single-file gokdogan.exe with PyInstaller.
#
#   .\packaging\build_exe.ps1
#
# Output: dist\gokdogan.exe — runs on any 64-bit Windows machine with no
# Python installed. Python, pefile, ppdeep, yara-python and the bundled YARA
# rules are all embedded. The optional web service is not included (it is a
# separate `pip install ".[web]"` concern, not a CLI feature).
# NOTE: PyInstaller logs INFO lines to stderr. Under Windows PowerShell 5.1
# with $ErrorActionPreference = "Stop" that would abort the build, so we keep
# the default preference and judge success by the exit code instead.
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")

# The import graph from entry.py -> gokdogan.cli pulls in every analyzer, so
# no --collect-submodules is needed; excluding the optional web stack keeps
# fastapi/uvicorn (which the CLI never imports) out of the binary.
pyinstaller --noconfirm --clean --onefile --console --name gokdogan `
    --paths . `
    --add-data "gokdogan/rules;gokdogan/rules" `
    --hidden-import yara `
    --hidden-import ppdeep `
    --exclude-module gokdogan.web `
    --exclude-module fastapi `
    --exclude-module uvicorn `
    --exclude-module starlette `
    packaging/entry.py
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "Built: $(Resolve-Path dist\gokdogan.exe)"
& .\dist\gokdogan.exe --version
if ($LASTEXITCODE -ne 0) { throw "frozen binary failed to run" }
