# VStackLens PyInstaller Packaging

This folder contains the first M4 packaging scaffold for the local Windows desktop app.

## Build

From the project root:

```powershell
.\packaging\build_desktop.ps1
```

For manual PyInstaller work:

```powershell
.\.python312\python.exe -m pip install -e ".[package]"
.\.python312\python.exe -m PyInstaller .\packaging\pyinstaller\vstacklens-desktop.spec --clean --noconfirm
```

The desktop app is written to:

```text
dist\VStackLens\VStackLens.exe
```

## Bundled Runtime Resources

The spec intentionally bundles:

- `src/vstacklens/db/schema.sql`
- `src/vstacklens/defaults/*.json`
- `src/vstacklens/reports/templates/*.j2`
- `rulepacks/builtin-vsphere-v1/**`

The application resolves those resources through `vstacklens.resources`, so the same code path works from source, editable installs, and PyInstaller bundles.

The desktop UI currently uses QtCore, QtGui, and QtWidgets only, so `PySide6-Essentials` is enough for packaging. Do not add the full `PySide6` dependency unless the app starts using modules from PySide6 Addons.

## Smoke Validation

Run these checks before installer work:

```powershell
.\.python312\python.exe -m pytest -q
.\.python312\python.exe -m vstacklens.cli validate-rules --rulepack .\rulepacks\builtin-vsphere-v1
.\.python312\python.exe -m compileall src tests
```

After building, launch `dist\VStackLens\VStackLens.exe` on a clean Windows VM without Python installed and verify:

- The login screen opens.
- Desktop default paths use `%LOCALAPPDATA%\VStackLens`.
- The rulepack page validates the bundled rulepack.
- A mock or real inspection can initialize SQLite and render an offline report package.
- The customer report still contains only `index.html`, `assets/`, and `data/customer_report_payload.json`.
