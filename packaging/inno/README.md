# VStackLens Inno Setup Installer

This folder contains the first Windows installer scaffold for the M4 offline desktop package.

## Build Order

Build the PyInstaller onedir bundle first:

```powershell
.\packaging\build_desktop.ps1
```

Then compile the installer with Inno Setup 6:

```powershell
.\packaging\build_installer.ps1
```

The wrapper can find `iscc.exe` on `PATH` or under the default Inno Setup 6 install directory. Use `-IsccPath` when the compiler is installed elsewhere.

For manual Inno Setup work:

```powershell
iscc .\packaging\inno\vstacklens.iss
```

Expected output:

```text
dist\installer\VStackLens-Setup-0.2.8.exe
```

## Installer Scope

The installer wraps only the local desktop bundle from `dist\VStackLens` and adds:

- install directory under `%LOCALAPPDATA%\Programs\VStackLens`
- Start Menu shortcut
- Desktop shortcut
- uninstall entry through Windows Apps & Features

It must not add services, scheduled tasks, telemetry, or automatic network calls during install.

## Clean-VM Smoke Test

On a Windows VM without Python installed:

1. Install `dist\installer\VStackLens-Setup-0.2.8.exe`.
2. Launch VStackLens from the Start Menu.
3. Confirm the local login screen opens.
4. Confirm desktop data defaults still point to `%LOCALAPPDATA%\VStackLens`.
5. Validate the bundled rulepack from the desktop rulepack page.
6. Run a mock or real inspection and generate an offline customer report package.
7. Confirm the customer report contains only `index.html`, `assets/`, and `data/customer_report_payload.json`.
