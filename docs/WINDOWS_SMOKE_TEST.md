# Windows Smoke Test

Use this procedure on a clean Windows VM before handing the installer to a customer site.

## Preconditions

- Use a Windows VM without Python installed.
- Build the handoff folder from the project root:

```powershell
.\packaging\build_handoff.ps1
```

- Copy the files from `dist\handoff` to the VM:

```text
VStackLens-Setup-0.2.0.exe
smoke_installed.ps1
WINDOWS_SMOKE_TEST.md
REAL_VCENTER_VALIDATION.md
```

The smoke script is not embedded into the installer. It must be copied with the installer or generated through `packaging\build_handoff.ps1`.

## Install

1. Run `VStackLens-Setup-0.2.0.exe`.
2. Confirm installation completes without requiring Python.
3. Run the installed bundle smoke check from the copied handoff folder:

```powershell
.\smoke_installed.ps1
```

Expected result:

```text
Installed VStackLens bundle smoke check passed.
```

4. Confirm the application install directory exists:

```text
%LOCALAPPDATA%\Programs\VStackLens
```

5. Confirm the installed executable exists:

```text
%LOCALAPPDATA%\Programs\VStackLens\VStackLens.exe
```

6. Confirm runtime data is created outside the install directory:

```text
%LOCALAPPDATA%\VStackLens
%LOCALAPPDATA%\VStackLens\data
%LOCALAPPDATA%\VStackLens\reports
%LOCALAPPDATA%\VStackLens\logs
%LOCALAPPDATA%\VStackLens\config
```

The install directory contains the application bundle. Runtime data, reports, logs, and local configuration stay under `%LOCALAPPDATA%\VStackLens`.

## Shortcuts

Confirm both shortcuts target the installed executable, not a source checkout path:

- Desktop shortcut: `VStackLens.lnk`
- Start Menu shortcut: `VStackLens\VStackLens.lnk`
- Expected target: `%LOCALAPPDATA%\Programs\VStackLens\VStackLens.exe`

## First Launch

1. Launch VStackLens from the Start Menu or Desktop shortcut.
2. Confirm the local login screen opens.
3. Log in with the default local account:

```text
username: admin
password: admin
```

4. After first login, use the security settings page to change the default password.

Default-password enforcement is not a release blocker for this build, but customer handoff should recommend changing the password during first login.

## Desktop vCenter Form

Open the inspection page and confirm the main vCenter inspection form only asks for:

```text
vCenter 地址
用户名
密码
客户名称
报告名称
报告输出目录
```

The desktop app should not ask the customer to choose a port, open `/sdk`, or configure SSL certificate verification. Internal self-signed vCenter certificates are handled by the desktop connection path. The inspection uses the full vSphere SDK / pyVmomi path; if SDK access is unavailable, the app should show a clear connection diagnostic result instead of producing an inventory inspection report.

## Mock Report

1. Open the desktop app.
2. Run a mock or local demo inspection if the delivery package includes a prepared fixture flow.
3. Confirm a report directory is created under:

```text
%LOCALAPPDATA%\VStackLens\reports
```

4. Confirm the report package contains:

```text
index.html
assets\report.css
assets\report.js
data\customer_report_payload.json
```

5. Disconnect the VM from the network.
6. Open `index.html` by double-clicking it.
7. Confirm the report opens offline and does not request external CDN or network resources.

## Uninstall

1. Uninstall VStackLens from Windows Apps & Features.
2. Confirm the application install directory is removed:

```text
%LOCALAPPDATA%\Programs\VStackLens
```

3. Confirm Desktop and Start Menu shortcuts are removed.
4. Confirm runtime data may remain for audit and reinstallation continuity:

```text
%LOCALAPPDATA%\VStackLens
```

Runtime data contains local reports, local SQLite data, logs, and configuration. Remove it manually only when the customer explicitly wants to delete local assessment data.
