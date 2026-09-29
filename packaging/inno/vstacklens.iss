#define MyAppName "VStackLens"
#define MyAppVersion "0.2.8"
#define MyAppPublisher "VStackLens"
#define MyAppExeName "VStackLens.exe"
#define MySourceDir "..\..\dist\VStackLens"
#define MyAppIcon "..\..\src\vstacklens\assets\icons\vstacklens.ico"

[Setup]
AppId={{9C640561-1635-435F-8372-786DB26012E7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\VStackLens
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist\installer
OutputBaseFilename=VStackLens-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
MinVersion=10.0.14393
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
WizardStyle=modern
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Remove files left by earlier contaminated onedir builds before an in-place upgrade.
Type: files; Name: "{app}\_internal\api-ms-win-*.dll"
Type: files; Name: "{app}\_internal\ext-ms-win-*.dll"
Type: files; Name: "{app}\_internal\VCRUNTIME140.dll"
Type: files; Name: "{app}\_internal\VCRUNTIME140_1.dll"
Type: files; Name: "{app}\_internal\ucrtbase.dll"
Type: files; Name: "{app}\_internal\icuuc.dll"
Type: files; Name: "{app}\_internal\icudt*.dll"
Type: files; Name: "{app}\_internal\libcrypto-3-x64.dll"
Type: files; Name: "{app}\_internal\libssl-3-x64.dll"

[Icons]
Name: "{group}\VStackLens"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\VStackLens"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,VStackLens}"; Flags: nowait postinstall skipifsilent
