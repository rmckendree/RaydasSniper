; Inno Setup script for the LMS Fuzzer (authorized security-testing tool).
; Per-user install: no admin prompt, and the app's own results\ / bodies\
; output folders stay writable (the frozen app writes next to its exe).
;
; Build:  "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\LMSFuzzer.iss
; Output: installer\Output\LMSFuzzer-Setup-<version>.exe

#define MyAppName "LMS Fuzzer"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "rmckendree"
#define MyAppExeName "LMSFuzzer.exe"
; Resolve paths relative to this .iss file (installer\ -> project root).
#define ProjRoot AddBackslash(SourcePath) + ".."
#define DistDir ProjRoot + "\dist\LMSFuzzer"

[Setup]
AppId={{AED751CF-C7C1-4092-A06D-D23C65FA94FD}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; Per-user install into %LocalAppData%\Programs\LMSFuzzer. No admin rights needed,
; and the install folder is writable so results\ / bodies\ work for any user.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={localappdata}\Programs\LMSFuzzer
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile={#ProjRoot}\assets\logo.ico
OutputDir={#SourcePath}Output
OutputBaseFilename=LMSFuzzer-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The whole built app (exe, _internal, payloads\, Requests\, README, etc.).
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Dirs]
; Output folders the app writes to at runtime (empty, so not shipped as Files).
Name: "{app}\results"
Name: "{app}\bodies"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up run output so uninstall leaves nothing behind.
Type: filesandordirs; Name: "{app}\results"
Type: filesandordirs; Name: "{app}\bodies"
