; Inno Setup script — builds gokdogan-setup.exe from dist\gokdogan.exe.
;
; Per-user install (no admin prompt): lands in %LocalAppData%\Programs\gokdogan
; and, if the user ticks the option, adds that folder to the user PATH so
; `gokdogan` works from any terminal. Uninstaller is registered in Apps.
;
; Build:  ISCC.exe packaging\gokdogan.iss   (after packaging\build_exe.ps1)

#define AppName    "gokdogan"
#define AppVersion "0.5.0"
#define AppExe     "gokdogan.exe"

[Setup]
AppId={{7B9C2E1A-5F3D-4C8B-9A21-0D0C0A5E0500}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=İlker Ünver
AppPublisherURL=https://github.com/IlkerUnver00/gokdogan-triage
AppSupportURL=https://github.com/IlkerUnver00/gokdogan-triage/issues
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename={#AppName}-setup
Compression=lzma2/max
SolidCompression=yes
ChangesEnvironment=yes
LicenseFile=..\LICENSE
UninstallDisplayIcon={app}\{#AppExe}
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "addtopath"; Description: "Add {#AppName} to the user PATH (run it from any terminal)"; GroupDescription: "Command line:"; Flags: checkedonce

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";      DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE";        DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName} (terminal)"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExe}"" --help"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Registry]
; Append the install dir to the *user* PATH (HKCU) — no admin needed.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  { look for the path with leading and trailing semicolon; Pos() returns 0 if not found }
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
