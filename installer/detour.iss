; Inno Setup 6 Script for Detour
; Codename: Detour - Per-application network connection router for Windows 11

#define MyAppName "Detour"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Mohamed Abderrahmane MEKSEN"
#define MyAppURL "https://github.com/meksenmohammedabderrahmane/detour"
#define MyAppExeName "detour-ui.exe"
#define MyServiceExeName "detour.exe"

[Setup]
AppId={{5D9D2A3B-8C4E-4B1C-9311-B58DF8972E8B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Detour
DefaultGroupName=Detour
AllowNoIcons=yes
OutputDir=..\_dist
OutputBaseFilename=DetourSetup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
CloseApplications=yes
CloseApplicationsFilter=detour-ui.exe,detour.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
; %ProgramData%\Detour with modify permissions for authenticated users
Name: "{commonappdata}\Detour"; Permissions: authusers-modify

[Files]
Source: "..\_dist\detour.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\_dist\detour-ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\_dist\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\_dist\wintun-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\cmd\detour-ui\assets\tray.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Detour"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\tray.ico"
Name: "{group}\Uninstall Detour"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Detour"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\tray.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start Detour UI automatically when logging in"; GroupDescription: "Startup options:"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "DetourUI"; ValueData: """{app}\{#MyAppExeName}"" --tray"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Install and start the privileged Windows service
Filename: "{app}\{#MyServiceExeName}"; Parameters: "service install"; StatusMsg: "Installing Detour service..."; Flags: runhidden
Filename: "{app}\{#MyServiceExeName}"; Parameters: "service start"; StatusMsg: "Starting Detour service..."; Flags: runhidden
; Optionally launch UI after installation
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,Detour}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Gracefully terminate running processes and clean engine routes before removal
Filename: "taskkill.exe"; Parameters: "/F /IM detour-ui.exe"; Flags: runhidden; RunOnceId: "KillDetourUI"
Filename: "{app}\{#MyServiceExeName}"; Parameters: "off"; Flags: runhidden; RunOnceId: "EngineOff"
Filename: "{app}\{#MyServiceExeName}"; Parameters: "service stop"; Flags: runhidden; RunOnceId: "ServiceStop"
Filename: "{app}\{#MyServiceExeName}"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "ServiceUninstall"
Filename: "{app}\{#MyServiceExeName}"; Parameters: "cleanup"; Flags: runhidden; RunOnceId: "CleanupLeftovers"

[Code]
// Stop active processes during upgrade before files are copied
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  // Stop UI if running
  Exec('taskkill.exe', '/F /IM detour-ui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Stop service if running
  Exec(ExpandConstant('{app}\{#MyServiceExeName}'), 'service stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Prompt whether to keep or remove rules on uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\Detour');
    if DirExists(DataDir) then
    begin
      if not UninstallSilent then
      begin
        if MsgBox('Do you want to keep your Detour rules and settings (%ProgramData%\Detour)?', mbConfirmation, MB_YESNO) = IDNO then
        begin
          DelTree(DataDir, True, True, True);
        end;
      end;
    end;
  end;
end;
