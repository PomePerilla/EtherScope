#ifndef AppVersion
  #error AppVersion required
#endif
#ifndef PayloadDirectory
  #error PayloadDirectory required
#endif
#ifndef ReleaseDirectory
  #error ReleaseDirectory required
#endif

[Setup]
AppId={{C3DDDFD6-1B8D-4D87-A5DF-F21F60246B70}
AppName=EtherScope
AppVersion={#AppVersion}
AppPublisher=EtherScope
DefaultDirName={localappdata}\Programs\EtherScope
DefaultGroupName=EtherScope
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
DisableProgramGroupPage=yes
DisableWelcomePage=yes
DisableDirPage=auto
WizardStyle=modern
OutputDir={#ReleaseDirectory}
OutputBaseFilename=EtherScope-Setup-{#AppVersion}-x64
Compression=lzma2/max
SolidCompression=yes
UninstallDisplayIcon={app}\EtherScope.exe
CloseApplications=yes
RestartApplications=no
AppMutex=EtherScope.Desktop
SetupLogging=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "zh_CN"; MessagesFile: "languages\ChineseSimplified.isl"
Name: "zh_TW"; MessagesFile: "languages\ChineseTraditional.isl"

[CustomMessages]
en.DesktopShortcut=Create a desktop shortcut
zh_CN.DesktopShortcut=创建桌面快捷方式
zh_TW.DesktopShortcut=建立桌面捷徑
en.LaunchProgram=Open EtherScope
zh_CN.LaunchProgram=打开 EtherScope
zh_TW.LaunchProgram=開啟 EtherScope

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopShortcut}"; Flags: checkedonce

[Files]
Source: "{#PayloadDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\EtherScope"; Filename: "{app}\EtherScope.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\EtherScope"; Filename: "{app}\EtherScope.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\EtherScope.exe"; Parameters: "--language {language}"; Description: "{cm:LaunchProgram}"; Flags: nowait postinstall skipifsilent
