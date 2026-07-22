#ifndef AppVersion
  #error AppVersion must be supplied by package-installer.ps1
#endif
#ifndef NumericVersion
  #error NumericVersion must be supplied by package-installer.ps1
#endif
#ifndef SourceDir
  #error SourceDir must be supplied by package-installer.ps1
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by package-installer.ps1
#endif

[Setup]
AppId={{3B30E32C-749F-4B75-A2DB-596886C137C6}
AppName=安全审查工具
AppVersion={#AppVersion}
AppVerName=安全审查工具 {#AppVersion}
AppPublisher=SecurityReviewTool
AppPublisherURL=https://github.com/yusiyi0429/Security-review-tool
AppSupportURL=https://github.com/yusiyi0429/Security-review-tool/issues
AppUpdatesURL=https://github.com/yusiyi0429/Security-review-tool/releases
VersionInfoVersion={#NumericVersion}
VersionInfoDescription=安全审查工具安装程序
DefaultDirName={localappdata}\Programs\SecurityReviewTool
DefaultGroupName=安全审查工具
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
OutputDir={#OutputDir}
OutputBaseFilename=SecurityReviewTool-{#AppVersion}-win-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\SecurityReviewTool.exe
SetupIconFile=..\src\SecurityReview.Desktop\Assets\SecurityReviewTool.ico
UsePreviousAppDir=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\安全审查工具"; Filename: "{app}\SecurityReviewTool.exe"; WorkingDir: "{app}"; IconFilename: "{app}\SecurityReviewTool.exe"; IconIndex: 0
Name: "{autodesktop}\安全审查工具"; Filename: "{app}\SecurityReviewTool.exe"; WorkingDir: "{app}"; IconFilename: "{app}\SecurityReviewTool.exe"; IconIndex: 0; Tasks: desktopicon

[Run]
Filename: "{app}\SecurityReviewTool.exe"; Description: "{cm:LaunchProgram,安全审查工具}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent
