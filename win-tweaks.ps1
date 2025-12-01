# Windows Tweaks and Optimization Script
# This script optimizes Windows 10/11 by disabling telemetry, services, and improving performance
# Run as Administrator

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting Windows Optimization..." -ForegroundColor Green

# Create System Restore Point
Write-Host "Creating System Restore Point..." -ForegroundColor Yellow
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "Windows Tweaks Backup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    Write-Host "System Restore Point Created Successfully" -ForegroundColor Green
} catch {
    Write-Host "Could not create restore point: $_" -ForegroundColor Yellow
}

# WiFi Settings
Write-Host "Configuring WiFi Settings..." -ForegroundColor Yellow
$regPath = "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\"
if (-not (Test-Path "$regPath\AllowWiFiHotSpotReporting")) {
    New-Item -Path "$regPath\AllowWiFiHotSpotReporting" -Force | Out-Null
    Write-Host "Created WiFi registry path"
}
Set-ItemProperty -Path "$regPath\AllowWiFiHotSpotReporting" -Name "Value" -Value 0 -Force
Set-ItemProperty -Path "$regPath\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0 -Force
Write-Host "WiFi Settings Configured" -ForegroundColor Green

# Activity Feed
Write-Host "Disabling Activity Feed..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Force
Write-Host "Activity Feed Disabled" -ForegroundColor Green

# Hibernation
Write-Host "Disabling Hibernation..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Value 0 -Force
$explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
if (-not (Test-Path $explorerPath)) {
    New-Item -Path $explorerPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPath -Name "ShowHibernateOption" -Value 0 -Force
Write-Host "Hibernation Disabled" -ForegroundColor Green

# Cloud Content & Game DVR
Write-Host "Disabling Cloud Content and Game DVR..." -ForegroundColor Yellow
$cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $cloudPath)) {
    New-Item -Path $cloudPath -Force | Out-Null
}
Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Value 0 -Force
$gamePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
if (-not (Test-Path $gamePath)) {
    New-Item -Path $gamePath -Force | Out-Null
}
Set-ItemProperty -Path $gamePath -Name "AllowGameDVR" -Value 0 -Force
Write-Host "Cloud Content and Game DVR Disabled" -ForegroundColor Green

# Disable Scheduled Tasks
Write-Host "Disabling Telemetry Scheduled Tasks..." -ForegroundColor Yellow
$tasks = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "Microsoft\Windows\Feedback\Siuf\DmClient",
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "Microsoft\Windows\Application Experience\MareBackup",
    "Microsoft\Windows\Application Experience\StartupAppTask",
    "Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "Microsoft\Windows\Maps\MapsUpdateTask"
)

foreach ($task in $tasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Write-Host "Disabled: $task"
    } catch {
        Write-Host "Could not disable: $task" -ForegroundColor Yellow
    }
}

# Telemetry Settings
Write-Host "Disabling Telemetry..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Force
Write-Host "Telemetry Disabled" -ForegroundColor Green

# Content Delivery Manager
Write-Host "Disabling Content Delivery..." -ForegroundColor Yellow
$contentPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Set-ItemProperty -Path $contentPath -Name "ContentDeliveryAllowed" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "OemPreInstalledAppsEnabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "PreInstalledAppsEnabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "PreInstalledAppsEverEnabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SilentInstalledAppsEnabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SubscribedContent-338387Enabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SubscribedContent-338388Enabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SubscribedContent-338389Enabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SubscribedContent-353698Enabled" -Value 0 -Force
Set-ItemProperty -Path $contentPath -Name "SystemPaneSuggestionsEnabled" -Value 0 -Force
Write-Host "Content Delivery Disabled" -ForegroundColor Green

# Advertising Info
Write-Host "Disabling Advertising ID..." -ForegroundColor Yellow
$advPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
if (-not (Test-Path $advPath)) {
    New-Item -Path $advPath -Force | Out-Null
}
Set-ItemProperty -Path $advPath -Name "DisabledByGroupPolicy" -Value 1 -Force
Write-Host "Advertising ID Disabled" -ForegroundColor Green

# Delivery Optimization
Write-Host "Disabling Delivery Optimization..." -ForegroundColor Yellow
$deliveryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
if (-not (Test-Path $deliveryPath)) {
    New-Item -Path $deliveryPath -Force | Out-Null
}
Set-ItemProperty -Path $deliveryPath -Name "DODownloadMode" -Value 0 -Force
$deliveryPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if (-not (Test-Path $deliveryPolicyPath)) {
    New-Item -Path $deliveryPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $deliveryPolicyPath -Name "DODownloadMode" -Value 0 -Force
Write-Host "Delivery Optimization Disabled" -ForegroundColor Green

# Explorer Settings
Write-Host "Configuring Explorer Settings..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Force
$peoplePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
if (-not (Test-Path $peoplePath)) {
    New-Item -Path $peoplePath -Force | Out-Null
}
Set-ItemProperty -Path $peoplePath -Name "PeopleBand" -Value 0 -Force
Write-Host "Explorer Settings Configured" -ForegroundColor Green

# Performance Tweaks
Write-Host "Applying Performance Tweaks..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 4294967295 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Value 30 -Force
Write-Host "Performance Tweaks Applied" -ForegroundColor Green

Write-Host "Windows Optimization Complete!" -ForegroundColor Green
Write-Host "Please restart your computer to apply all changes." -ForegroundColor Yellow
