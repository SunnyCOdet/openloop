# -----------------------------------------------------------------------------
# OfradrAgent Installation Script
# Run this script directly from a web server:
# iwr -useb https://your-server.com/install.ps1 | iex
# -----------------------------------------------------------------------------

$ErrorActionPreference = "Stop"

$AppName = "hope"
$AppExeName = "hope.exe"
$InstallDir = "$env:APPDATA\$AppName"
$ExePath = "$InstallDir\$AppExeName"
$HotkeysPath = "$InstallDir\hotkeys.json"

# Replace this URL with the actual location of your compiled executable
# e.g., "https://github.com/yourusername/ofradr-cpp/releases/latest/download/OfradrAgent.exe"
$DownloadUrl = "https://github.com/SunnyCOdet/openloop/releases/download/Release/hope.exe"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "          Installing $AppName" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Create Installation Directory
if (!(Test-Path $InstallDir)) {
    Write-Host "[*] Creating installation directory at $InstallDir..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 2. Download the Executable
Write-Host "[*] Downloading the latest build..."
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ExePath
    Write-Host "[+] Download complete!" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to download the executable. Please check the download URL." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "          Configuration Setup" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# 3. Prompt User for Credentials
$TelegramToken = Read-Host "1. Enter your Telegram Bot Token"

Write-Host ""
Write-Host "Please send a message to your Telegram bot now so we can capture your Chat ID." -ForegroundColor Yellow
Write-Host "Waiting for message..."

$TelegramChatId = ""
$UpdatesUrl = "https://api.telegram.org/bot$TelegramToken/getUpdates"

do {
    try {
        $response = Invoke-RestMethod -Uri $UpdatesUrl -Method Get -ErrorAction Stop
        if ($response.ok -eq $true -and $response.result.Count -gt 0) {
            # Get the chat ID from the most recent message
            $lastMessage = $response.result[-1]
            if ($lastMessage.message.chat.id) {
                $TelegramChatId = $lastMessage.message.chat.id
                Write-Host "[+] Automatically detected Chat ID: $TelegramChatId" -ForegroundColor Green
            }
        }
    } catch {
        # Ignore errors and keep polling
    }
    
    if ([string]::IsNullOrEmpty($TelegramChatId)) {
        Start-Sleep -Seconds 2
        Write-Host "." -NoNewline
    }
} while ([string]::IsNullOrEmpty($TelegramChatId))
Write-Host ""

Write-Host ""
Write-Host "Available AI Providers:"
Write-Host "  1 - Gemini"
Write-Host "  2 - OpenAI"
Write-Host "  3 - Anthropic (Claude)"
Write-Host "  4 - DeepSeek"
Write-Host "  5 - Moonshot (Kimi)"
Write-Host "  6 - OpenRouter"
$ProviderChoice = Read-Host "3. Select your preferred AI Provider (1-6)"

$ProviderKeyMap = @{
    "1" = "gemini"
    "2" = "openai"
    "3" = "claude"
    "4" = "deepseek"
    "5" = "kimi"
    "6" = "openrouter"
}

$SelectedProvider = $ProviderKeyMap[$ProviderChoice]
if ([string]::IsNullOrWhiteSpace($SelectedProvider)) {
    Write-Host "[-] Invalid provider selected. Defaulting to Gemini." -ForegroundColor Yellow
    $SelectedProvider = "gemini"
}

$ApiKey = Read-Host "4. Enter your API Key for $SelectedProvider"

$ApiKeysObj = @{}
$ApiKeysObj[$SelectedProvider] = $ApiKey

while ($true) {
    Write-Host ""
    $addMore = Read-Host "Do you want to add another provider's API key? (y/N)"
    if ($addMore -notmatch "^[yY]$") { break }

    $nextChoice = Read-Host "Select another AI Provider (1-6)"
    $nextProvider = $ProviderKeyMap[$nextChoice]
    if ([string]::IsNullOrWhiteSpace($nextProvider)) {
        Write-Host "[-] Invalid provider selected, skipping." -ForegroundColor Yellow
        continue
    }
    
    $nextKey = Read-Host "Enter your API Key for $nextProvider"
    $ApiKeysObj[$nextProvider] = $nextKey
}

$ApiKeysJsonList = @()
foreach ($k in $ApiKeysObj.Keys) {
    $ApiKeysJsonList += "`"$k`": `"$($ApiKeysObj[$k])`""
}
$ApiKeysJsonString = $ApiKeysJsonList -join ",`n        "

# 4. Generate hotkeys.json Configuration
Write-Host ""
Write-Host "[*] Saving configuration..."

# Create a default JSON structure with user inputs
$ConfigTemplate = @"
{
    "chatHistory": {
        "enabled": false
    },
    "telegram": {
        "chatId": "$TelegramChatId",
        "enabled": true,
        "token": "$TelegramToken"
    },
    "toggle": {
        "alt": true,
        "ctrl": false,
        "shift": false,
        "vk": 191
    },
    "screenshot": {
        "alt": false,
        "ctrl": false,
        "shift": false,
        "vk": 0
    },
    "apiKeys": {
        $ApiKeysJsonString
    }
}
"@

Set-Content -Path $HotkeysPath -Value $ConfigTemplate
Write-Host "[+] Configuration saved to $HotkeysPath" -ForegroundColor Green

# 5. UAC Configuration
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "          Advanced Configuration" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "By default, Windows isolates UAC (Admin) prompts on a 'Secure Desktop' which blocks the agent."
Write-Host "To allow the agent to interact with UAC prompts, we can disable the Secure Desktop"
Write-Host "so that UAC prompts appear as normal windows (requires running this script as Administrator)."
$UacChoice = Read-Host "Allow Agent to interact with UAC prompts? (y/N)"

if ($UacChoice -match "^[yY]$") {
    Write-Host "[*] Disabling UAC Secure Desktop..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0 -Type DWord
        Write-Host "[+] Secure Desktop disabled successfully!" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to disable Secure Desktop. Please re-run install.ps1 as Administrator to apply this setting." -ForegroundColor Yellow
    }
}

# 6. Add to Windows Startup
Write-Host ""
Write-Host "[*] Adding application to Windows Startup..."
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $TaskName = "$AppName`_Startup"
        $Action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory $InstallDir
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
        Write-Host "[+] Added Scheduled Task for Startup successfully!" -ForegroundColor Green
    } else {
        Write-Host "[-] Installer is not running as Administrator. Falling back to Registry Run Key..." -ForegroundColor Yellow
        Write-Host "[-] Note: If the app requires Admin privileges, it may fail to auto-start. Please run install as Admin." -ForegroundColor Yellow
        $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        # Use cmd.exe /c start to specify the working directory for the registry key fallback
        Set-ItemProperty -Path $RegistryPath -Name $AppName -Value "cmd.exe /c start `"`" /d `"$InstallDir`" `"$ExePath`""
        Write-Host "[+] Added to Registry Startup successfully!" -ForegroundColor Green
    }
} catch {
    Write-Host "[-] Failed to add to startup: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Launch Application
Write-Host ""
Write-Host "[*] Starting $AppName in the background..."
try {
    # Start the process silently in the correct directory
    Start-Process -FilePath $ExePath -WorkingDirectory $InstallDir -WindowStyle Hidden
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "[+] Installation and Setup Complete!" -ForegroundColor Green
    Write-Host "[+] The agent is now running and waiting for Telegram commands." -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to launch the application: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit..."
