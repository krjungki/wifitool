# 패키지 WPF 창을 데이터 상호작용 없이 PNG로 캡처한다.
param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\dist\wifitool-win-x64\WifiTool.exe'),
    [string]$Output = (Join-Path $PSScriptRoot '..\build\ui-smoke.png'),
    [int]$ExistingProcessId = 0
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WindowCaptureNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr handle, out RECT rect);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr handle, int command);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr handle);
}
'@

$startedHere = $ExistingProcessId -eq 0
$process = if ($startedHere) { Start-Process -FilePath (Resolve-Path $Executable) -PassThru } else { Get-Process -Id $ExistingProcessId -ErrorAction Stop }
try {
    if (-not $process.WaitForInputIdle(15000)) { throw '창이 입력 대기 상태가 되지 않았습니다.' }
    $process.Refresh()
    if ($process.MainWindowHandle -eq [IntPtr]::Zero) { throw '주 창 핸들을 찾지 못했습니다.' }
    $null = [WindowCaptureNative]::ShowWindow($process.MainWindowHandle, 9)
    $null = [WindowCaptureNative]::SetForegroundWindow($process.MainWindowHandle)
    $null = $process.WaitForInputIdle(15000)
    $rect = New-Object WindowCaptureNative+RECT
    if (-not [WindowCaptureNative]::GetWindowRect($process.MainWindowHandle, [ref]$rect)) { throw '창 좌표를 읽지 못했습니다.' }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    $directory = Split-Path -Parent $Output
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $bitmap = New-Object System.Drawing.Bitmap($width, $height)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
            $bitmap.Save($Output, [System.Drawing.Imaging.ImageFormat]::Png)
        }
        finally { $graphics.Dispose() }
    }
    finally { $bitmap.Dispose() }
    $file = Get-Item $Output
    [pscustomobject]@{ Width = $width; Height = $height; Bytes = $file.Length; Path = $file.FullName }
}
finally {
    if ($startedHere -and -not $process.HasExited) {
        $null = $process.CloseMainWindow()
        if (-not $process.WaitForExit(5000)) { $process.Kill() }
    }
}