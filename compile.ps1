# JADX Frida HookAll 编译脚本
Write-Host "========== JADX Frida HookAll 编译 ==========" -ForegroundColor Cyan

# 从环境变量或参数获取 JADX JAR 路径
if ($args.Count -gt 0) {
    $jadxGuiJar = $args[0]
} elseif ($env:JADX_GUI_JAR) {
    $jadxGuiJar = $env:JADX_GUI_JAR
} else {
    # 默认路径（请根据实际情况修改为你的 JADX 路径）
    # 示例：$jadxGuiJar = "D:\path\to\jadx\jadx-gui\build\libs\jadx-gui-dev-all.jar"
    $jadxGuiJar = "..\jadx\jadx-gui\build\libs\jadx-gui-dev-all.jar"
}

# 检查 JADX JAR 是否存在
if (-not (Test-Path $jadxGuiJar)) {
    Write-Host "✗ JADX JAR 文件不存在: $jadxGuiJar" -ForegroundColor Red
    Write-Host ""
    Write-Host "请使用以下方式之一指定 JADX JAR 路径:" -ForegroundColor Yellow
    Write-Host "  1. 参数传递: .\compile.ps1 'C:\path\to\jadx-gui-dev-all.jar'" -ForegroundColor Cyan
    Write-Host "  2. 环境变量: `$env:JADX_GUI_JAR='C:\path\to\jadx-gui-dev-all.jar'" -ForegroundColor Cyan
    Write-Host "  3. 修改脚本中的默认路径" -ForegroundColor Cyan
    exit 1
}

Write-Host "✓ 找到 JADX: $jadxGuiJar" -ForegroundColor Green

# 步骤 1: 创建 lib 目录并复制 JADX
Write-Host "`n[1/2] 准备 JADX 库..." -ForegroundColor Yellow

$libDir = ".\lib"
if (-not (Test-Path $libDir)) {
    New-Item -ItemType Directory -Path $libDir | Out-Null
    Write-Host "✓ 创建 lib 目录" -ForegroundColor Green
}

Copy-Item $jadxGuiJar -Destination "$libDir\jadx-gui.jar" -Force
Write-Host "✓ 复制 JADX 库到 lib\jadx-gui.jar" -ForegroundColor Green

# 步骤 2: 编译项目
Write-Host "`n[2/2] 编译项目..." -ForegroundColor Yellow
.\mvnw.cmd clean package -DskipTests

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "✓ 编译成功!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    $jarFile = Get-Item ".\target\jadx-frida-hookall-1.0.3.jar"
    Write-Host "`n生成的插件文件:" -ForegroundColor Yellow
    Write-Host "  路径: $($jarFile.FullName)" -ForegroundColor White
    Write-Host "  大小: $([math]::Round($jarFile.Length / 1KB, 2)) KB" -ForegroundColor Gray
    
    Write-Host "`n安装到 JADX:" -ForegroundColor Yellow
    Write-Host "  方法1 - JADX GUI 安装:" -ForegroundColor Cyan
    Write-Host "    在 JADX GUI 中: Plugins -> Install plugin -> 选择上面的 jar 文件`n" -ForegroundColor White
    
    Write-Host "  方法2 - 手动复制:" -ForegroundColor Cyan
    Write-Host "    将 jar 复制到 JADX 的 plugins 目录" -ForegroundColor White
    Write-Host "    Windows: %USERPROFILE%\.jadx\plugins\" -ForegroundColor Gray
    
} else {
    Write-Host "`n✗ 编译失败" -ForegroundColor Red
    exit 1
}
