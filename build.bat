@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "FAKECA_BUILD_FILE=%~f0"
set "FAKECA_BUILD_ARG_COUNT=0"
:collect_arguments
if "%~1"=="" goto run_build
set "FAKECA_BUILD_ARG_%FAKECA_BUILD_ARG_COUNT%=%~1"
set /a FAKECA_BUILD_ARG_COUNT+=1 >nul
shift
goto collect_arguments
:run_build
powershell.exe -NoLogo -NoProfile -Command "$ErrorActionPreference='Stop'; $source=[IO.File]::ReadAllText($env:FAKECA_BUILD_FILE,[Text.Encoding]::UTF8); $body=($source -split '(?m)^# FAKECA_POWERSHELL\r?$',2)[1]; $items=@(for($i=0;$i -lt [int]$env:FAKECA_BUILD_ARG_COUNT;$i++){[Environment]::GetEnvironmentVariable('FAKECA_BUILD_ARG_'+$i)}); & ([ScriptBlock]::Create($body)) -BuildArguments $items -ProjectDirectory ([IO.Path]::GetDirectoryName($env:FAKECA_BUILD_FILE))"
endlocal & exit /b %errorlevel%

# FAKECA_POWERSHELL
param([string[]]$BuildArguments = @(), [string]$ProjectDirectory)

# Keep the CMD launcher ASCII-only. Unicode output is written by PowerShell
# without switching the shared console code page or clearing its scrollback.
$ErrorActionPreference = 'Stop'
$supportedTargets = @('windows-amd64', 'windows-arm64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64')
$buildTargets = New-Object 'System.Collections.Generic.List[string]'
$needHost = $false
$rebuildFrontend = $false
$showHelp = $false
$showList = $false
$pauseRequested = $false
$noPause = $false
$buildOutputDir = 'bin'
$buildExitCode = 0
$locationPushed = $false

function Add-BuildTarget([string]$Target) {
    if ($supportedTargets -notcontains $Target) {
        throw "不支持的目标：$Target；使用 --list 查看可选目标。"
    }
    if (-not $buildTargets.Contains($Target)) { $buildTargets.Add($Target) }
}

function Show-BuildHelp {
    Write-Host @"
🔨 FakeCA 跨平台构建

用法：build.bat [目标...] [--out DIR] [--frontend] [--pause|--no-pause]

目标：windows-amd64  windows-arm64  linux-amd64  linux-arm64
      darwin-amd64   darwin-arm64   host（当前平台）  all（全部）
不指定目标时构建当前平台；多个目标用空格分隔，重复目标只构建一次。
darwin 表示 macOS，amd64 表示 Intel/AMD x64，arm64 包括 Apple Silicon。

参数：--out DIR   输出目录，默认 bin；相对路径以项目根目录为基准
      --frontend  先执行 npm ci 和 npm run build，重新生成内嵌网页
      --list      列出支持的目标
      -h, --help  显示帮助，也支持 /?
      --pause     帮助或构建结束后等待回车，方便临时窗口查看结果
      --no-pause  不等待回车，适合自动化调用和重定向输出

示例：build.bat windows-amd64 darwin-arm64
      build.bat all --out bin\release
      build.bat host --frontend
      build.bat --help --no-pause

需要 Go（版本由 go.mod 指定）；仅 --frontend 需要 Node 22+ 与 npm。
默认复用仓库中的内嵌网页资源，不执行测试、发布者代码签名或安装包封装。
帮助默认等待回车；普通构建默认不暂停。--no-pause 或重定向输入时不暂停。
"@
}

try {
    for ($index = 0; $index -lt $BuildArguments.Count; $index++) {
        $argument = $BuildArguments[$index]
        switch ($argument.ToLowerInvariant()) {
            { $_ -in @('-h', '--help', '/?') } { $showHelp = $true; break }
            '--list' { $showList = $true; break }
            '--pause' { $pauseRequested = $true; break }
            '--no-pause' { $noPause = $true; break }
            '--frontend' { $rebuildFrontend = $true; break }
            'host' { $needHost = $true; break }
            'all' { foreach ($target in $supportedTargets) { Add-BuildTarget $target }; break }
            '--out' {
                $index++
                if ($index -ge $BuildArguments.Count -or [string]::IsNullOrEmpty($BuildArguments[$index])) {
                    throw '--out 后需要指定输出目录。'
                }
                $buildOutputDir = $BuildArguments[$index]
                if ($buildOutputDir.StartsWith('-')) {
                    throw '--out 后需要目录，不能是另一个选项；以 - 开头的目录请使用 .\ 前缀。'
                }
                break
            }
            default { Add-BuildTarget $argument.ToLowerInvariant() }
        }
    }
    if ($showHelp) { $pauseRequested = $true; Show-BuildHelp; return }
    if ($showList) { $supportedTargets | ForEach-Object { Write-Host $_ }; return }

    Push-Location -LiteralPath $ProjectDirectory
    $locationPushed = $true
    $goExecutable = (Get-Command go -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $goExecutable) {
        throw '未找到 Go，请安装后加入 PATH。'
    }
    if ($buildTargets.Count -eq 0) { $needHost = $true }
    if ($needHost) {
        $hostOS = & $goExecutable env GOHOSTOS
        if ($LASTEXITCODE -ne 0) { throw '无法读取 Go 宿主平台。' }
        $hostArch = & $goExecutable env GOHOSTARCH
        if ($LASTEXITCODE -ne 0) { throw '无法读取 Go 宿主架构。' }
        Add-BuildTarget "$hostOS-$hostArch"
    }
    if ($rebuildFrontend) {
        $nodeExecutable = (Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        $npmExecutable = (Get-Command npm -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        if (-not $nodeExecutable -or -not $npmExecutable) {
            throw '--frontend 需要 Node 22+ 与 npm，请安装后加入 PATH。'
        }
        & $nodeExecutable -e "if (Number(process.versions.node.split('.')[0]) < 22) process.exit(1)"
        if ($LASTEXITCODE -ne 0) { throw '--frontend 需要 Node 22 或更高版本。' }
        Write-Host '📦 重新构建内嵌网页…'
        & $npmExecutable --prefix web ci
        if ($LASTEXITCODE -ne 0) { throw '前端依赖安装失败。' }
        & $npmExecutable --prefix web run build
        if ($LASTEXITCODE -ne 0) { throw '前端构建失败。' }
    }

    $resolvedOutputDir = if ([IO.Path]::IsPathRooted($buildOutputDir)) {
        [IO.Path]::GetFullPath($buildOutputDir)
    } else {
        [IO.Path]::GetFullPath([IO.Path]::Combine($ProjectDirectory, $buildOutputDir))
    }
    $null = [IO.Directory]::CreateDirectory($resolvedOutputDir)
    $env:CGO_ENABLED = '0'
    $env:GOAMD64 = 'v1'
    $env:GOARM64 = 'v8.0'
    foreach ($target in $buildTargets) {
        $env:GOOS, $env:GOARCH = $target.Split('-')
        $suffix = if ($env:GOOS -eq 'windows') { '.exe' } else { '' }
        $output = Join-Path $resolvedOutputDir "fakeca-$target$suffix"
        Write-Host "🔨 构建 $target → $output"
        & $goExecutable build -trimpath '-ldflags=-s -w' -o $output .
        if ($LASTEXITCODE -ne 0) { throw "构建失败：$target" }
        Write-Host "✅ $output"
    }
    Write-Host '🎉 构建完成。以上为命令行可执行文件，未进行发布者代码签名或 macOS 公证。'
} catch {
    Write-Host "❌ $($_.Exception.Message)"
    $buildExitCode = 1
} finally {
    if ($locationPushed) { Pop-Location }
    if ($pauseRequested -and -not $noPause -and -not [Console]::IsInputRedirected) {
        try { $null = Read-Host '按回车返回命令行' } catch { }
    }
}
exit $buildExitCode
