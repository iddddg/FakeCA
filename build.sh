#!/bin/sh
# POSIX sh: Linux, macOS and Git Bash. No platform-specific signing tools needed.
set -eu

project_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
cd "$project_dir"
supported='windows-amd64 windows-arm64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64'
targets=''
need_host=0
frontend=0
out=bin

usage() {
    cat <<'EOF'
🔨 FakeCA 跨平台构建

用法：sh build.sh [目标...] [--out DIR] [--frontend]

目标：windows-amd64  windows-arm64  linux-amd64  linux-arm64
      darwin-amd64   darwin-arm64   host（当前平台）  all（全部）
不指定目标时构建当前平台；多个目标用空格分隔，重复目标只构建一次。
darwin 表示 macOS，amd64 表示 Intel/AMD x64，arm64 包括 Apple Silicon。

参数：--out DIR   输出目录，默认 bin；相对路径以项目根目录为基准
      --frontend  先执行 npm ci 和 npm run build，重新生成内嵌网页
      --list      列出支持的目标
      -h, --help  显示帮助

示例：sh build.sh windows-amd64 darwin-arm64
      sh build.sh all --out bin/release
      sh build.sh host --frontend

需要 Go（版本由 go.mod 指定）；仅 --frontend 需要 Node 22+ 与 npm。
默认复用仓库中的内嵌网页资源，不执行测试、代码签名或安装包封装。
EOF
}

fail() { printf '❌ %s\n' "$*" >&2; exit 1; }
add_target() {
    case " $targets " in *" $1 "*) return ;; esac
    targets="${targets:+$targets }$1"
}
validate_target() {
    case "$1" in
        windows-amd64|windows-arm64|linux-amd64|linux-arm64|darwin-amd64|darwin-arm64) add_target "$1" ;;
        *) fail "不支持的目标：$1；使用 --list 查看可选目标。" ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --list) printf '%s\n' $supported; exit 0 ;;
        --out)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail '--out 后需要指定输出目录。'
            case "$2" in -*) fail '--out 后需要目录，不能是另一个选项；以 - 开头的目录请使用 ./ 前缀。' ;; esac
            out=$2
            shift 2
            ;;
        --frontend) frontend=1; shift ;;
        host) need_host=1; shift ;;
        all) for target in $supported; do add_target "$target"; done; shift ;;
        *) validate_target "$1"; shift ;;
    esac
done

command -v go >/dev/null 2>&1 || fail '未找到 Go，请安装后加入 PATH。'
if [ -z "$targets" ]; then need_host=1; fi
if [ "$need_host" -eq 1 ]; then
    host_os=$(go env GOHOSTOS) || fail '无法读取 Go 宿主平台。'
    host_arch=$(go env GOHOSTARCH) || fail '无法读取 Go 宿主架构。'
    validate_target "$host_os-$host_arch"
fi
if [ "$frontend" -eq 1 ]; then
    command -v node >/dev/null 2>&1 || fail '--frontend 需要 Node 22+ 与 npm，请安装后加入 PATH。'
    command -v npm >/dev/null 2>&1 || fail '--frontend 需要 Node/npm，请安装后加入 PATH。'
    node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' || fail '--frontend 需要 Node 22 或更高版本。'
    printf '📦 重新构建内嵌网页…\n'
    npm --prefix web ci || fail '前端依赖安装失败。'
    npm --prefix web run build || fail '前端构建失败。'
fi

mkdir -p -- "$out" || fail "无法创建输出目录：$out"
for target in $targets; do
    target_os=${target%-*}
    target_arch=${target#*-}
    suffix=''
    if [ "$target_os" = windows ]; then suffix=.exe; fi
    output="$out/fakeca-$target$suffix"
    printf '🔨 构建 %s → %s\n' "$target" "$output"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOAMD64=v1 GOARM64=v8.0 \
        go build -trimpath -ldflags='-s -w' -o "$output" . || fail "构建失败：$target"
    printf '✅ %s\n' "$output"
done
printf '🎉 构建完成。以上为命令行可执行文件，未进行代码签名或公证。\n'
