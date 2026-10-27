#!/usr/bin/env python3
"""Package the six build.sh/build.bat outputs with licenses and provenance."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time
import zipfile


ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    "windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64",
    "darwin-amd64", "darwin-arm64",
)
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, encoding="utf-8").strip()


def validate_tag(tag):
    match = TAG_PATTERN.fullmatch(tag)
    if not match or (match[4] and any(
        value.isdigit() and len(value) > 1 and value.startswith("0")
        for value in match[4].split(".")
    )):
        raise ValueError("版本标签应为 v1.0.0 或 v1.0.0-rc.1，不接受路径、空格或前导零。")


def inspect_binary(binary, target, commit):
    details = command("go", "version", "-m", str(binary))
    fields = {}
    for line in details.splitlines()[1:]:
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[0] == "build" and "=" in parts[1]:
            key, value = parts[1].split("=", 1)
            fields[key] = value
        elif len(parts) == 2 and parts[0] == "path":
            fields["package"] = parts[1]
    target_os, target_arch = target.split("-")
    expected = {
        "package": "github.com/iddddg/FakeCA", "GOOS": target_os,
        "GOARCH": target_arch, "CGO_ENABLED": "0", "vcs.revision": commit,
        "vcs.modified": "false",
    }
    for key, value in expected.items():
        if fields.get(key) != value:
            raise ValueError(f"{binary.name} 的 {key} 不匹配：{fields.get(key)!r}，预期 {value!r}")
    return details.splitlines()[0].rsplit(": ", 1)[-1]


def write_archive(destination, files, executable, epoch):
    if destination.suffix == ".zip":
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, time.gmtime(epoch)[:6])
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o755 if name == executable else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    else:
        with destination.open("wb") as output:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for name, data in files.items():
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o755 if name == executable else 0o644
                        info.mtime = epoch
                        archive.addfile(info, io.BytesIO(data))
    # Verify bytes and permissions after writing, before publishing checksums.
    if destination.suffix == ".zip":
        with zipfile.ZipFile(destination) as archive:
            if set(archive.namelist()) != set(files) or archive.testzip():
                raise ValueError(f"ZIP 内容或 CRC 不正确：{destination.name}")
            for name, data in files.items():
                if archive.read(name) != data:
                    raise ValueError(f"ZIP 文件内容不匹配：{name}")
    else:
        with tarfile.open(destination, "r:gz") as archive:
            if set(archive.getnames()) != set(files):
                raise ValueError(f"TAR 内容不正确：{destination.name}")
            for name, data in files.items():
                member = archive.getmember(name)
                if not member.isfile() or archive.extractfile(member).read() != data:
                    raise ValueError(f"TAR 文件内容不匹配：{name}")
                if member.mode != (0o755 if name == executable else 0o644):
                    raise ValueError(f"TAR 文件权限不正确：{name}")


def main():
    parser = argparse.ArgumentParser(description="📦 打包 FakeCA 六平台产物、许可证及 SHA-256 校验文件。")
    parser.add_argument("--version", required=True, help="版本标签，例如 v1.0.0")
    parser.add_argument("--input-dir", type=Path, default=ROOT / "bin/release/raw", help="构建脚本的输出目录")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "bin/release/assets", help="发布附件目录，必须为空")
    parser.add_argument("--validate-only", action="store_true", help="仅检查版本标签格式")
    args = parser.parse_args()
    validate_tag(args.version)
    if args.validate_only:
        print(f"✅ 版本标签有效：{args.version}")
        return

    commit = command("git", "rev-parse", "HEAD")
    epoch = int(command("git", "show", "-s", "--format=%ct", "HEAD"))
    if command("git", "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("发布打包要求工作区干净，请先提交源码；不发布含未提交改动的产物。")
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"输出目录必须为空，避免混入旧附件：{output}")

    # Validate every input first; never collect arbitrary workspace files.
    binaries = []
    for target in TARGETS:
        executable = "fakeca.exe" if target.startswith("windows-") else "fakeca"
        suffix = ".exe" if executable.endswith(".exe") else ""
        binary = args.input_dir.resolve() / f"fakeca-{target}{suffix}"
        if not binary.is_file():
            raise ValueError(f"缺少构建产物：{binary}")
        binaries.append((target, executable, binary, inspect_binary(binary, target, commit)))

    license_text = (ROOT / "LICENSE").read_bytes()
    notices = (ROOT / "web/public/third-party-notices.txt").read_bytes()
    template = (ROOT / "docs/RELEASE_README.md").read_text(encoding="utf-8")
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for target, executable, binary, go_version in binaries:
        info = {
            "version": args.version, "target": target, "commit": commit,
            "repository": "https://github.com/iddddg/FakeCA", "go_version": go_version,
            "cgo_enabled": False,
        }
        readme = template.replace("{{VERSION}}", args.version).replace("{{TARGET}}", target).replace("{{COMMIT}}", commit)
        files = {
            executable: binary.read_bytes(), "LICENSE": license_text,
            "THIRD_PARTY_NOTICES.txt": notices, "README.md": readme.encode("utf-8"),
            "release-info.json": (json.dumps(info, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        }
        extension = ".zip" if target.startswith("windows-") else ".tar.gz"
        archive = output / f"fakeca_{args.version}_{target}{extension}"
        write_archive(archive, files, executable, epoch)
        checksums.append((archive.name, hashlib.sha256(archive.read_bytes()).hexdigest()))
        print(f"✅ {archive.name}")
    (output / "SHA256SUMS.txt").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(checksums)), encoding="utf-8", newline="\n")
    print(f"🎉 6 个平台包及 SHA256SUMS.txt 已生成：{output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"❌ {error}")
