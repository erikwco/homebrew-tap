#!/usr/bin/env python3
"""Validate a published Projectory release and generate Formula/projectory.rb.

Only the standard library is used so the tool runs unchanged on GitHub runners
and on a maintainer machine. Every subcommand fails closed: any unexpected
version, release state, asset name, checksum or archive member is an error.

Subcommands:
  check-version    strict semver gate (stable unless --allow-prerelease)
  assets           print "<name>\t<url>" for the five release assets to download
  check-release    validate GitHub release JSON (tag, draft, prerelease, assets)
  verify-assets    verify downloaded tarballs against checksums.txt and API digests
  generate         write the formula from a local checksums.txt
  compare          refuse to rewind or rewrite a version already in the tap
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import tarfile
from pathlib import Path

REPOSITORY = "erikwco/projectory"
TAP_FORMULA = "erikwco/tap/projectory"
DOWNLOAD_BASE = f"https://github.com/{REPOSITORY}/releases/download"
CHECKSUMS = "checksums.txt"
# (Homebrew OS block, Homebrew CPU block, GOOS, GOARCH), in formula order.
PLATFORMS = (
    ("macos", "arm", "darwin", "arm64"),
    ("macos", "intel", "darwin", "amd64"),
    ("linux", "arm", "linux", "arm64"),
    ("linux", "intel", "linux", "amd64"),
)
ARCHIVE_REQUIRED = frozenset({"projectory", "LICENSE", "THIRD_PARTY_NOTICES.md"})
ARCHIVE_ALLOWED = ARCHIVE_REQUIRED | {"README.md"}
MAX_VERSION_LENGTH = 40
MAX_CHECKSUMS_BYTES = 64 * 1024
MAX_MEMBER_COUNT = 16

_NUMBER = r"(0|[1-9][0-9]{0,8})"
# Release candidates are numbered from 1, matching the release workflow and the updater.
VERSION_RE = re.compile(rf"\A{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-rc\.([1-9][0-9]{{0,8}}))?\Z")
CHECKSUM_LINE_RE = re.compile(r"\A([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)\Z")
FORMULA_URL_RE = re.compile(r'^ +url "https://github\.com/erikwco/projectory/releases/download/v([^/"]+)/', re.MULTILINE)


class ContractError(Exception):
    """The release, input or tap state does not satisfy the publishing contract."""


class Version:
    def __init__(self, text: str):
        if not isinstance(text, str) or len(text) > MAX_VERSION_LENGTH:
            raise ContractError("version must be a short string like 1.2.3 or 1.2.3-rc.1, without v")
        match = VERSION_RE.match(text)
        if not match:
            raise ContractError(f"invalid version {text!r}: expected MAJOR.MINOR.PATCH[-rc.N] without v")
        major, minor, patch, rc = match.groups()
        self.text = text
        self.rc = None if rc is None else int(rc)
        # Stable sorts after every release candidate of the same core version.
        self.key = (int(major), int(minor), int(patch), 1 if rc is None else 0, self.rc or 0)

    @property
    def prerelease(self) -> bool:
        return self.rc is not None

    @property
    def tag(self) -> str:
        return "v" + self.text

    def __lt__(self, other: "Version") -> bool:
        return self.key < other.key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.key == other.key

    def __str__(self) -> str:
        return self.text


def parse_version(text: str, allow_prerelease: bool = False) -> Version:
    version = Version(text)
    if version.prerelease and not allow_prerelease:
        raise ContractError(f"{version} is a release candidate; only stable versions can be published (RC is dry-run only)")
    return version


def archive_name(version: Version, goos: str, goarch: str) -> str:
    return f"projectory_{version}_{goos}_{goarch}.tar.gz"


def archive_names(version: Version) -> list[str]:
    return [archive_name(version, goos, goarch) for _, _, goos, goarch in PLATFORMS]


def download_url(version: Version, name: str) -> str:
    return f"{DOWNLOAD_BASE}/{version.tag}/{name}"


def parse_checksums(text: str) -> dict[str, str]:
    """Parse a sha256sum/GoReleaser manifest, rejecting malformed or duplicate lines."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = CHECKSUM_LINE_RE.match(line)
        if not match:
            raise ContractError(f"{CHECKSUMS} line {number} is not '<sha256>  <file>'")
        digest, name = match.groups()
        if name in sums:
            raise ContractError(f"{CHECKSUMS} lists {name} more than once")
        sums[name] = digest
    return sums


def read_checksums(path: Path) -> dict[str, str]:
    data = path.read_bytes()
    if len(data) > MAX_CHECKSUMS_BYTES:
        raise ContractError(f"{CHECKSUMS} is larger than {MAX_CHECKSUMS_BYTES} bytes")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ContractError(f"{CHECKSUMS} is not ASCII") from error
    return parse_checksums(text)


def archive_checksums(version: Version, sums: dict[str, str]) -> dict[str, str]:
    missing = [name for name in archive_names(version) if name not in sums]
    if missing:
        raise ContractError(f"{CHECKSUMS} is missing: {', '.join(missing)}")
    return {name: sums[name] for name in archive_names(version)}


def check_release(release: dict, version: Version, allow_prerelease: bool, require_immutable: bool) -> list[str]:
    """Validate release JSON from GET /repos/{owner}/{repo}/releases/tags/{tag}; return warnings."""
    warnings = []
    if release.get("tag_name") != version.tag:
        raise ContractError(f"release tag is {release.get('tag_name')!r}, expected {version.tag!r}")
    if release.get("draft") is not False:
        raise ContractError("release is a draft or its state is unknown")
    if release.get("prerelease") is not (version.prerelease):
        raise ContractError(f"release prerelease flag is {release.get('prerelease')!r} but {version} implies {version.prerelease}")
    if version.prerelease and not allow_prerelease:
        raise ContractError("prerelease releases are accepted only for dry runs")
    immutable = release.get("immutable")
    if immutable is not True:
        message = "release is not immutable; assets could still be replaced"
        if require_immutable:
            raise ContractError(message)
        warnings.append(message)
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ContractError("release has no asset list")
    by_name: dict[str, dict] = {}
    for asset in assets:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str):
            raise ContractError("release asset without a name")
        if name in by_name:
            raise ContractError(f"release lists asset {name} more than once")
        by_name[name] = asset
    for name in archive_names(version) + [CHECKSUMS]:
        asset = by_name.get(name)
        if asset is None:
            raise ContractError(f"release is missing asset {name}")
        if asset.get("browser_download_url") != download_url(version, name):
            raise ContractError(f"asset {name} has unexpected download URL {asset.get('browser_download_url')!r}")
        if asset.get("state", "uploaded") != "uploaded":
            raise ContractError(f"asset {name} is not fully uploaded")
        size = asset.get("size")
        if not isinstance(size, int) or size <= 0:
            raise ContractError(f"asset {name} has invalid size {size!r}")
        digest = asset.get("digest")
        if digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
            raise ContractError(f"asset {name} has unexpected digest {digest!r}")
    return warnings


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_archive(path: Path) -> None:
    """Read tar headers only (nothing is extracted) and enforce the archive contract."""
    seen: set[str] = set()
    try:
        with tarfile.open(path, "r:gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_MEMBER_COUNT:
                    raise ContractError(f"{path.name} has more than {MAX_MEMBER_COUNT} entries")
                name = member.name.removeprefix("./")
                if name not in ARCHIVE_ALLOWED:
                    raise ContractError(f"{path.name} contains unexpected entry {member.name!r}")
                if name in seen:
                    raise ContractError(f"{path.name} contains {name} more than once")
                if not member.isreg():
                    raise ContractError(f"{path.name}: {name} is not a regular file")
                if name == "projectory" and not member.mode & stat.S_IXUSR:
                    raise ContractError(f"{path.name}: projectory is not executable")
                seen.add(name)
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ContractError(f"{path.name} is not a readable tar.gz: {error}") from error
    missing = sorted(ARCHIVE_REQUIRED - seen)
    if missing:
        raise ContractError(f"{path.name} is missing {', '.join(missing)}")


def verify_assets(version: Version, directory: Path, release: dict | None) -> dict[str, str]:
    """Verify the four tarballs and checksums.txt in directory; return archive checksums."""
    api_digests = {}
    if release is not None:
        api_digests = {a["name"]: a.get("digest") for a in release.get("assets", []) if isinstance(a, dict) and "name" in a}
    files = [CHECKSUMS] + archive_names(version)
    for name in files:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ContractError(f"missing downloaded file {name}")
        expected = api_digests.get(name)
        if expected and expected != "sha256:" + sha256_file(path):
            raise ContractError(f"{name} does not match the digest GitHub reports for the release asset")
    sums = archive_checksums(version, read_checksums(directory / CHECKSUMS))
    for name, expected in sums.items():
        if sha256_file(directory / name) != expected:
            raise ContractError(f"{name} does not match {CHECKSUMS}")
        inspect_archive(directory / name)
    return sums


def render_formula(version: Version, sums: dict[str, str]) -> str:
    sums = archive_checksums(version, sums)
    blocks = []
    for os_block in ("macos", "linux"):
        cpu_blocks = []
        for platform_os, cpu, goos, goarch in PLATFORMS:
            if platform_os != os_block:
                continue
            name = archive_name(version, goos, goarch)
            cpu_blocks.append(
                f"    on_{cpu} do\n"
                f'      url "{download_url(version, name)}"\n'
                f'      sha256 "{sums[name]}"\n'
                f"    end"
            )
        blocks.append(f"  on_{os_block} do\n" + "\n\n".join(cpu_blocks) + "\n  end")
    platforms = "\n\n".join(blocks)
    return f'''# Generated by scripts/projectory_formula.py from the published {version.tag} release.
# Do not edit by hand: run the "Bump formula" workflow instead.
class Projectory < Formula
  desc "Catalog projects, copies and Git worktrees and jump to them from the shell"
  homepage "https://github.com/{REPOSITORY}"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

{platforms}

  def install
    bin.install "projectory"
    doc.install "THIRD_PARTY_NOTICES.md"
  end

  def caveats
    <<~EOS
      Para activar la función pt, añade a ~/.zshrc:
        eval "$(#{{opt_bin}}/projectory init zsh)"
      o, en bash, a ~/.bashrc:
        eval "$(#{{opt_bin}}/projectory init bash)"

      Homebrew administra esta instalación. Para actualizar usa:
        brew update && brew upgrade {TAP_FORMULA}
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/projectory --version")

    ENV["PROJECTORY_DATA_DIR"] = (testpath/"data").to_s
    ENV["PROJECTORY_CONFIG_DIR"] = (testpath/"config").to_s
    (testpath/"demo").mkpath
    system bin/"projectory", "add", testpath/"demo", "--name", "demo", "--no-input", "--no-worktrees"
    assert_path_exists testpath/"data/catalog.db"
    assert_match "demo", shell_output("#{{bin}}/projectory list --plain")
    assert_match "pt()", shell_output("#{{bin}}/projectory init zsh")

    executable = (bin/"projectory").realpath
    digest = executable.sha256
    output = shell_output("#{{bin}}/projectory update --yes 2>&1", 1)
    assert_match "brew upgrade {TAP_FORMULA}", output
    assert_equal digest, executable.sha256
  end
end
'''


def formula_version(text: str) -> Version:
    """Read the version from the release URLs; Homebrew scans it from them too."""
    versions = set(FORMULA_URL_RE.findall(text))
    if len(versions) != 1:
        raise ContractError(f"existing formula must reference exactly one release version, found {sorted(versions)}")
    return Version(versions.pop())


def compare(existing: Path, generated: Path, version: Version) -> str:
    """Return 'new', 'upgrade' or 'unchanged'; raise if publishing would rewind or rewrite."""
    if not existing.exists():
        return "new"
    current_text = existing.read_text(encoding="utf-8")
    current = formula_version(current_text)
    if version < current:
        raise ContractError(f"the tap already ships {current}; refusing to rewind to {version}")
    if version == current:
        if current_text != generated.read_text(encoding="utf-8"):
            raise ContractError(f"the tap already ships {current} with different content; released versions are never rewritten")
        return "unchanged"
    return "upgrade"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ContractError(f"{path} is not a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def with_version(command: argparse.ArgumentParser) -> None:
        command.add_argument("--version", required=True, help="release version without v, e.g. 1.2.3")
        command.add_argument("--allow-prerelease", action="store_true", help="accept -rc.N versions (dry runs only)")

    with_version(sub.add_parser("check-version"))
    with_version(sub.add_parser("assets"))
    command = sub.add_parser("check-release")
    with_version(command)
    command.add_argument("--release-json", type=Path, required=True)
    command.add_argument("--require-immutable", action="store_true")
    command = sub.add_parser("verify-assets")
    with_version(command)
    command.add_argument("--dir", type=Path, required=True)
    command.add_argument("--release-json", type=Path)
    command = sub.add_parser("generate")
    with_version(command)
    command.add_argument("--checksums", type=Path, required=True, help="local checksums.txt of the release")
    command.add_argument("--output", type=Path, required=True)
    command = sub.add_parser("compare")
    with_version(command)
    command.add_argument("--existing", type=Path, required=True)
    command.add_argument("--generated", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        version = parse_version(args.version, args.allow_prerelease)
        if args.command == "check-release":
            for warning in check_release(load_json(args.release_json), version, args.allow_prerelease, args.require_immutable):
                print(f"warning: {warning}", file=sys.stderr)
        elif args.command == "verify-assets":
            release = load_json(args.release_json) if args.release_json else None
            for name, digest in verify_assets(version, args.dir, release).items():
                print(f"{digest}  {name}")
        elif args.command == "generate":
            formula = render_formula(version, read_checksums(args.checksums))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(formula, encoding="utf-8")
        elif args.command == "compare":
            print(compare(args.existing, args.generated, version))
        elif args.command == "assets":
            for name in [CHECKSUMS] + archive_names(version):
                print(f"{name}\t{download_url(version, name)}")
        else:
            print(version)
    except ContractError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
