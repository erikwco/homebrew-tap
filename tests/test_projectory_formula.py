"""Contract tests for scripts/projectory_formula.py (stdlib unittest, no network)."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("projectory_formula", ROOT / "scripts" / "projectory_formula.py")
pf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pf)

STABLE = pf.Version("1.2.3")
RC = pf.Version("1.2.3-rc.1")


def tar_bytes(members: list[tuple[str, bytes, int]], symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(info)
    return buffer.getvalue()


GOOD_MEMBERS = [
    ("projectory", b"#!/bin/sh\n", 0o755),
    ("LICENSE", b"MIT\n", 0o644),
    ("README.md", b"readme\n", 0o644),
    ("THIRD_PARTY_NOTICES.md", b"notices\n", 0o644),
]


def write_release(directory: Path, version: pf.Version, archives: dict[str, bytes] | None = None) -> dict:
    """Write tarballs + checksums.txt; return matching release JSON."""
    archives = archives or {}
    lines = []
    for name in pf.archive_names(version):
        data = archives.get(name, tar_bytes(GOOD_MEMBERS))
        (directory / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    lines.append(f"{'0' * 64}  projectory_{version}_sbom.json")
    (directory / pf.CHECKSUMS).write_text("\n".join(lines) + "\n")
    return release_json(version, directory)


def release_json(version: pf.Version, directory: Path | None = None) -> dict:
    assets = []
    for name in pf.archive_names(version) + [pf.CHECKSUMS]:
        asset = {"name": name, "browser_download_url": pf.download_url(version, name), "size": 10, "state": "uploaded"}
        if directory is not None:
            asset["digest"] = "sha256:" + pf.sha256_file(directory / name)
        assets.append(asset)
    return {"tag_name": version.tag, "draft": False, "prerelease": version.prerelease, "immutable": True, "assets": assets}


class VersionTests(unittest.TestCase):
    def test_accepts_strict_semver(self):
        for text in ("0.1.0", "1.2.3", "10.20.30", "1.0.0-rc.1", "1.0.0-rc.12"):
            self.assertEqual(str(pf.parse_version(text, allow_prerelease=True)), text)

    def test_rejects_everything_else(self):
        for text in ("v1.2.3", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-rc1", "1.2.3-beta.1", "1.2.3-rc.01", "1.2.3-rc.0",
                     "1.2.3+build", " 1.2.3", "1.2.3\n", "1.2.3;id", "$(id)", "1.2.3-rc.1\nx", "", "1" * 50 + ".0.0"):
            with self.subTest(text=text), self.assertRaises(pf.ContractError):
                pf.parse_version(text, allow_prerelease=True)

    def test_release_candidates_need_opt_in(self):
        with self.assertRaisesRegex(pf.ContractError, "dry-run only"):
            pf.parse_version("1.2.3-rc.1")

    def test_ordering(self):
        ordered = [pf.Version(v) for v in ("0.9.9", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0", "1.0.1", "1.10.0")]
        self.assertEqual(sorted(reversed(ordered), key=lambda v: v.key), ordered)
        self.assertTrue(pf.Version("1.0.0-rc.9") < pf.Version("1.0.0"))
        self.assertEqual(pf.Version("2.0.0"), pf.Version("2.0.0"))


class ChecksumTests(unittest.TestCase):
    def test_parses_goreleaser_and_binary_markers(self):
        sums = pf.parse_checksums(f"{'a' * 64}  one.tar.gz\n{'b' * 64} *two.tar.gz\n\n")
        self.assertEqual(sums, {"one.tar.gz": "a" * 64, "two.tar.gz": "b" * 64})

    def test_rejects_malformed_and_duplicates(self):
        for text in (f"{'A' * 64}  x", f"{'a' * 63}  x", f"{'a' * 64} x", f"{'a' * 64}  ../x", f"{'a' * 64}  x y",
                     f"{'a' * 64}  x\n{'b' * 64}  x"):
            with self.subTest(text=text), self.assertRaises(pf.ContractError):
                pf.parse_checksums(text)

    def test_requires_all_four_archives(self):
        sums = {name: "c" * 64 for name in pf.archive_names(STABLE)[:3]}
        with self.assertRaisesRegex(pf.ContractError, "linux_amd64"):
            pf.archive_checksums(STABLE, sums)


class FormulaTests(unittest.TestCase):
    def sums(self, version=STABLE):
        return {name: f"{index:x}" * 64 for index, name in enumerate(pf.archive_names(version), 10)}

    def test_renders_four_prebuilt_archives_per_platform(self):
        formula = pf.render_formula(STABLE, self.sums())
        self.assertNotIn("version ", formula.split("livecheck")[0], "Homebrew scans the version from the URLs")
        self.assertIn('license "MIT"', formula)
        self.assertNotIn("depends_on", formula)
        expected = {
            ("macos", "arm"): "darwin_arm64", ("macos", "intel"): "darwin_amd64",
            ("linux", "arm"): "linux_arm64", ("linux", "intel"): "linux_amd64",
        }
        for (os_name, cpu), suffix in expected.items():
            block = re.search(rf"  on_{os_name} do\n(.*?)\n  end\n", formula, re.S).group(1)
            cpu_block = re.search(rf"on_{cpu} do\n(.*?)\n    end", block, re.S).group(1)
            name = f"projectory_1.2.3_{suffix}.tar.gz"
            self.assertIn(f'url "https://github.com/erikwco/projectory/releases/download/v1.2.3/{name}"', cpu_block)
            self.assertIn(f'sha256 "{self.sums()[name]}"', cpu_block)
        self.assertEqual(formula.count("url \"https://"), 4)

    def test_includes_shell_caveats_and_safe_update_test(self):
        formula = pf.render_formula(STABLE, self.sums())
        self.assertIn('eval "$(#{opt_bin}/projectory init zsh)"', formula)
        self.assertIn('eval "$(#{opt_bin}/projectory init bash)"', formula)
        self.assertIn('ENV["PROJECTORY_DATA_DIR"]', formula)
        self.assertIn('ENV["PROJECTORY_CONFIG_DIR"]', formula)
        self.assertIn('shell_output("#{bin}/projectory update --yes 2>&1", 1)', formula)
        self.assertIn('assert_match "brew upgrade erikwco/tap/projectory", output', formula)
        self.assertIn("assert_equal digest, executable.sha256", formula)

    def test_is_deterministic_and_ignores_extra_checksums(self):
        sums = self.sums() | {"projectory_1.2.3_sbom.json": "f" * 64}
        self.assertEqual(pf.render_formula(STABLE, sums), pf.render_formula(STABLE, self.sums()))
        self.assertNotIn("sbom", pf.render_formula(STABLE, sums))

    def test_release_candidate_formula(self):
        formula = pf.render_formula(RC, self.sums(RC))
        self.assertIn("/download/v1.2.3-rc.1/projectory_1.2.3-rc.1_linux_arm64.tar.gz", formula)


class ReleaseTests(unittest.TestCase):
    def check(self, release, version=STABLE, allow=False, immutable=True):
        return pf.check_release(release, version, allow, immutable)

    def test_accepts_published_immutable_stable(self):
        self.assertEqual(self.check(release_json(STABLE)), [])

    def test_rejects_bad_release_state(self):
        cases = {
            "draft": {"draft": True},
            "missing draft": {"draft": None},
            "prerelease flag": {"prerelease": True},
            "tag": {"tag_name": "v1.2.4"},
            "mutable": {"immutable": False},
            "no assets": {"assets": None},
        }
        for label, change in cases.items():
            with self.subTest(label):
                with self.assertRaises(pf.ContractError):
                    self.check(release_json(STABLE) | change)

    def test_mutable_release_is_a_warning_when_not_required(self):
        warnings = self.check(release_json(STABLE) | {"immutable": False}, immutable=False)
        self.assertEqual(len(warnings), 1)

    def test_rc_release_only_with_opt_in(self):
        self.assertEqual(self.check(release_json(RC), RC, allow=True), [])
        with self.assertRaises(pf.ContractError):
            self.check(release_json(RC), RC, allow=False)
        with self.assertRaises(pf.ContractError):
            self.check(release_json(RC) | {"prerelease": False}, RC, allow=True)

    def test_rejects_bad_assets(self):
        def mutate(change):
            release = release_json(STABLE)
            change(release["assets"])
            return release

        cases = {
            "missing": lambda a: a.pop(0),
            "duplicate": lambda a: a.append(dict(a[0])),
            "foreign url": lambda a: a[0].update(browser_download_url="https://evil.example/x.tar.gz"),
            "empty": lambda a: a[1].update(size=0),
            "uploading": lambda a: a[2].update(state="starter"),
            "digest": lambda a: a[3].update(digest="md5:abc"),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(pf.ContractError):
                self.check(mutate(change))


class VerifyAssetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_accepts_matching_assets(self):
        release = write_release(self.dir, STABLE)
        sums = pf.verify_assets(STABLE, self.dir, release)
        self.assertEqual(list(sums), pf.archive_names(STABLE))

    def test_rejects_tampered_archive(self):
        release = write_release(self.dir, STABLE)
        name = pf.archive_names(STABLE)[2]
        (self.dir / name).write_bytes(tar_bytes(GOOD_MEMBERS[:2] + [("README.md", b"changed\n", 0o644)] + GOOD_MEMBERS[3:]))
        with self.assertRaisesRegex(pf.ContractError, "digest GitHub reports"):
            pf.verify_assets(STABLE, self.dir, release)
        with self.assertRaisesRegex(pf.ContractError, "does not match checksums.txt"):
            pf.verify_assets(STABLE, self.dir, None)

    def test_rejects_missing_file(self):
        write_release(self.dir, STABLE)
        (self.dir / pf.archive_names(STABLE)[0]).unlink()
        with self.assertRaisesRegex(pf.ContractError, "missing downloaded file"):
            pf.verify_assets(STABLE, self.dir, None)

    def test_rejects_unsafe_archives(self):
        cases = {
            "symlink": tar_bytes(GOOD_MEMBERS, symlink="README.md"),
            "traversal": tar_bytes(GOOD_MEMBERS + [("../projectory", b"x", 0o755)]),
            "absolute": tar_bytes(GOOD_MEMBERS + [("/usr/local/bin/projectory", b"x", 0o755)]),
            "unexpected": tar_bytes(GOOD_MEMBERS + [("install.sh", b"x", 0o755)]),
            "duplicate": tar_bytes(GOOD_MEMBERS + [("projectory", b"x", 0o755)]),
            "not executable": tar_bytes([("projectory", b"x", 0o644)] + GOOD_MEMBERS[1:]),
            "missing notices": tar_bytes(GOOD_MEMBERS[:3]),
            "not gzip": b"plain text",
        }
        name = pf.archive_names(STABLE)[1]
        for label, data in cases.items():
            with self.subTest(label):
                write_release(self.dir, STABLE, {name: data})
                with self.assertRaises(pf.ContractError):
                    pf.verify_assets(STABLE, self.dir, None)


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.sums = {name: "a" * 64 for name in pf.archive_names(STABLE)}
        self.generated = self.dir / "generated.rb"
        self.generated.write_text(pf.render_formula(STABLE, self.sums))
        self.existing = self.dir / "existing.rb"

    def tearDown(self):
        self.tmp.cleanup()

    def existing_for(self, text, sums=None):
        version = pf.Version(text)
        self.existing.write_text(pf.render_formula(version, sums or {n: "b" * 64 for n in pf.archive_names(version)}))

    def test_new_upgrade_unchanged(self):
        self.assertEqual(pf.compare(self.existing, self.generated, STABLE), "new")
        self.existing_for("1.2.2")
        self.assertEqual(pf.compare(self.existing, self.generated, STABLE), "upgrade")
        self.existing.write_text(self.generated.read_text())
        self.assertEqual(pf.compare(self.existing, self.generated, STABLE), "unchanged")

    def test_reads_version_from_urls_only(self):
        self.existing.write_text("class Projectory < Formula\nend\n")
        with self.assertRaisesRegex(pf.ContractError, "exactly one release version"):
            pf.compare(self.existing, self.generated, STABLE)
        mixed = self.generated.read_text().replace("download/v1.2.3/projectory_1.2.3_linux", "download/v1.2.4/projectory_1.2.3_linux")
        self.existing.write_text(mixed)
        with self.assertRaisesRegex(pf.ContractError, "exactly one release version"):
            pf.compare(self.existing, self.generated, STABLE)

    def test_refuses_rewind_and_rewrite(self):
        self.existing_for("1.3.0")
        with self.assertRaisesRegex(pf.ContractError, "rewind"):
            pf.compare(self.existing, self.generated, STABLE)
        self.existing_for("1.2.3")
        with self.assertRaisesRegex(pf.ContractError, "never rewritten"):
            pf.compare(self.existing, self.generated, STABLE)


class CommandLineTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_generate_from_local_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_release(directory, STABLE)
            output = directory / "Formula" / "projectory.rb"
            code, _, err = self.run_main("generate", "--version", "1.2.3", "--checksums", str(directory / "checksums.txt"),
                                         "--output", str(output))
            self.assertEqual((code, err), (0, ""))
            self.assertIn("/v1.2.3/projectory_1.2.3_darwin_arm64.tar.gz", output.read_text())

    def test_errors_exit_nonzero_without_traceback(self):
        code, _, err = self.run_main("check-version", "--version", "1.2.3-rc.1")
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("error: "))
        self.assertEqual(self.run_main("check-version", "--version", "1.2.3-rc.1", "--allow-prerelease")[0], 0)

    def test_assets_lists_exact_downloads(self):
        code, out, _ = self.run_main("assets", "--version", "1.2.3")
        self.assertEqual(code, 0)
        lines = [line.split("\t") for line in out.splitlines()]
        self.assertEqual([name for name, _ in lines], ["checksums.txt"] + pf.archive_names(STABLE))
        for name, url in lines:
            self.assertEqual(url, f"https://github.com/erikwco/projectory/releases/download/v1.2.3/{name}")

    def test_check_release_reads_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.json"
            path.write_text(json.dumps(release_json(STABLE) | {"immutable": False}))
            self.assertEqual(self.run_main("check-release", "--version", "1.2.3", "--release-json", str(path),
                                           "--require-immutable")[0], 1)
            code, _, err = self.run_main("check-release", "--version", "1.2.3", "--release-json", str(path))
            self.assertEqual(code, 0)
            self.assertIn("warning: release is not immutable", err)


if __name__ == "__main__":
    unittest.main()
