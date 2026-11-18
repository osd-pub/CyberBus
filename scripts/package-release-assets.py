#!/usr/bin/env python3
"""Assemble normalized, checksummed GitHub Release assets from CI artifacts."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
import zipfile


PLATFORM_ARTIFACTS = (
    ("linux-x86_64", "sdk-x86_64-unknown-linux-gnu", ".tar.gz"),
    ("windows-x86_64", "sdk-x86_64-pc-windows-msvc", ".zip"),
    ("macos-arm64", "sdk-aarch64-apple-darwin", ".tar.gz"),
    ("android-arm64", "sdk-android-arm64", ".tar.gz"),
    ("ios-device-simulator", "sdk-ios-device-simulator", ".tar.gz"),
)

SAMPLE_PATHS = (
    "README.md",
    "SECURITY.md",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "deploy/test-client.json",
    "docs/BUILDING.md",
    "docs/INTEGRATION.md",
    "examples",
    "include",
    "packaging/smoke",
    "proto",
    "scripts/run-sample.sh",
)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def normalize_tag(tag):
    if not re.fullmatch(
        r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
        r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
        tag,
    ):
        raise SystemExit(f"release tag must be a semantic version such as v0.1.0: {tag}")
    return tag[1:]


def workspace_version(root):
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    section = re.search(
        r"(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\Z)", text
    )
    if not section:
        raise SystemExit("Cargo.toml has no [workspace.package] section")
    version = re.search(r'^version\s*=\s*"([^"]+)"', section.group(1), re.MULTILINE)
    if not version:
        raise SystemExit("workspace.package.version is missing")
    return version.group(1)


def verify_versions(root, version):
    if workspace_version(root) != version:
        raise SystemExit(
            f"tag version {version} does not match workspace version "
            f"{workspace_version(root)}"
        )
    manifests = sorted((root / "crates").glob("*/Cargo.toml"))
    manifests.extend(sorted((root / "examples").glob("*/Cargo.toml")))
    for manifest in manifests:
        text = manifest.read_text(encoding="utf-8")
        package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", text)
        if not package:
            continue
        match = re.search(r'^version\s*=\s*"([^"]+)"', package.group(1), re.MULTILINE)
        if match and match.group(1) != version:
            raise SystemExit(
                f"{manifest.relative_to(root)} version {match.group(1)} "
                f"does not match release version {version}"
            )


def copy_tree(source, destination):
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(
            ".build", ".gradle", "build", "DerivedData", "__pycache__"
        ),
    )


def write_archive(source, destination):
    if destination.suffix == ".zip":
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, (Path(source.name) / path.relative_to(source)).as_posix())
    else:
        with tarfile.open(destination, "w:gz", compresslevel=9) as archive:
            archive.add(source, arcname=source.name)


def find_maven_repository(artifact_root, version):
    relative = Path("io/cyberbus/cyberbus-sdk") / version
    candidates = [
        path
        for path in artifact_root.rglob("repository")
        if path.is_dir() and (path / relative).is_dir()
    ]
    if not candidates:
        raise SystemExit(
            f"Android Maven repository for version {version} is missing from "
            f"{artifact_root.name}"
        )
    return candidates[0]


def package_platform(
    root, artifact_root, staging_root, label, version
):
    destination_root = staging_root / f"cyberbus-v{version}-{label}-sdk"
    destination_root.mkdir(parents=True)
    manifests = sorted(artifact_root.rglob("MANIFEST.json"))
    if not manifests:
        raise SystemExit(f"no package MANIFEST.json found in {artifact_root}")

    package_names = []
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("version") != version:
            raise SystemExit(
                f"{manifest_path} version {manifest.get('version')} does not match {version}"
            )
        kind = str(manifest.get("kind", "sdk"))
        target = str(manifest.get("target", "unknown"))
        package_name = f"{kind}-{target}".replace("/", "-")
        if package_name in package_names:
            package_name += f"-{len(package_names) + 1}"
        package_names.append(package_name)
        copy_tree(manifest_path.parent, destination_root / "sdk" / package_name)

    if any(name.startswith("android-") for name in package_names):
        copy_tree(
            find_maven_repository(artifact_root, version),
            destination_root / "maven-repository",
        )
        apks = sorted(artifact_root.rglob("*.apk"))
        if not apks:
            raise SystemExit(
                f"Android sample APK is missing from {artifact_root}; "
                "release assets must include a runnable sample"
            )
        (destination_root / "samples").mkdir()
        for apk in apks:
            shutil.copy2(apk, destination_root / "samples" / apk.name)

    (destination_root / "README.md").write_text(
        f"""# CyberBus v{version} {label} SDK

This bundle was assembled by GitHub Actions from tag `v{version}`.

- `sdk/`: native and platform package contents, including `MANIFEST.json`,
  `SHA256SUMS`, `SBOM.cdx.json`, licenses and source material.
- `maven-repository/`: Android Maven repository when this is the Android bundle.
- `samples/`: runnable platform sample APK when available.

Desktop bundles include `cyberbus-cli` and `sample.c`. Apple bundles include
`sample.swift`. Verify each package's `SHA256SUMS` before use. Public deployment
values must be replaced; no token, seed, PSK or private key belongs in a config.
""",
        encoding="utf-8",
    )
    return destination_root


def package_examples(root, staging_root, version):
    destination_root = staging_root / f"cyberbus-v{version}-examples"
    destination_root.mkdir(parents=True)
    files = subprocess.run(
        ["git", "ls-files", "-z", "--", *SAMPLE_PATHS],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.split(b"\0")
    for encoded in sorted(value for value in files if value):
        relative = Path(encoded.decode("utf-8"))
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, destination)
    (destination_root / "SAMPLES.md").write_text(
        f"""# CyberBus v{version} examples

This archive contains the public example sources, protocol schema, C header,
integration guides and the safe placeholder deployment configuration from tag
`v{version}`.

- `examples/cyberbus-cli`: desktop CLI sample.
- `examples/cyberbus-test-client`: real SDK machine client.
- `examples/android-demo`: Kotlin/JNI Android sample.
- `packaging/smoke/desktop.c`: minimal C lifecycle sample.
- `packaging/smoke/swift.swift`: minimal Apple lifecycle sample.

Use the matching platform SDK bundle for prebuilt libraries and the GitHub
source archives for the complete Rust workspace. `deploy/test-client.json`
contains placeholders only and must be replaced with your own public deployment.
""",
        encoding="utf-8",
    )
    return destination_root


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True, help="Release tag, for example v0.1.0")
    parser.add_argument("--input", type=Path, required=True, help="Downloaded artifact root")
    parser.add_argument("--output", type=Path, required=True, help="Release asset output")
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.repository_root.resolve()
    version = normalize_tag(args.tag)
    verify_versions(root, version)
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    work = output / ".work"
    work.mkdir()

    built = []
    for label, artifact_name, suffix in PLATFORM_ARTIFACTS:
        artifact_root = args.input / artifact_name
        if not artifact_root.is_dir():
            raise SystemExit(f"missing downloaded artifact: {artifact_name}")
        staged = package_platform(root, artifact_root, work, label, version)
        archive = output / f"cyberbus-v{version}-{label}-sdk{suffix}"
        write_archive(staged, archive)
        built.append(archive)

    examples = package_examples(root, work, version)
    examples_archive = output / f"cyberbus-v{version}-examples.tar.gz"
    write_archive(examples, examples_archive)
    built.append(examples_archive)
    shutil.rmtree(work)

    checksums = []
    for asset in sorted(built):
        checksums.append(f"{digest(asset)}  {asset.name}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    (output / "release-manifest.json").write_text(
        json.dumps(
            {
                "name": "CyberBus",
                "version": version,
                "tag": args.tag,
                "commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=root, text=True
                ).strip(),
                "assets": [
                    {"name": asset.name, "sha256": digest(asset)} for asset in built
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    names = "\n".join(f"- `{asset.name}`" for asset in built)
    (output / "RELEASE_NOTES.md").write_text(
        f"""# CyberBus {args.tag}

This release was built and verified by GitHub Actions from tag `{args.tag}`.

## Release assets

{names}
- `SHA256SUMS`
- `release-manifest.json`

Platform bundles contain their native libraries, `cyberbus-cli` or platform SDK
package, package manifests, SBOM, licenses, source material and samples. The
examples archive contains the desktop, Android and Apple example sources.

Package assembly and simulator/consumer smoke tests do not replace real
cross-network login, device ACK, network-change recovery or scale validation.
See `docs/UNRESOLVED.md` in the source tree for the current limits.
""",
        encoding="utf-8",
    )
    print(f"assembled {len(built)} release assets in {output}")


if __name__ == "__main__":
    main()
