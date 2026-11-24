#!/usr/bin/env bash
# Verify the exact, unmodified ZKA source closure before compile and TXE.
# No private repository or Git history is required by the public snapshot.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 - "$SCRIPT_DIR" "$@" <<'PY'
import argparse
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import tomllib

PINNED_COMMIT = "b5ab3b3743d33cbee3b9ee38c6e14610deb2228f"
PINNED_TREE = "7dc81a09abcae52e2f48436523d3cdf139a54368"
PINNED_GOLDEN_SHA256 = "790f3fe67ee6629bc036fde4af6eab8714748a312186a9b5cc58fd34ba03f2ae"
SCRIPT_DIR = Path(sys.argv[1])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_files(root):
    require(root.is_dir() and not root.is_symlink(), "source directory missing or symlinked")
    files = []
    for directory, names, leaves in os.walk(root):
        current = Path(directory)
        for name in names + leaves:
            require(not (current / name).is_symlink(), "symlink in source snapshot")
        require(".git" not in names + leaves, "Git metadata in source snapshot")
        names[:] = [name for name in names if name != "target"]
        for name in leaves:
            if name != ".DS_Store":
                path = current / name
                require(path.is_file(), "non-regular source file")
                files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def source_digest(root):
    records = b"".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(root).as_posix()}\n".encode()
        for path in source_files(root)
    )
    return hashlib.sha256(records).hexdigest()


def git_object(kind, data):
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data).digest()


def source_tree(root):
    # Reproduce upstream subtree IDs from bytes and modes, without storing or
    # importing any objects from the private repository's commit graph.
    entries = []
    for path in root.iterdir():
        if path.name in {"target", ".DS_Store"}:
            continue
        require(not path.is_symlink(), "symlink in source tree")
        if path.is_dir():
            mode, oid, sort_key = "40000", source_tree(path), path.name + "/"
        else:
            require(path.is_file(), "non-regular source file")
            mode = "100755" if path.stat().st_mode & 0o111 else "100644"
            oid, sort_key = git_object("blob", path.read_bytes()), path.name
        entries.append((sort_key.encode(), mode.encode() + b" " + path.name.encode() + b"\0" + oid))
    return git_object("tree", b"".join(record for _, record in sorted(entries)))


parser = argparse.ArgumentParser(description="Verify the vendored ZKA source closure (no network).")
parser.add_argument("--dep-dir", type=Path, default=SCRIPT_DIR / "../vendor/zka")
parser.add_argument("--golden", type=Path, default=SCRIPT_DIR / "zka-main.source.sha256")
modes = parser.add_mutually_exclusive_group()
modes.add_argument("--fetch", action="store_true", help="Compatibility alias: verify local source; never fetch.")
modes.add_argument("--print-digest", action="store_true")
modes.add_argument("--self-test", action="store_true")
args = parser.parse_args(sys.argv[2:])
try:
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="zkm-zka-integrity-") as temporary:
            fixture = Path(temporary)
            (fixture / "main.nr").write_text("source\n")
            baseline = source_digest(fixture)
            (fixture / "target").mkdir()
            (fixture / "target/output").write_text("generated\n")
            require(source_digest(fixture) == baseline, "generated files changed digest")
            (fixture / "main.nr").write_text("mutation\n")
            require(source_digest(fixture) != baseline, "source mutation not detected")
        print("ZKA source-integrity self-test passed.")
        sys.exit(0)
    if args.print_digest:
        print(source_digest(args.dep_dir))
        sys.exit(0)
    require(hashlib.sha256(args.golden.read_bytes()).hexdigest() == PINNED_GOLDEN_SHA256,
            "source identity manifest differs from reviewed pin")
    golden = {}
    for line in args.golden.read_text().splitlines():
        key, value = line.split("=", 1)
        require(key not in golden and value, "duplicate or empty source identity entry")
        golden[key] = value
    require(golden["format"] == "zkm:zka-source-integrity:v2", "unsupported source identity format")
    require(golden["ref"] == golden["commit"] == PINNED_COMMIT, "commit provenance mismatch")
    require(golden["tree"] == PINNED_TREE, "upstream tree provenance mismatch")
    manifest = SCRIPT_DIR / "../zkm_mandate_aztec/Nargo.toml"
    with manifest.open("rb") as handle:
        dependency = tomllib.load(handle)["dependencies"]["zka_transfer_aztec"]
    require(dependency == {"path": "../vendor/zka/aztec/zka_transfer_aztec"},
            "dependency manifest differs from verified local source path")
    require(len(source_files(args.dep_dir)) == int(golden["file_count"]), "source file-count mismatch")
    require(source_digest(args.dep_dir) == golden["source_sha256"], "source digest mismatch")
    require(hashlib.sha256((args.dep_dir / "LICENSE").read_bytes()).hexdigest() == golden["license_sha256"],
            "LICENSE digest mismatch")
    for key, value in golden.items():
        if key.startswith("package_tree_sha1."):
            relative, tree_id = value, key.removeprefix("package_tree_sha1.")
            require(source_tree(args.dep_dir / relative).hex() == tree_id,
                    "upstream package tree mismatch")
except (OSError, ValueError, KeyError) as error:
    print(f"ZKA source-integrity check failed: {error}", file=sys.stderr)
    sys.exit(1)
print(f"ZKA source integrity verified: {PINNED_COMMIT} (vendored, no fetch).")
PY
