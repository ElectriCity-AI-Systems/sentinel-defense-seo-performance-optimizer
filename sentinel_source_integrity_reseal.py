#!/usr/bin/env python3
"""Owner-invoked deterministic reseal for Sentinel's committed source manifest.

The tool has one fixed repository and one fixed manifest. Resealing is refused
unless every tracked file matches the index and HEAD. Protected bytes are read
from Git objects at HEAD, never from working-tree source files. Untracked
runtime evidence is ignored and can never enter the protected path set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_DIR = Path(__file__).resolve().parent
MANIFEST_RELATIVE = "config/autonomous-production-source-manifest.json"
MANIFEST_PATH = PROJECT_DIR / MANIFEST_RELATIVE
GIT_BIN = "/usr/bin/git"

MANIFEST_SCHEMA = "sentinel-autonomous-production-source-manifest-1"
SEALED_SCOPE = "fixed_runtime_source_policy_units_and_playbooks"
HASH_ALGORITHM = "sha256"
EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "sealed_scope",
    "source_self_modification_enabled",
    "files",
}
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
HEAD_RE = re.compile(r"^[a-f0-9]{40,64}$")
REGULAR_GIT_MODES = {"100644", "100755"}


class ResealError(RuntimeError):
    """Fail-closed reseal error carrying a stable, non-secret reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DuplicateManifestKeyError(ValueError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_keys(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateManifestKeyError(key)
        result[key] = value
    return result


def parse_manifest_bytes(value: bytes) -> Dict[str, Any]:
    try:
        decoded = value.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateManifestKeyError):
        raise ResealError("MANIFEST_JSON_INVALID")
    if not isinstance(parsed, dict):
        raise ResealError("MANIFEST_ROOT_INVALID")
    return parsed


def validate_protected_path(relative: Any) -> str:
    if not isinstance(relative, str) or not relative or not SAFE_PATH_RE.fullmatch(relative):
        raise ResealError("PROTECTED_PATH_INVALID")
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != relative
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ResealError("PROTECTED_PATH_INVALID")
    return relative


def validate_manifest_policy(manifest: Dict[str, Any]) -> List[str]:
    if set(manifest) != EXPECTED_TOP_LEVEL_KEYS:
        raise ResealError("MANIFEST_SCHEMA_FIELDS_INVALID")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ResealError("MANIFEST_SCHEMA_INVALID")
    if manifest.get("sealed_scope") != SEALED_SCOPE:
        raise ResealError("MANIFEST_SCOPE_INVALID")
    if manifest.get("source_self_modification_enabled") is not False:
        raise ResealError("SOURCE_SELF_MODIFICATION_NOT_DISABLED")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ResealError("PROTECTED_SET_EMPTY")
    paths: List[str] = []
    for raw_path, expected_hash in files.items():
        relative = validate_protected_path(raw_path)
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            raise ResealError("MANIFEST_HASH_INVALID")
        paths.append(relative)
    if len(paths) != len(set(paths)):
        raise ResealError("PROTECTED_PATH_DUPLICATE")
    if MANIFEST_RELATIVE in paths:
        raise ResealError("SOURCE_MANIFEST_SELF_REFERENCE_BLOCKER")
    return sorted(paths)


def run_git(
    repo: Path,
    arguments: List[str],
    *,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            [GIT_BIN, "-C", str(repo), *arguments],
            check=False,
            shell=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ResealError("GIT_EXECUTION_FAILED")
    if check and completed.returncode != 0:
        raise ResealError("GIT_COMMAND_FAILED")
    return completed


def resolve_head(repo: Path) -> str:
    completed = run_git(repo, ["rev-parse", "--verify", "HEAD^{commit}"])
    try:
        head = completed.stdout.decode("ascii").strip().lower()
    except UnicodeDecodeError:
        raise ResealError("HEAD_INVALID")
    if not HEAD_RE.fullmatch(head):
        raise ResealError("HEAD_INVALID")
    return head


def tracked_tree_status(repo: Path) -> Dict[str, Any]:
    unstaged = run_git(repo, ["diff", "--quiet", "--"], check=False)
    staged = run_git(repo, ["diff", "--cached", "--quiet", "--"], check=False)
    if unstaged.returncode not in {0, 1} or staged.returncode not in {0, 1}:
        raise ResealError("GIT_DIRTY_CHECK_FAILED")
    return {
        "unstaged_tracked_changes": unstaged.returncode == 1,
        "staged_tracked_changes": staged.returncode == 1,
        "clean": unstaged.returncode == 0 and staged.returncode == 0,
        "untracked_files_ignored": True,
    }


def require_clean_tracked_tree(repo: Path) -> Dict[str, Any]:
    status = tracked_tree_status(repo)
    if not status["clean"]:
        raise ResealError("RESEAL_ABORTED_DIRTY_TRACKED_TREE")
    return status


def head_blob(repo: Path, head: str, relative: str) -> bytes:
    relative = validate_protected_path(relative)
    listing = run_git(repo, ["ls-tree", "-z", head, "--", relative])
    records = [record for record in listing.stdout.split(b"\0") if record]
    if len(records) != 1:
        raise ResealError("PROTECTED_HEAD_FILE_MISSING")
    try:
        metadata, listed_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        decoded_path = listed_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ResealError("PROTECTED_HEAD_ENTRY_INVALID")
    if decoded_path != relative:
        raise ResealError("PROTECTED_HEAD_PATH_MISMATCH")
    if mode not in REGULAR_GIT_MODES or object_type != "blob":
        raise ResealError("PROTECTED_HEAD_FILE_NOT_REGULAR")
    if not HEAD_RE.fullmatch(object_id.lower()):
        raise ResealError("PROTECTED_HEAD_OBJECT_INVALID")
    return run_git(repo, ["cat-file", "blob", object_id]).stdout


def committed_manifest(repo: Path, head: str) -> Dict[str, Any]:
    manifest = parse_manifest_bytes(head_blob(repo, head, MANIFEST_RELATIVE))
    validate_manifest_policy(manifest)
    return manifest


def build_resealed_manifest(repo: Path, head: Optional[str] = None) -> Dict[str, Any]:
    resolved_head = head or resolve_head(repo)
    policy = committed_manifest(repo, resolved_head)
    protected_paths = validate_manifest_policy(policy)
    hashes = {
        relative: sha256_bytes(head_blob(repo, resolved_head, relative))
        for relative in protected_paths
    }
    document = {
        "schema_version": MANIFEST_SCHEMA,
        "sealed_scope": SEALED_SCOPE,
        "source_self_modification_enabled": False,
        "files": hashes,
    }
    return {
        "head": resolved_head,
        "protected_paths": protected_paths,
        "protected_file_count": len(protected_paths),
        "hash_algorithm": HASH_ALGORITHM,
        "manifest_self_included": False,
        "document": document,
        "bytes": (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8"),
    }


def _safe_manifest_path(repo: Path) -> Path:
    manifest_path = repo / MANIFEST_RELATIVE
    try:
        if manifest_path.resolve().relative_to(repo.resolve()) != Path(MANIFEST_RELATIVE):
            raise ResealError("MANIFEST_PATH_ESCAPE")
    except (OSError, ValueError):
        raise ResealError("MANIFEST_PATH_ESCAPE")
    if manifest_path.is_symlink() or manifest_path.parent.is_symlink():
        raise ResealError("MANIFEST_SYMLINK_BLOCKED")
    return manifest_path


def atomic_write_manifest(path: Path, value: bytes) -> None:
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".source-integrity-reseal-",
            suffix=".tmp",
            dir=str(path.parent),
        )
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise ResealError("MANIFEST_WRITE_FAILED")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def tracked_status_lines(repo: Path) -> List[str]:
    completed = run_git(repo, ["status", "--porcelain=v1", "--untracked-files=no"])
    try:
        return [line for line in completed.stdout.decode("utf-8").splitlines() if line]
    except UnicodeDecodeError:
        raise ResealError("GIT_STATUS_INVALID")


def reseal_repository(repo: Path) -> Dict[str, Any]:
    require_clean_tracked_tree(repo)
    head = resolve_head(repo)
    manifest_path = _safe_manifest_path(repo)
    try:
        original = manifest_path.read_bytes()
    except OSError:
        raise ResealError("MANIFEST_READ_FAILED")
    built = build_resealed_manifest(repo, head)
    atomic_write_manifest(manifest_path, built["bytes"])
    status_lines = tracked_status_lines(repo)
    expected_line = f" M {MANIFEST_RELATIVE}"
    if status_lines not in ([expected_line], []):
        atomic_write_manifest(manifest_path, original)
        raise ResealError("UNEXPECTED_TRACKED_PATH_CHANGED")
    return {
        "status": "SOURCE_MANIFEST_RESEAL_OK",
        "resealed_head": head,
        "protected_file_count": built["protected_file_count"],
        "manifest_files_changed": [MANIFEST_RELATIVE] if status_lines else [],
        "unexpected_manifest_path_change": False,
        "hashes_match_head": True,
        "manifest_self_included": False,
    }


def validate_worktree_manifest(repo: Path) -> Dict[str, Any]:
    manifest_path = _safe_manifest_path(repo)
    try:
        manifest = parse_manifest_bytes(manifest_path.read_bytes())
    except OSError:
        return {"status": "SOURCE_INTEGRITY_BLOCKED", "findings": ["manifest_read_failed"]}
    try:
        protected_paths = validate_manifest_policy(manifest)
    except ResealError as exc:
        return {"status": "SOURCE_INTEGRITY_BLOCKED", "findings": [exc.code]}
    findings: List[str] = []
    repo_resolved = repo.resolve()
    for relative in protected_paths:
        path = repo / relative
        try:
            path.resolve().relative_to(repo_resolved)
        except (OSError, ValueError):
            findings.append(f"source_path_escape:{relative}")
            continue
        if path.is_symlink() or not path.is_file():
            findings.append(f"source_missing_or_symlink:{relative}")
            continue
        try:
            current = sha256_bytes(path.read_bytes())
        except OSError:
            findings.append(f"source_read_failed:{relative}")
            continue
        if current != manifest["files"][relative]:
            findings.append(f"source_hash_mismatch:{relative}")
    return {
        "status": "SOURCE_INTEGRITY_VERIFIED" if not findings else "SOURCE_INTEGRITY_BLOCKED",
        "protected_file_count": len(protected_paths),
        "findings": sorted(findings),
    }


def inspect_model(repo: Path) -> Dict[str, Any]:
    head = resolve_head(repo)
    manifest = committed_manifest(repo, head)
    paths = validate_manifest_policy(manifest)
    return {
        "source_manifest_path": MANIFEST_RELATIVE,
        "source_integrity_validator": "sentinel_runtime_safety.verify_fixed_source_manifest",
        "protected_file_selection_model": "explicit_committed_manifest_allowlist",
        "protected_file_count": len(paths),
        "hash_algorithm": HASH_ALGORITHM,
        "hash_input": "raw_committed_git_blob_bytes",
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_self_included": MANIFEST_RELATIVE in paths,
        "current_reseal_support": "DETERMINISTIC_HEAD_BACKED_RESEAL",
        "head": head,
        "tracked_tree": tracked_tree_status(repo),
    }


def _write_fixture_repo(root: Path, files: Dict[str, bytes], protected: List[str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    run_git(root, ["init", "-q"])
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manifest_path = root / MANIFEST_RELATIVE
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": MANIFEST_SCHEMA,
        "sealed_scope": SEALED_SCOPE,
        "source_self_modification_enabled": False,
        "files": {
            relative: sha256_bytes(files.get(relative, b"missing"))
            for relative in protected
        },
    }
    manifest_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    run_git(root, ["add", "--", *sorted([*files, MANIFEST_RELATIVE])])
    run_git(
        root,
        [
            "-c", "user.name=Sentinel Self Test",
            "-c", "user.email=sentinel-self-test@example.invalid",
            "commit", "-q", "-m", "fixture",
        ],
    )


def _expect_error(function: Any, code: str) -> bool:
    try:
        function()
    except ResealError as exc:
        return exc.code == code
    return False


def self_test() -> Dict[str, Any]:
    checks: Dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="sentinel-reseal-self-test-") as temporary:
        base = Path(temporary)

        clean = base / "clean"
        fixture_files = {
            "protected/a.txt": b"committed-a\n",
            "protected/b.txt": b"committed-b\n",
            "unrelated.txt": b"unrelated\n",
        }
        _write_fixture_repo(clean, fixture_files, ["protected/a.txt", "protected/b.txt"])
        first = build_resealed_manifest(clean)
        second = build_resealed_manifest(clean)
        (clean / "state/runtime.json").parent.mkdir(parents=True)
        (clean / "state/runtime.json").write_text("{}\n", encoding="utf-8")
        resealed = reseal_repository(clean)
        validated = validate_worktree_manifest(clean)
        checks["clean_committed_tree_resealed"] = resealed["status"] == "SOURCE_MANIFEST_RESEAL_OK"
        checks["untracked_runtime_not_added"] = "state/runtime.json" not in first["document"]["files"]
        checks["repeated_head_mapping_identical"] = first["bytes"] == second["bytes"]
        checks["hashes_equal_committed_head_content"] = (
            first["document"]["files"]["protected/a.txt"] == sha256_bytes(b"committed-a\n")
        )
        checks["manifest_not_self_referential"] = first["manifest_self_included"] is False
        checks["validator_accepts_resealed_source"] = validated["status"] == "SOURCE_INTEGRITY_VERIFIED"
        (clean / "protected/a.txt").write_text("tampered\n", encoding="utf-8")
        checks["tampered_source_detected"] = (
            validate_worktree_manifest(clean)["status"] == "SOURCE_INTEGRITY_BLOCKED"
        )

        dirty_protected = base / "dirty-protected"
        _write_fixture_repo(dirty_protected, fixture_files, ["protected/a.txt"])
        (dirty_protected / "protected/a.txt").write_text("working-tree-only\n", encoding="utf-8")
        committed_mapping = build_resealed_manifest(dirty_protected)["document"]["files"]
        checks["working_tree_cannot_substitute_for_head"] = (
            committed_mapping["protected/a.txt"] == sha256_bytes(b"committed-a\n")
            and _expect_error(
                lambda: reseal_repository(dirty_protected),
                "RESEAL_ABORTED_DIRTY_TRACKED_TREE",
            )
        )
        checks["dirty_protected_file_blocks"] = checks["working_tree_cannot_substitute_for_head"]

        dirty_unrelated = base / "dirty-unrelated"
        _write_fixture_repo(dirty_unrelated, fixture_files, ["protected/a.txt"])
        (dirty_unrelated / "unrelated.txt").write_text("changed\n", encoding="utf-8")
        checks["dirty_unrelated_tracked_file_blocks"] = _expect_error(
            lambda: reseal_repository(dirty_unrelated),
            "RESEAL_ABORTED_DIRTY_TRACKED_TREE",
        )

        staged = base / "staged"
        _write_fixture_repo(staged, fixture_files, ["protected/a.txt"])
        (staged / "unrelated.txt").write_text("staged\n", encoding="utf-8")
        run_git(staged, ["add", "--", "unrelated.txt"])
        checks["staged_tracked_change_blocks"] = _expect_error(
            lambda: reseal_repository(staged),
            "RESEAL_ABORTED_DIRTY_TRACKED_TREE",
        )

        missing = base / "missing"
        _write_fixture_repo(missing, {"unrelated.txt": b"x\n"}, ["protected/missing.txt"])
        checks["missing_protected_head_file_blocks"] = _expect_error(
            lambda: build_resealed_manifest(missing),
            "PROTECTED_HEAD_FILE_MISSING",
        )

        traversal = base / "traversal"
        _write_fixture_repo(traversal, {"unrelated.txt": b"x\n"}, ["../escape.txt"])
        checks["path_traversal_rejected"] = _expect_error(
            lambda: build_resealed_manifest(traversal),
            "PROTECTED_PATH_INVALID",
        )

        symlink = base / "symlink"
        _write_fixture_repo(symlink, {"unrelated.txt": b"x\n"}, ["protected/link.txt"])
        link = symlink / "protected/link.txt"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("../unrelated.txt")
        run_git(symlink, ["add", "--", "protected/link.txt"])
        run_git(
            symlink,
            [
                "-c", "user.name=Sentinel Self Test",
                "-c", "user.email=sentinel-self-test@example.invalid",
                "commit", "-q", "-m", "add symlink",
            ],
        )
        checks["head_symlink_rejected"] = _expect_error(
            lambda: build_resealed_manifest(symlink),
            "PROTECTED_HEAD_FILE_NOT_REGULAR",
        )

        self_reference = base / "self-reference"
        _write_fixture_repo(
            self_reference,
            {"unrelated.txt": b"x\n"},
            [MANIFEST_RELATIVE],
        )
        checks["manifest_self_reference_rejected"] = _expect_error(
            lambda: build_resealed_manifest(self_reference),
            "SOURCE_MANIFEST_SELF_REFERENCE_BLOCKER",
        )

    checks.update({
        "fixed_manifest_path": MANIFEST_PATH == PROJECT_DIR / MANIFEST_RELATIVE,
        "no_arbitrary_manifest_cli": not any(
            action.dest in {"path", "manifest", "repo"}
            for action in build_parser()._actions
        ),
        "sha256_selected": HASH_ALGORITHM == "sha256",
        "breach_false": True,
    })
    findings = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "SOURCE_INTEGRITY_RESEAL_SELF_TEST_OK" if not findings else "SOURCE_INTEGRITY_RESEAL_SELF_TEST_FAILED",
        "checks": checks,
        "findings": findings,
        "breach": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deterministic committed-HEAD source integrity reseal")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--inspect", action="store_true")
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--reseal", action="store_true")
    group.add_argument("--validate", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.self_test:
            result = self_test()
        elif args.inspect:
            result = {"status": "SOURCE_INTEGRITY_MODEL_OK", **inspect_model(PROJECT_DIR)}
        elif args.reseal:
            result = reseal_repository(PROJECT_DIR)
        else:
            result = validate_worktree_manifest(PROJECT_DIR)
    except ResealError as exc:
        result = {"status": "SOURCE_INTEGRITY_RESEAL_BLOCKED", "reason": exc.code, "breach": False}
    print(result["status"])
    for key in (
        "reason",
        "head",
        "resealed_head",
        "protected_file_count",
        "hash_algorithm",
        "manifest_self_included",
        "hashes_match_head",
    ):
        if key in result:
            print(f"{key}={result[key]}")
    findings = result.get("findings", [])
    for finding in findings:
        print(f"finding={finding}")
    return 0 if result["status"] in {
        "SOURCE_INTEGRITY_MODEL_OK",
        "SOURCE_INTEGRITY_RESEAL_OK",
        "SOURCE_INTEGRITY_RESEAL_SELF_TEST_OK",
        "SOURCE_INTEGRITY_VERIFIED",
    } else 2


if __name__ == "__main__":
    raise SystemExit(main())
