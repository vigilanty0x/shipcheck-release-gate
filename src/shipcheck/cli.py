"""Shipcheck command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Any

from . import __version__
from .api import create_server
from .adapters import normalize_bundle, normalize_cyclonedx, normalize_junit, normalize_sarif
from .artifacts import hash_artifact, inspect_archive
from .canonical import canonical_json
from .demo import write_demo
from .engine import DecisionEngine
from .errors import ShipcheckError, ValidationError
from .ledger import DecisionLedger
from .limits import load_json_file
from .models import Decision, ReleaseEvidence, ReleasePolicy, Waiver
from .report import RENDERERS, render
from .receipt import explain_receipt, render_receipt, verify_receipt
from .selftest import run_selftest
from .secureio import atomic_write, read_regular_file, read_secret_file
from .trust import TrustStore

EXIT_READY = 0
EXIT_NOT_READY = 2
EXIT_INVALID = 3
EXIT_INTERNAL = 4


class StableArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValidationError(f"command line: {message}")


def _load_inputs(args: argparse.Namespace) -> tuple[ReleaseEvidence, ReleasePolicy, TrustStore, tuple[Waiver, ...]]:
    evidence = ReleaseEvidence.from_dict(load_json_file(args.evidence))
    policy = ReleasePolicy.from_dict(load_json_file(args.policy))
    from .limits import loads_strict
    trust = TrustStore.from_dict(loads_strict(read_secret_file(args.trust_store, max_bytes=262_144), max_bytes=262_144))
    if policy.digest != args.expected_policy_digest:
        raise ValidationError("policy digest does not match the protected expected digest")
    if trust.digest != args.expected_trust_digest:
        raise ValidationError("trust store digest does not match the protected expected digest")
    waivers: tuple[Waiver, ...] = ()
    if getattr(args, "waivers", None):
        raw = load_json_file(args.waivers, max_bytes=262_144)
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "waivers"} or raw["schema_version"] != "shipcheck/waivers-v1":
            raise ValidationError("waiver file must use shipcheck/waivers-v1")
        if not isinstance(raw["waivers"], list) or len(raw["waivers"]) > 100:
            raise ValidationError("waiver file may contain at most 100 waivers")
        waivers = tuple(Waiver.from_dict(item) for item in raw["waivers"])
        if len({item.waiver_id for item in waivers}) != len(waivers):
            raise ValidationError("waiver_id values must be unique")
    return evidence, policy, trust, waivers


def _write_or_stdout(data: bytes, output: str | None) -> None:
    if output:
        atomic_write(output, data, mode=0o600)
    else:
        sys.stdout.buffer.write(data)


def _paths_alias(left: str | Path, right: str | Path) -> bool:
    a, b = Path(left), Path(right)
    try:
        if a.exists() and b.exists() and os.path.samefile(a, b):
            return True
    except OSError:
        pass
    try:
        return os.path.normcase(str(a.resolve(strict=False))) == os.path.normcase(str(b.resolve(strict=False)))
    except OSError:
        return os.path.normcase(str(a.absolute())) == os.path.normcase(str(b.absolute()))


def _parser() -> argparse.ArgumentParser:
    parser = StableArgumentParser(prog="shipcheck", description="Evidence-first release decision engine")
    parser.add_argument("--version", action="version", version=f"shipcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("capabilities", help="print the bounded offline feature contract")
    sub.add_parser("selftest", help="run deterministic contracts shared by source, wheel, and sdist")

    demo = sub.add_parser("demo", help="write a fresh, clearly synthetic E2E fixture")
    demo.add_argument("--out", required=True)

    for name in ("validate", "decide"):
        command = sub.add_parser(name, help=f"{name} versioned release evidence")
        command.add_argument("--evidence", required=True)
        command.add_argument("--policy", required=True)
        command.add_argument("--trust-store", required=True)
        command.add_argument("--expected-policy-digest", required=True)
        command.add_argument("--expected-trust-digest", required=True)
        command.add_argument("--waivers")
        if name == "decide":
            command.add_argument("--format", choices=sorted(RENDERERS), default="json")
            command.add_argument("--out")
            command.add_argument("--ledger")
            command.add_argument("--idempotency-key")
            command.add_argument("--receipt-out")

    artifact = sub.add_parser("artifact", help="hash or inspect an inert artifact without extraction/execution")
    artifact_sub = artifact.add_subparsers(dest="artifact_command", required=True)
    for name in ("hash", "inspect"):
        command = artifact_sub.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument("--path", required=True)

    normalize = sub.add_parser("normalize", help="normalize a bounded offline CI artifact without trusting it")
    normalize_sub = normalize.add_subparsers(dest="normalize_command", required=True)
    junit = normalize_sub.add_parser("junit", help="normalize JUnit XML to test_summary records")
    junit.add_argument("--input", required=True); junit.add_argument("--run-id", default="supplied-junit"); junit.add_argument("--out")
    sarif = normalize_sub.add_parser("sarif", help="normalize SARIF 2.1.0 to a gap/check summary")
    sarif.add_argument("--input", required=True); sarif.add_argument("--out")
    cyclonedx = normalize_sub.add_parser("cyclonedx", help="normalize CycloneDX JSON to an artifact-bound SBOM record")
    cyclonedx.add_argument("--input", required=True); cyclonedx.add_argument("--artifact-name", required=True); cyclonedx.add_argument("--artifact-digest", required=True); cyclonedx.add_argument("--out")
    bundle = normalize_sub.add_parser("bundle", help="compose normalized JSON documents without changing their trust level")
    bundle.add_argument("--input", action="append", required=True); bundle.add_argument("--out")

    ledger = sub.add_parser("ledger", help="inspect the local decision ledger")
    ledger_sub = ledger.add_subparsers(dest="ledger_command", required=True)
    for name in ("verify", "list", "get", "state"):
        command = ledger_sub.add_parser(name)
        command.add_argument("--ledger", required=True)
        if name == "list":
            command.add_argument("--after", type=int, default=0)
            command.add_argument("--limit", type=int, default=100)
        if name == "get":
            command.add_argument("--sequence", required=True, type=int)
        if name == "state":
            command.add_argument("--candidate-digest", required=True)

    promotion = sub.add_parser("promotion", help="record local promotion state only; never changes a forge or environment")
    promotion_sub = promotion.add_subparsers(dest="promotion_command", required=True)
    plan = promotion_sub.add_parser("plan")
    plan.add_argument("--ledger", required=True); plan.add_argument("--decision-sequence", type=int, required=True); plan.add_argument("--idempotency-key", required=True)
    for name in ("apply", "verify"):
        command = promotion_sub.add_parser(name)
        command.add_argument("--ledger", required=True); command.add_argument("--candidate-digest", required=True); command.add_argument("--decision-digest", required=True); command.add_argument("--fencing-token", required=True, type=int); command.add_argument("--idempotency-key", required=True)
    rollback = promotion_sub.add_parser("rollback")
    rollback.add_argument("--ledger", required=True); rollback.add_argument("--candidate-digest", required=True); rollback.add_argument("--reason", required=True); rollback.add_argument("--fencing-token", required=True, type=int); rollback.add_argument("--idempotency-key", required=True)

    receipt = sub.add_parser(
        "receipt",
        help="export or check a potentially sensitive, internal-consistency-only receipt",
    )
    receipt_sub = receipt.add_subparsers(dest="receipt_command", required=True)
    export = receipt_sub.add_parser("export")
    export.add_argument("--ledger", required=True); export.add_argument("--sequence", type=int, required=True); export.add_argument("--out", required=True)
    for name in ("verify", "explain"):
        command = receipt_sub.add_parser(name)
        command.add_argument("--receipt", required=True)

    serve = sub.add_parser("serve", help="serve authenticated read-only dashboard on loopback")
    serve.add_argument("--ledger", required=True); serve.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1"); serve.add_argument("--port", type=int, default=8765); serve.add_argument("--token-file")
    return parser


def _execute(args: argparse.Namespace) -> int:
    if args.command == "demo":
        print(json.dumps(write_demo(args.out), sort_keys=True))
        return EXIT_READY
    if args.command == "capabilities":
        sys.stdout.buffer.write(canonical_json({
            "schema_version": "shipcheck/capabilities-v1",
            "offline": True,
            "runtime_dependencies": 0,
            "states": ["READY", "BLOCKED", "UNKNOWN"],
            "assurance_profiles": ["LAB", "PRODUCTION"],
            "production_ready_semantics": "outcome=READY and assurance_profile=PRODUCTION",
            "reports": sorted(RENDERERS),
            "offline_normalizers": ["junit-xml", "sarif-2.1.0", "cyclonedx-json", "normalized-bundle"],
            "artifact_parity_selftest": "shipcheck selftest",
            "normalized_input_trust": {"source_kind": "supplied", "trust_level": "self_declared", "production_ready_by_itself": False},
            "receipt_operations": ["export", "verify-internal-consistency", "explain"],
            "receipt_authenticity_established": False,
            "receipt_integrity_scope": "internal_consistency_only",
            "exit_codes": {"production_ready": 0, "not_ready_or_lab": 2, "invalid_input": 3, "internal_error": 4},
            "mutations": ["local-ledger"],
            "forbidden": ["execute-code", "merge", "deploy", "forge-network", "extract-archive"],
        }) + b"\n")
        return EXIT_READY
    if args.command == "selftest":
        sys.stdout.buffer.write(canonical_json(run_selftest()) + b"\n")
        return EXIT_READY
    if args.command in {"validate", "decide"}:
        evidence, policy, trust, waivers = _load_inputs(args)
        decision = DecisionEngine(trust_store=trust).evaluate(evidence, policy, waivers=waivers)
        if args.command == "validate":
            print(json.dumps({"valid": True, "outcome": decision.outcome, "assurance_profile": decision.assurance_profile, "production_ready": decision.production_ready, "release_id": evidence.release_id, "evidence_digest": evidence.digest, "policy_digest": policy.digest}, sort_keys=True))
            return EXIT_READY if decision.production_ready else EXIT_NOT_READY
        if args.idempotency_key and not args.ledger:
            raise ValidationError("--idempotency-key requires --ledger")
        if args.receipt_out and not args.ledger:
            raise ValidationError("--receipt-out requires --ledger")
        if args.out:
            protected = [args.evidence, args.policy, args.trust_store]
            if args.waivers:
                protected.append(args.waivers)
            if args.ledger:
                protected.extend([args.ledger, f"{args.ledger}.anchor", f"{args.ledger}-wal", f"{args.ledger}-shm", f"{args.ledger}.init.lock"])
            if any(_paths_alias(args.out, path) for path in protected):
                raise ValidationError("report output must not alias ledger, sidecars, or decision inputs")
        if args.ledger:
            if not args.idempotency_key:
                raise ValidationError("--idempotency-key is required with --ledger")
            if not args.receipt_out:
                raise ValidationError("--receipt-out is required with --ledger")
            receipt_protected = [args.evidence, args.policy, args.trust_store, args.ledger, f"{args.ledger}.anchor", f"{args.ledger}-wal", f"{args.ledger}-shm", f"{args.ledger}.init.lock"]
            if args.waivers:
                receipt_protected.append(args.waivers)
            if args.out:
                receipt_protected.append(args.out)
            if any(_paths_alias(args.receipt_out, path) for path in receipt_protected):
                raise ValidationError("receipt output must not alias report, ledger, sidecars, or decision inputs")
            ledger = DecisionLedger(args.ledger)
            decision, ledger_receipt = ledger.evaluate_and_record(
                evidence, policy, trust, expected_policy_digest=args.expected_policy_digest,
                expected_trust_digest=args.expected_trust_digest, idempotency_key=args.idempotency_key, waivers=waivers,
            )
            atomic_write(args.receipt_out, render_receipt(ledger, ledger_receipt.sequence))
        _write_or_stdout(render(decision, args.format, evidence), args.out)
        return EXIT_READY if decision.production_ready else EXIT_NOT_READY
    if args.command == "artifact":
        result = hash_artifact(args.root, args.path) if args.artifact_command == "hash" else inspect_archive(args.root, args.path)
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return EXIT_READY
    if args.command == "normalize":
        inputs = list(args.input) if isinstance(args.input, list) else [args.input]
        if args.out and any(_paths_alias(args.out, path) for path in inputs):
            raise ValidationError("normalized output must not alias an input")
        if args.normalize_command == "junit":
            result = normalize_junit(read_regular_file(args.input, max_bytes=2_097_152), run_id=args.run_id)
        elif args.normalize_command == "sarif":
            result = normalize_sarif(read_regular_file(args.input, max_bytes=2_097_152))
        elif args.normalize_command == "cyclonedx":
            result = normalize_cyclonedx(
                read_regular_file(args.input, max_bytes=2_097_152),
                artifact_name=args.artifact_name,
                artifact_digest=args.artifact_digest,
            )
        else:
            from .limits import loads_strict
            documents = [loads_strict(read_regular_file(path, max_bytes=2_097_152), max_bytes=2_097_152) for path in args.input]
            result = normalize_bundle(documents)
        _write_or_stdout(canonical_json(result) + b"\n", args.out)
        return EXIT_READY
    if args.command == "ledger":
        ledger = DecisionLedger(args.ledger)
        if args.ledger_command == "verify": result = ledger.verify()
        elif args.ledger_command == "list": result = {"entries": ledger.list_entries(after=args.after, limit=args.limit)}
        elif args.ledger_command == "get": result = ledger.get_entry(args.sequence)
        else: result = {"state": ledger.promotion_state(args.candidate_digest)}
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return EXIT_READY if result.get("ok", True) else EXIT_NOT_READY
    if args.command == "promotion":
        ledger = DecisionLedger(args.ledger)
        if args.promotion_command == "plan":
            entry = ledger.get_entry(args.decision_sequence)
            if entry["receipt"]["entry_type"] != "EVALUATED_DECISION": raise ValidationError("sequence does not contain a ledger-evaluated decision")
            envelope = entry["payload"]
            if not isinstance(envelope, dict) or not isinstance(envelope.get("decision"), dict): raise ValidationError("evaluated decision envelope is invalid")
            receipt = ledger.plan_promotion(Decision.from_dict(envelope["decision"]), idempotency_key=args.idempotency_key)
        elif args.promotion_command == "apply": receipt = ledger.apply_promotion(candidate_digest=args.candidate_digest, decision_digest=args.decision_digest, expected_fencing_token=args.fencing_token, idempotency_key=args.idempotency_key)
        elif args.promotion_command == "verify": receipt = ledger.verify_promotion(candidate_digest=args.candidate_digest, decision_digest=args.decision_digest, expected_fencing_token=args.fencing_token, idempotency_key=args.idempotency_key)
        else: receipt = ledger.rollback_promotion(candidate_digest=args.candidate_digest, reason=args.reason, expected_fencing_token=args.fencing_token, idempotency_key=args.idempotency_key)
        sys.stdout.buffer.write(canonical_json(receipt.to_dict()) + b"\n")
        return EXIT_READY
    if args.command == "receipt":
        if args.receipt_command == "export":
            protected = [args.ledger, f"{args.ledger}.anchor", f"{args.ledger}-wal", f"{args.ledger}-shm", f"{args.ledger}.init.lock"]
            if any(_paths_alias(args.out, path) for path in protected):
                raise ValidationError("receipt output must not alias ledger or sidecars")
            atomic_write(args.out, render_receipt(DecisionLedger(args.ledger), args.sequence))
            return EXIT_READY
        raw = read_regular_file(args.receipt, max_bytes=2_097_152)
        result = verify_receipt(raw) if args.receipt_command == "verify" else explain_receipt(raw)
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        if args.receipt_command == "verify":
            return EXIT_READY if result["internally_consistent"] else EXIT_NOT_READY
        return EXIT_READY if result["internally_consistent"] else EXIT_NOT_READY
    if args.command == "serve":
        token = None
        if args.token_file:
            token = read_secret_file(args.token_file, max_bytes=4_096).decode("utf-8", "strict").strip()
        server, actual_token = create_server(ledger=DecisionLedger(args.ledger), token=token, host=args.host, port=args.port)
        print(f"Shipcheck read-only dashboard: http://{args.host}:{args.port}/", flush=True)
        if token is None: print(f"Ephemeral session token: {actual_token}", flush=True)
        try: server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt: pass
        finally: server.server_close()
        return EXIT_READY
    raise ValidationError("unknown command")


def main(argv: list[str] | None = None) -> int:
    try:
        return _execute(_parser().parse_args(argv))
    except ShipcheckError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message}, sort_keys=True), file=sys.stderr)
        return EXIT_INVALID
    except (UnicodeError, OSError, ValueError) as exc:
        print(json.dumps({"error": "INVALID_INPUT", "message": str(exc)}, sort_keys=True), file=sys.stderr)
        return EXIT_INVALID
    except Exception as exc:  # defensive CLI boundary; no traceback or sensitive repr
        print(json.dumps({"error": "INTERNAL_ERROR", "message": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
