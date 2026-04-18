"""CLI entry point for plan generation — extracted from plan_generator.py."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from plan.detectors import _detect_lang
from plan.generator import generate_plan
from plan.post_compile import phase_post_compile, phase_checkpoint, phase_write_fork_setup
from plan.prompts_solidity import (
    phase_hunter_prompt, phase_deepdive_prompt, phase_findings,
    phase_fork_poc_prompt, phase_cross_prompt,
    phase_chimera_early_prompt, phase_chimera_builder_prompt,
    phase_enhance_targets_prompt,
)
from plan.prompts_rust import (
    phase_rust_fuzz_scaffold_prompt, phase_rust_fuzz_harness_prompt,
    phase_rust_merge_harness,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plan generator for agent-mode benchmarks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Generate full execution plan\n"
            "  python3 plan_generator.py --generate --repo /path --components A,B "
            "--protocol proto --session-dir /tmp/sess\n\n"
            "  # Dynamic phase (called mid-execution by skill)\n"
            "  python3 plan_generator.py --phase hunter-prompt --component A "
            "--protocol proto --repo /path --session-dir /tmp/sess\n"
        ),
    )
    parser.add_argument(
        "--generate", action="store_true",
        help="Generate a full execution plan JSON",
    )
    parser.add_argument(
        "--phase",
        choices=[
            "hunter-prompt", "deepdive-prompt", "findings", "cross-prompt",
            "checkpoint", "chimera-early-prompt", "chimera-builder-prompt",
            "enhance-targets-prompt", "post-compile", "write-fork-setup",
            "fork-poc-prompt",
            # Rust pipeline phases
            "rust-fuzz-scaffold-prompt", "rust-fuzz-harness-prompt",
            "rust-merge-harness",
        ],
        help="Dynamic phase to execute mid-run",
    )
    parser.add_argument("--repo", help="Path to repo root")
    parser.add_argument(
        "--components", help="Comma-separated components (for --generate)",
    )
    parser.add_argument(
        "--component", help="Single component or comma pair (for --phase)",
    )
    parser.add_argument("--protocol", help="Protocol name")
    parser.add_argument("--session-dir", help="Path to session directory")
    parser.add_argument("--ground-truth", help="Path to benchmark YAML")
    parser.add_argument("--fast", action="store_true", help="Fast mode (fewer fuzz runs)")
    parser.add_argument(
        "--pre-production", action="store_true",
        help="Pre-production mode (deploy-on-fork PoC strategy)",
    )
    parser.add_argument(
        "--benchmark-mode",
        choices=["hypothesis", "poc", "redteam"],
        default="redteam",
        help="Benchmark depth: hypothesis (hunters only), poc (+PoC), redteam (full pipeline)",
    )
    parser.add_argument(
        "--finding-id",
        help="Finding ID (for --phase fork-poc-prompt)",
    )
    parser.add_argument(
        "--parallel-components", type=int, default=1,
        help="Max components to run in parallel via Agent Teams (default: 1 = sequential)",
    )
    parser.add_argument(
        "--chain", default="mainnet",
        help="Target chain for fork PoCs (mainnet, base, optimism, arbitrum, polygon)",
    )
    parser.add_argument(
        "--fork-block", type=int, default=0,
        help="Fork block for PoCs. 0 = latest (portable, no hardcoded block)",
    )
    parser.add_argument(
        "--lang", default="",
        help="Contract language: solidity, rust (auto-detected if empty)",
    )

    args = parser.parse_args()

    if args.generate:
        if not args.repo or not args.components or not args.protocol or not args.session_dir:
            parser.error("--generate requires --repo, --components, --protocol, --session-dir")

        components = [c.strip() for c in args.components.split(",") if c.strip()]
        plan = generate_plan(
            repo=args.repo,
            components=components,
            protocol=args.protocol,
            session_dir=args.session_dir,
            ground_truth=args.ground_truth or "",
            is_pre_production=args.pre_production,
            fast=args.fast,
            benchmark_mode=args.benchmark_mode,
            parallel_components=args.parallel_components,
            chain=args.chain,
            fork_block=args.fork_block,
            lang=args.lang,
        )

        # Write plan to session_dir/execution_plan.json
        out_path = Path(args.session_dir) / "execution_plan.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plan.to_json(str(out_path))
        print(json.dumps({"plan_path": str(out_path), "steps": len(plan.steps)}, indent=2))

    elif args.phase:
        if not args.protocol or not args.session_dir:
            parser.error("--phase requires --protocol and --session-dir")

        if args.phase == "hunter-prompt":
            if not args.component or not args.repo:
                parser.error("--phase hunter-prompt requires --component and --repo")
            result = phase_hunter_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                         lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "deepdive-prompt":
            if not args.component or not args.repo:
                parser.error("--phase deepdive-prompt requires --component and --repo")
            result = phase_deepdive_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                            lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "findings":
            if not args.component or not args.repo:
                parser.error("--phase findings requires --component and --repo")
            result = phase_findings(
                args.component, args.protocol, args.repo, args.session_dir,
                benchmark_mode=args.benchmark_mode,
                chain=args.chain,
                fork_block=args.fork_block,
                lang=args.lang or _detect_lang(args.repo),
                parallel_components=args.parallel_components,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "cross-prompt":
            if not args.component or not args.repo:
                parser.error("--phase cross-prompt requires --component and --repo")
            result = phase_cross_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                         lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "chimera-early-prompt":
            if not args.component or not args.repo:
                parser.error("--phase chimera-early-prompt requires --component and --repo")
            result = phase_chimera_early_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "chimera-builder-prompt":
            if not args.component or not args.repo:
                parser.error("--phase chimera-builder-prompt requires --component and --repo")
            result = phase_chimera_builder_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                 parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "enhance-targets-prompt":
            if not args.component or not args.repo:
                parser.error("--phase enhance-targets-prompt requires --component and --repo")
            result = phase_enhance_targets_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                  parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-fuzz-scaffold-prompt":
            if not args.component or not args.repo:
                parser.error("--phase rust-fuzz-scaffold-prompt requires --component and --repo")
            result = phase_rust_fuzz_scaffold_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-fuzz-harness-prompt":
            if not args.component or not args.repo:
                parser.error("--phase rust-fuzz-harness-prompt requires --component and --repo")
            result = phase_rust_fuzz_harness_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-merge-harness":
            if not args.component or not args.repo:
                parser.error("--phase rust-merge-harness requires --component and --repo")
            phase_rust_merge_harness(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )

        elif args.phase == "post-compile":
            if not args.component or not args.repo:
                parser.error("--phase post-compile requires --component and --repo")
            result = phase_post_compile(
                args.component, args.protocol, args.repo, args.session_dir,
                fast=args.fast,
                lang=args.lang or _detect_lang(args.repo),
                parallel_components=args.parallel_components,
                is_pre_production=args.pre_production,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "write-fork-setup":
            if not args.repo:
                parser.error("--phase write-fork-setup requires --repo")
            phase_write_fork_setup(args.repo, chain=args.chain, fork_block=args.fork_block)

        elif args.phase == "fork-poc-prompt":
            if not args.component or not args.repo or not args.finding_id:
                parser.error("--phase fork-poc-prompt requires --component, --repo, --finding-id")
            result = phase_fork_poc_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                finding_id=args.finding_id,
                chain=args.chain,
                fork_block=args.fork_block,
                parallel_components=args.parallel_components,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "checkpoint":
            if not args.component:
                parser.error("--phase checkpoint requires --component")
            phase_checkpoint(args.component, args.protocol, args.session_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
