#!/usr/bin/env python3
"""Resolve a numbered OpenSpec task to a model; never start an agent or mark work done."""

import argparse
import json
from pathlib import Path
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parents[2]
TIERS = {"light": 0, "standard": 1, "deep": 2}
TASK = re.compile(r"^- \[([ xX])\] (\d+(?:\.\d+)+)\s+(.+)$")
METADATA = re.compile(r"<!-- agent: (.+) -->")


def config(root):
    data = json.loads((root / ".claude/task-routing.json").read_text())
    if not isinstance(data, dict) or data.get("schemaVersion") != 1 or data.get("defaultTier") not in TIERS:
        raise ValueError("unsupported routing schema or default tier")
    providers = data.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("providers must be a nonempty object")
    for name, provider in providers.items():
        if not isinstance(provider, dict):
            raise ValueError(f"{name}: provider must be an object")
        models, defaults = provider["models"], provider["defaults"]
        if not isinstance(models, dict) or not isinstance(defaults, dict) or set(defaults) != set(TIERS) or not models:
            raise ValueError(f"{name}: supply every tier default and a model catalog")
        for model, tier in models.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", model) or tier not in TIERS:
                raise ValueError(f"{name}: invalid model or tier")
        for tier, model in defaults.items():
            if model not in models or TIERS[models[model]] < TIERS[tier]:
                raise ValueError(f"{name}: default model cannot satisfy {tier}")
    return data


def tasks(path):
    result = {}
    previous = None
    fence = None
    for number, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        marker = re.match(r"^(`{3,}|~{3,})", stripped)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            previous = None
            continue
        if fence:
            continue
        match = TASK.fullmatch(line)
        if match:
            done, task_id, description = match.groups()
            if task_id in result:
                raise ValueError(f"{path}:{number}: duplicate task {task_id}")
            previous = {"task": task_id, "description": description, "done": done.lower() == "x",
                        "line": number, "metadata": {}}
            result[task_id] = previous
        elif stripped.startswith("<!-- agent"):
            match = METADATA.fullmatch(stripped)
            if previous is None or match is None:
                raise ValueError(f"{path}:{number}: malformed or non-adjacent agent metadata")
            metadata = {}
            for field in shlex.split(match[1]):
                key, separator, value = field.partition("=")
                if not separator or key not in {"tier", "risk", "reason"} or key in metadata or not value:
                    raise ValueError(f"{path}:{number}: invalid or duplicate metadata field")
                metadata[key] = value
            if metadata.get("tier") not in TIERS or metadata.get("risk") not in {"low", "medium", "high"}:
                raise ValueError(f"{path}:{number}: metadata needs a valid tier and risk")
            if metadata["risk"] == "high" and metadata["tier"] != "deep":
                raise ValueError(f"{path}:{number}: high risk requires deep tier")
            previous["metadata"] = metadata
            previous = None
        else:
            previous = None
    return result


def select(root, change, task_id, provider_name, model=None, escalate=False):
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", change):
        raise ValueError("change must be an active change name, not a path")
    path = root / "openspec/changes" / change / "tasks.md"
    data = config(root)
    task = tasks(path).get(task_id)
    if task is None:
        raise ValueError(f"unknown task {task_id}; use the printed dotted number, not OpenSpec's ordinal ID")
    if task["done"]:
        raise ValueError(f"task {task_id} is already complete")
    metadata = task["metadata"]
    tier = metadata.get("tier", data["defaultTier"])
    effective = "deep" if escalate else tier
    if provider_name not in data["providers"]:
        raise ValueError(f"unknown provider {provider_name}")
    provider = data["providers"][provider_name]
    selected = model or provider["defaults"][effective]
    if selected not in provider["models"] or TIERS[provider["models"][selected]] < TIERS[effective]:
        raise ValueError(f"model {selected!r} is not configured for {effective} or higher")
    return {"change": change, "task": task_id, "description": task["description"],
            "source": str(path.relative_to(root)), "line": task["line"],
            "provider": provider_name, "model": selected, "tier": effective,
            "declaredTier": tier, "risk": metadata.get("risk"),
            "reason": metadata.get("reason"), "defaulted": not bool(metadata), "escalated": escalate}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("change", nargs="?")
    parser.add_argument("task", nargs="?", help="printed task number, e.g. 4.2 (not OpenSpec ordinal ID)")
    parser.add_argument("--provider", choices=["claude", "codex"], default="claude")
    parser.add_argument("--model", help="explicit configured model of the same or higher tier")
    parser.add_argument("--escalate", action="store_true", help="select deep tier after substantive failures")
    parser.add_argument("--format", choices=["json", "model"], default="json")
    parser.add_argument("--check", action="store_true", help="validate configuration and all active task metadata")
    args = parser.parse_args()
    try:
        if args.check:
            if args.change or args.task or args.model or args.escalate:
                parser.error("--check cannot be combined with task selection")
            config(ROOT)
            for path in sorted((ROOT / "openspec/changes").glob("*/tasks.md")):
                tasks(path)
            print("Task routing configuration and active metadata valid")
        else:
            if not args.change or not args.task:
                parser.error("change and task are required")
            result = select(ROOT, args.change, args.task, args.provider, args.model, args.escalate)
            print(result["model"] if args.format == "model" else json.dumps(result, indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"task routing: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
