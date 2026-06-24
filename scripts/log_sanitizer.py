#!/usr/bin/env python3
"""Offline text/log sanitizer with interactive category selection."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Callable

PATTERNS: dict[str, str] = {
    "url": r"https?://[^\s\"'<>]+",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "windows_user": r"\b[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+\b",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "mac": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b",
    "domain": r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|uk|local|internal|corp|cloud|dev|app|be|tr|eu)\b",
    "hostname": r"\b(?:DESKTOP|LAPTOP|SRV|SERVER|DC|WIN|PC|HOST)-[A-Za-z0-9-]+\b",
    "guid": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "hash": r"\b[a-fA-F0-9]{32,64}\b",
}

FAKES: dict[str, Callable[[int], str]] = {
    "url": lambda i: f"https://example{i}.com/path",
    "email": lambda i: f"john.smith{i}@example.com",
    "windows_user": lambda i: f"DOMAIN\\john.smith{i}",
    "ipv4": lambda i: f"10.10.{i // 254}.{i % 254 + 1}",
    "ipv6": lambda i: f"fd00::{i}",
    "domain": lambda i: f"example{i}.com",
    "hostname": lambda i: f"HOST-{i:04d}",
    "mac": lambda i: f"00:11:22:33:44:{i % 255:02x}",
    "guid": lambda i: f"00000000-0000-0000-0000-{i:012d}",
    "hash": lambda i: f"{i:064x}",
}


def detect(text: str) -> dict[str, list[str]]:
    """Return unique findings grouped by sensitive-value category."""
    findings: defaultdict[str, set[str]] = defaultdict(set)

    for category, pattern in PATTERNS.items():
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            findings[category].add(match)

    return {category: sorted(values) for category, values in findings.items() if values}


def ask_categories(findings: dict[str, list[str]]) -> set[str]:
    """Prompt the user for the finding categories that should be randomized."""
    selected: set[str] = set()
    print("\nDetected potentially sensitive values:\n")

    for category, values in findings.items():
        examples = ", ".join(values[:5])
        print(f"[{category}] {len(values)} unique value(s)")
        print(f"  Examples: {examples}")

        answer = input(f"Randomize {category}? [y/N]: ").strip().lower()
        if answer in {"y", "yes"}:
            selected.add(category)

        print()

    return selected


def build_mapping(findings: dict[str, list[str]], selected: set[str]) -> dict[str, str]:
    """Build stable replacements, replacing longer source strings first."""
    mapping: dict[str, str] = {}

    for category in PATTERNS:
        if category not in selected:
            continue
        for index, value in enumerate(findings.get(category, []), start=1):
            mapping.setdefault(value, FAKES[category](index))

    return dict(sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True))


def sanitize(text: str, mapping: dict[str, str]) -> str:
    """Apply exact stable replacements to the original text."""
    for real_value, fake_value in mapping.items():
        text = text.replace(real_value, fake_value)
    return text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline log/text sanitizer")
    parser.add_argument("input", help="Input log/txt file")
    parser.add_argument("-o", "--output", help="Output sanitized file")
    parser.add_argument("--save-map", action="store_true", help="Save replacement map as JSON")
    parser.add_argument(
        "--categories",
        help="Comma-separated categories to sanitize without prompting, or 'all' for every detected category",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix(input_path.suffix + ".sanitized.txt")

    text = input_path.read_text(errors="ignore", encoding="utf-8")
    findings = detect(text)

    if not findings:
        print("No obvious sensitive values detected.")
        return

    if args.categories:
        selected = set(findings) if args.categories.lower() == "all" else {item.strip() for item in args.categories.split(",")}
        selected &= set(findings)
    else:
        selected = ask_categories(findings)

    if not selected:
        print("No categories selected. Nothing changed.")
        return

    mapping = build_mapping(findings, selected)
    output_path.write_text(sanitize(text, mapping), encoding="utf-8")
    print(f"\nSanitized file written to: {output_path}")

    if args.save_map:
        map_path = output_path.with_suffix(output_path.suffix + ".map.json")
        map_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        print(f"Replacement map written to: {map_path}")


if __name__ == "__main__":
    main()
