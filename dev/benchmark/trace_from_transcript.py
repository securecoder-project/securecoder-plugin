#!/usr/bin/env python3
"""Rebuild a SecureCoder trace log from a Claude Code transcript.

`SECURECODER_TRACE_LOG` has to be set *before* a session starts (see
DEVELOPMENT.md). When it wasn't, the tool calls and their results are still
recorded in the Claude Code transcript, so a trace can be recovered after the
fact. Every record is tagged `"reconstructed": true` to keep it distinguishable
from one the MCP server wrote itself.

Recovered per tool, matching mcp-server/index.js traceLog():
  securecoder_analyze        ts, tool, session, files, deep, result
  securecoder_enrich_prompt  ts, tool, prompt, hints, enriched
  securecoder_reset_session  ts, tool, session

Usage:
  python3 dev/benchmark/trace_from_transcript.py \
      --transcript ~/.claude/projects/<slug>/<uuid>.jsonl \
      --out traces/session.jsonl
"""

import argparse
import json
from pathlib import Path

PREFIX = "mcp__plugin_securecoder_securecoder-analysis__"


def load_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def result_text(content) -> str:
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return str(content)


def parse_enrich(text: str) -> tuple[list[str], str]:
    """Split the enrich_prompt response back into (hints, enriched)."""
    hints: list[str] = []
    head, _, tail = text.partition("\n\nEnriched prompt:\n")
    for line in head.splitlines():
        if line.startswith("- "):
            hints.append(line[2:])
    return hints, tail


def collect(lines: list[dict]) -> list[dict]:
    """Pair each securecoder tool_use with the tool_result that follows it."""
    calls: dict[str, dict] = {}
    order: list[str] = []

    for entry in lines:
        msg = entry.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and block.get("name", "").startswith(PREFIX):
                calls[block["id"]] = {
                    "ts": entry.get("timestamp"),
                    "tool": block["name"][len(PREFIX):],
                    "input": block.get("input") or {},
                    "text": None,
                }
                order.append(block["id"])
            elif block.get("type") == "tool_result" and block.get("tool_use_id") in calls:
                calls[block["tool_use_id"]]["text"] = result_text(block.get("content"))

    records = []
    for call_id in order:
        call = calls[call_id]
        tool, args, text = call["tool"], call["input"], call["text"] or ""
        rec = {"ts": call["ts"], "tool": tool, "reconstructed": True}

        if tool == "securecoder_analyze":
            # The server's own schema calls this `session`; a client that sent
            # `session_id` instead got no retry tracking, so record what was
            # actually sent rather than normalizing it away.
            rec["session"] = args.get("session") or args.get("session_id")
            rec["files"] = args.get("files", [])
            rec["deep"] = args.get("deep") is True
            try:
                rec["result"] = json.loads(text)
            except json.JSONDecodeError:
                rec["result"] = {"unparsed_text": text}
        elif tool == "securecoder_enrich_prompt":
            hints, enriched = parse_enrich(text)
            rec["prompt"] = args.get("prompt", "")
            rec["hints"] = hints
            rec["enriched"] = enriched
        elif tool == "securecoder_reset_session":
            rec["session"] = args.get("session") or args.get("session_id")
        else:
            rec["input"] = args
            rec["text"] = text

        records.append(rec)

    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    records = collect(load_jsonl(args.transcript.expanduser()))
    if not records:
        raise SystemExit(f"no securecoder tool calls found in {args.transcript}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    counts: dict[str, int] = {}
    for rec in records:
        counts[rec["tool"]] = counts.get(rec["tool"], 0) + 1
    print(f"Wrote {len(records)} records to {args.out}")
    for tool, n in sorted(counts.items()):
        print(f"  {tool}: {n}")


if __name__ == "__main__":
    main()
