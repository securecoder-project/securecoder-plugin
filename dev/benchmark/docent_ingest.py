#!/usr/bin/env python3
"""Convert one `claude -p` run into a Docent AgentRun and upload it.

Pairs two inputs produced by a single benchmark task:
  - a Claude Code session transcript (~/.claude/projects/<slug>/<uuid>.jsonl)
  - a SecureCoder trace log (see SECURECODER_TRACE_LOG in DEVELOPMENT.md)

Usage:
  .venv/bin/python dev/benchmark/docent_ingest.py \
      --transcript ~/.claude/projects/.../<uuid>.jsonl \
      --trace /path/to/task-001.trace.jsonl \
      --task-id demo-task-001 \
      --variant securecoder \
      --collection securecoder-docent-demo
"""

import argparse
import json
import os
from pathlib import Path

from docent import Docent
from docent.data_models import AgentRun, Transcript
from docent.data_models.chat import AssistantMessage, ToolCall, ToolMessage, UserMessage


def load_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def tool_result_text(content) -> str:
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return str(content)


def convert_transcript(raw_lines: list[dict]) -> list:
    """Claude Code JSONL -> Docent ChatMessage list.

    Claude Code nests tool calls inside assistant.content ({"type":"tool_use"})
    and their results inside the *next* user message's content
    ({"type":"tool_result"}) — Docent instead wants ToolCall on the
    AssistantMessage and a separate role="tool" ToolMessage, so both get
    reshaped here. tool_use_id -> function name is tracked across the loop
    since tool_result blocks don't carry the name themselves.
    """
    messages = []
    tool_name_by_id: dict[str, str] = {}

    for d in raw_lines:
        if d.get("type") not in ("user", "assistant"):
            continue
        msg = d.get("message") or {}
        role = msg.get("role")
        content = msg.get("content")

        if role == "user":
            if isinstance(content, str):
                messages.append(UserMessage(content=content))
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        call_id = block.get("tool_use_id")
                        messages.append(ToolMessage(
                            content=tool_result_text(block.get("content")),
                            tool_call_id=call_id,
                            function=tool_name_by_id.get(call_id),
                        ))
                    elif block.get("type") == "text":
                        messages.append(UserMessage(content=block.get("text", "")))

        elif role == "assistant":
            text_parts = []
            tool_calls = []
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    tool_name_by_id[block["id"]] = block.get("name", "")
                    tool_calls.append(ToolCall(
                        id=block["id"],
                        function=block.get("name", ""),
                        arguments=block.get("input") or {},
                        type="function",
                    ))
            if isinstance(content, str):
                text_parts.append(content)
            messages.append(AssistantMessage(
                content="\n".join(text_parts),
                tool_calls=tool_calls or None,
                model=msg.get("model"),
            ))

    return messages


def scores_from_trace(trace: list[dict]) -> dict:
    """Final-state security metrics, from the last securecoder_analyze record."""
    analyze_records = [r for r in trace if r.get("tool") == "securecoder_analyze"]
    if not analyze_records:
        return {"analyzed": False}
    last = analyze_records[-1]["result"]
    retry = last.get("retry") or {}
    return {
        "analyzed": True,
        "final_verdict": retry.get("verdict"),
        "attempts": retry.get("attempt"),
        "violations_final": len(last.get("violations", [])),
        "analyzers_run": last.get("analyzersRun", []),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", required=True, type=Path)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--variant", default="securecoder")
    ap.add_argument("--collection", default="securecoder-docent-demo")
    args = ap.parse_args()

    api_key = os.environ.get("DOCENT_API_KEY")
    if not api_key:
        raise SystemExit("DOCENT_API_KEY not set (export it, or run with `set -a; source .env; set +a` first)")

    raw_transcript = load_jsonl(args.transcript)
    trace = load_jsonl(args.trace)

    messages = convert_transcript(raw_transcript)
    transcript = Transcript(messages=messages, metadata={"source_file": str(args.transcript)})

    agent_run = AgentRun(
        transcripts=[transcript],
        metadata={
            "task_id": args.task_id,
            "variant": args.variant,
            "scores": scores_from_trace(trace),
            "trace_log": trace,
        },
    )

    client = Docent(api_key=api_key)
    collection_id = client.create_collection(name=args.collection, description="SecureCoder plugin benchmark trajectories")
    client.add_agent_runs(collection_id, [agent_run])

    print(f"Uploaded 1 agent run ({len(messages)} messages) to collection {collection_id}")
    print(f"https://docent.transluce.org/dashboard/{collection_id}")


if __name__ == "__main__":
    main()
