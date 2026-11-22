"""Independent spawn-through-exit report. No cross-runner latency thresholds."""

import contextlib
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import time

from release import WATCHDOG, process, stop_reading, workspace


SAMPLES = 128
WARMUP = 8


def invocation(operation, directory, repo):
    binary = directory / "dotagent"
    session = {"session_id": "bench"}
    if operation == "pre-tool":
        return [binary, operation], {**session, "tool_name": "Read",
                                     "tool_input": {"file_path": str(repo / "plain.txt")}}
    if operation == "post-tool":
        return [binary, operation], {**session, "tool_name": "Read", "tool_response": "fixture"}
    if operation == "shell":
        return [directory / "agent-guard-sh", "-c", "printf %s fixture"], None
    if operation == "read-safe":
        return [binary, operation, "plain.txt"], None
    return [binary, "pre-compact"], session


def stats(values):
    values = sorted(values)
    return {key: values[math.ceil(len(values) * p / 100) - 1]
            for key, p in (("p50", 50), ("p95", 95), ("p99", 99), ("max", 100))}


def run(mode, builds):
    with workspace() as (repo, state, env), contextlib.ExitStack() as stack:
        if mode != "absent":
            receiver = stack.enter_context(process(
                [builds["pr"] / "dotagent", "collect-observations", "--owned"], repo, env))
            if mode == "crashed":
                receiver.kill()
                receiver.wait(timeout=WATCHDOG)
            if mode == "saturated":
                stop_reading(receiver)
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
                    sender.setblocking(False)
                    sender.connect(os.path.relpath(state / "observations/in"))
                    for _ in range(16384):
                        try:
                            sender.send(b"benchmark-capacity")
                        except BlockingIOError:
                            break
                    else:
                        raise AssertionError("failed to establish kernel backpressure")
        for operation in ("pre-tool", "post-tool", "shell", "read-safe", "pre-compact"):
            samples = {label: [] for label in builds}
            exits = {label: set() for label in builds}
            for cycle in range(SAMPLES + WARMUP):
                labels = tuple(builds)
                for label in labels if cycle % 2 == 0 else reversed(labels):
                    args, payload = invocation(operation, builds[label], repo)
                    data = json.dumps(payload).encode() if payload is not None else b""
                    # Give each process an independent session and the same guarded repository.
                    session = f"bench-{mode}-{operation}-{cycle}-{label}"
                    if payload is not None:
                        data = json.dumps({**payload, "session_id": session}).encode()
                    run_env = {**env, "AGENT_GUARD_SESSION_ID": session}
                    start = time.perf_counter_ns()
                    child = subprocess.run(args, input=data, cwd=repo, env=run_env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           timeout=WATCHDOG, check=False)
                    elapsed = time.perf_counter_ns() - start
                    if cycle == 0 and label == "pr":
                        diagnostic = (child.stderr + child.stdout).decode("ascii", "replace")
                        codes = sorted(set(re.findall(r"\b[A-Z][A-Z0-9_]{4,}\b", diagnostic)))
                        print("FIXTURE", mode, operation, child.returncode, codes[:8], flush=True)
                    if cycle >= WARMUP:
                        samples[label].append(elapsed)
                        exits[label].add(child.returncode)
            for label in builds:
                print("COLD_NS " + json.dumps({"operation": operation, "collector": mode,
                      "revision": label, "n": SAMPLES, "exit": sorted(exits[label]),
                      **stats(samples[label])}, sort_keys=True), flush=True)


if __name__ == "__main__":
    print("PLATFORM", platform.platform(), platform.machine(), flush=True)
    binaries = {"main": Path(sys.argv[1]).resolve(), "pr": Path(sys.argv[2]).resolve()}
    for condition in ("absent", "available", "crashed", "saturated"):
        run(condition, binaries)
