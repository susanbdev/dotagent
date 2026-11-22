"""Exercise the shipped CLI and a separately built panic=abort fixture on private test state."""

import contextlib
import json
import hashlib
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
WATCHDOG = 10


def until(check):
    deadline = time.monotonic() + WATCHDOG
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        os.sched_yield()
    raise AssertionError("watchdog expired while awaiting " + check.__qualname__)


def line(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        assert selector.select(WATCHDOG), "subprocess response exceeded watchdog"
    raw = child.stdout.readline()
    assert raw, f"unexpected EOF from {child.args}, status={child.poll()}"
    return raw.decode("ascii").strip()


def ask(child, request):
    child.stdin.write(request.encode("ascii") + b"\n")
    child.stdin.flush()
    return line(child)


@contextlib.contextmanager
def workspace():
    parent = ROOT / "target/test-workspaces"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="obs-", dir=parent) as name:
        base = Path(name)
        repo = base / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / "plain.txt").write_text("ordinary fixture text\n")
        state = base / "state"
        state.mkdir(mode=0o700)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("AGENT_GUARD_", "DOTAGENT_"))}
        env["AGENT_GUARD_STATE_DIR"] = str(state)
        yield repo, state, env


def limit_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


@contextlib.contextmanager
def process(args, repo, env, ready=True):
    child = subprocess.Popen(args, cwd=repo, env=env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, bufsize=0, preexec_fn=limit_core)
    try:
        if ready:
            assert line(child) == "READY"
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=WATCHDOG)
        child.stdin.close()
        child.stdout.close()


def health(state):
    path = state / "observations/health"
    return json.loads(path.read_bytes()) if path.is_file() else {}


def observed(state):
    path = state / "audit.jsonl"
    if not path.is_file():
        return []
    data = path.read_bytes()
    return [json.loads(row) for row in data.split(b"\n")[:-1] if row]


def submitted(producer):
    result = ask(producer, "observe")
    return result[9:] if result.startswith("ACCEPTED ") else None


def assert_authority(producer):
    assert ask(producer, "guard") == "GUARD true true true true"
    assert producer.poll() is None


def stop_reading(child):
    os.kill(child.pid, signal.SIGSTOP)
    pid, status = os.waitpid(child.pid, os.WUNTRACED)
    assert pid == child.pid and os.WIFSTOPPED(status)


def exercise(mode, bins):
    cli = bins / "dotagent"
    probe = bins / "examples/observation-probe"
    with workspace() as (repo, state, env), contextlib.ExitStack() as stack:
        spawn = lambda argv: stack.enter_context(process(argv, repo, env))
        producer = spawn([probe, "producer"])
        if mode == "absent":
            assert ask(producer, "observe") == "Unavailable"
            assert_authority(producer)
            assert not (state / "observations").exists()
            return
        injected = mode in {"panic", "exit-handoff", "enospc", "permission", "blocked-store"}
        receiver = spawn([probe, mode] if injected else [cli, "collect-observations", "--owned"])
        if mode in {"panic", "exit-handoff"}:
            accepted = submitted(producer)
            assert accepted
            expected = -signal.SIGABRT if mode == "panic" else 73
            assert receiver.wait(timeout=WATCHDOG) == expected
            assert ask(producer, "observe") == "Unavailable"
            assert all(row.get("event_id") != accepted for row in observed(state))
        elif mode in {"kill", "stale", "restart"}:
            previous = submitted(producer)
            assert previous
            until(lambda: any(row.get("event_id") == previous for row in observed(state)))
            receiver.kill()
            receiver.wait(timeout=WATCHDOG)
            assert (state / "observations/in").is_socket()
            if mode == "stale":
                producer = spawn([probe, "producer"])
            assert ask(producer, "observe") == "Unavailable"
            if mode == "restart":
                spawn([cli, "collect-observations", "--owned"])
                second = until(lambda: submitted(producer))
                assert second != previous
                try:
                    until(lambda: any(row.get("event_id") == second for row in observed(state)))
                except AssertionError:
                    print("restart handoff", second, "collector counters", health(state), flush=True)
                    raise
                ids = [r.get("event_id") for r in observed(state)]
                assert ids.count(previous) == ids.count(second) == 1
        elif mode in {"permission", "enospc"}:
            accepted = submitted(producer)
            assert accepted
            until(lambda: health(state).get("audit_queue", {}).get("failed", 0) > 0)
            assert health(state)["audit_queue"]["persisted"] == 0
            assert all(r.get("event_id") != accepted for r in observed(state))
        elif mode == "stopped":
            stop_reading(receiver)
            until(lambda: ask(producer, "observe") == "Full")
        elif mode == "blocked-store":
            assert submitted(producer)
            assert line(receiver) == "STALLED"
            def saturated():
                for _ in range(16):
                    ask(producer, "observe")
                return health(state).get("audit_queue", {}).get("full", 0)
            until(saturated)
            assert health(state)["audit_queue"]["persisted"] == 0
        elif mode == "healthy":
            event = submitted(producer)
            assert event
            until(lambda: any(r.get("event_id") == event for r in observed(state)))
        assert_authority(producer)
        ids = [r["event_id"] for r in observed(state) if "event_id" in r]
        assert len(ids) == len(set(ids))
        if mode == "blocked-store":
            receiver.stdin.write(b"x")
            receiver.stdin.flush()
            until(lambda: health(state).get("audit_queue", {}).get("persisted", 0) > 0)
        if mode == "healthy":
            receiver.stdin.close()
            assert receiver.wait(timeout=WATCHDOG) == 0
            assert health(state)["phase"] == "closing"
            assert not (state / "observations/in").exists()


def shipped_host(bins):
    with workspace() as (repo, state, env), process(
            [bins / "dotagent", "hook-daemon", "--idle-secs", "30"], repo, env, ready=False) as host:
        address = state / "daemon/hook.sock"
        until(address.is_socket)
        def rpc(payload):
            request = {"op": "eval_hook", "phase": "post-tool", "repo_root": str(repo),
                       "cwd": str(repo), "payload": json.dumps(payload)}
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(WATCHDOG)
                client.connect(os.path.relpath(address))
                client.sendall(json.dumps(request).encode() + b"\n")
                return json.loads(client.makefile("rb").readline())
        until((state / "observations/route").is_file)
        allow = {"tool_name": "Read", "tool_response": "unique_private_fixture_output"}
        deny = {"tool_name": "Task", "tool_response": "ordinary detail " * 100}
        assert rpc(allow)["allow"] is True
        assert rpc(deny)["code"] == "SUBAGENT_RETURN_BUDGET_EXCEEDED"
        until(lambda: any(r.get("event_type") == "USAGE_AND_DISPOSITION" for r in observed(state)))
        assert b"unique_private_fixture_output" not in (state / "audit.jsonl").read_bytes()
        assert host.poll() is None
        first_pid = until(lambda: health(state).get("collector_pid"))
        os.kill(first_pid, signal.SIGKILL)
        def replacement():
            pid = health(state).get("collector_pid")
            return pid and pid != first_pid
        until(replacement)
        assert rpc(allow)["allow"] is True
        assert rpc(deny)["code"] == "SUBAGENT_RETURN_BUDGET_EXCEEDED"
        assert host.poll() is None


if __name__ == "__main__":
    binaries = Path(sys.argv[1]).resolve()
    for scenario in ("healthy", "absent", "panic", "kill", "exit-handoff", "stale",
                     "stopped", "blocked-store", "permission", "enospc", "restart"):
        exercise(scenario, binaries)
        print("PASS", scenario, flush=True)
    shipped_host(binaries)
    print("PASS production hook daemon and automatic collector", flush=True)
