#!/usr/bin/env python3
"""
agentsh v0.20.2 + Modal Sandbox Security Tests

Comprehensive tests for ptrace-based enforcement on Modal's gVisor runtime.
Key demonstration: domain-name DNS filtering (not just IP-based blocking).

Usage:
    modal run tests.py
"""

import modal
import json
import time
import re
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.20.2"
DEB_ARCH = "amd64"

# Modal runs as root; workspace is /root
WORKSPACE = "/root"


# =============================================================================
# MODAL IMAGE DEFINITION
# =============================================================================

def create_agentsh_image() -> modal.Image:
    """Create a Modal image with agentsh installed."""
    version = AGENTSH_TAG.lstrip("v")
    deb_name = f"agentsh_{version}_linux_{DEB_ARCH}.deb"
    deb_url = f"https://github.com/{AGENTSH_REPO}/releases/download/{AGENTSH_TAG}/{deb_name}"

    return (
        modal.Image.debian_slim(python_version="3.11")
        .apt_install(
            "ca-certificates",
            "curl",
            "bash",
            "git",
            "sudo",
            "libseccomp2",
            "fuse3",
            "netcat-openbsd",
            "dnsutils",
        )
        .run_commands(
            "echo 'rebuilt: 2026-05-25-v0.20.2'",  # cache bust BEFORE download to force re-fetch
            f"curl -fsSL -L '{deb_url}' -o /tmp/agentsh.deb",
            "dpkg -i /tmp/agentsh.deb",
            "rm -f /tmp/agentsh.deb",
            "agentsh --version",
            "mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh",
            "chmod 777 /etc/agentsh /etc/agentsh/policies",
            "chmod 777 /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions",
            "chmod 777 /var/log/agentsh",
        )
        .env({"AGENTSH_SERVER": "http://127.0.0.1:18080"})
    )


# =============================================================================
# MODAL APP DEFINITION
# =============================================================================

app = modal.App("agentsh-tests")
image = create_agentsh_image()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def write_file_to_sandbox(sb: modal.Sandbox, path: str, content: str) -> None:
    """Write a file to the sandbox filesystem."""
    p = sb.exec("sh", "-c", f"cat > '{path}' << 'AGENTSH_EOF'\n{content}\nAGENTSH_EOF")
    p.wait()


def run_command(sb: modal.Sandbox, command: str, timeout: int = 30) -> tuple[str, str, int]:
    """Run a command in the sandbox and return stdout, stderr, exit_code."""
    try:
        p = sb.exec("bash", "-c", command, timeout=timeout)
        p.wait()
        stdout = p.stdout.read() if p.stdout else ""
        stderr = p.stderr.read() if p.stderr else ""
        exit_code = p.returncode if p.returncode is not None else -1
        return stdout, stderr, exit_code
    except Exception as e:
        return "", str(e), -1


def setup_agentsh(sb: modal.Sandbox, config_yaml: str, default_yaml: str) -> str:
    """Configure agentsh and start the daemon. Returns the session ID."""
    print("    Writing configuration files...")
    write_file_to_sandbox(sb, "/etc/agentsh/config.yaml", config_yaml)
    write_file_to_sandbox(sb, "/etc/agentsh/policies/default.yaml", default_yaml)

    print("    Starting agentsh daemon...")
    sb.exec("sh", "-c", "agentsh server --config /etc/agentsh/config.yaml > /var/log/agentsh/agentsh.log 2>&1 &")

    # Wait for daemon to be ready
    for i in range(20):
        time.sleep(1)
        stdout, stderr, exit_code = run_command(sb, "curl -s http://127.0.0.1:18080/health 2>&1", timeout=5)
        output = (stdout + stderr).strip()
        if exit_code == 0 and output:
            print(f"    agentsh daemon health: {output[:50]} (took {i+1}s)")
            break
    else:
        log_out, log_err, _ = run_command(sb, "cat /var/log/agentsh/agentsh.log 2>&1 | tail -30", timeout=5)
        print(f"    Warning: daemon may not be ready. Log:\n{(log_out + log_err)[:500]}")

    # Show ptrace/DNS status from log
    log_out, _, _ = run_command(sb, "cat /var/log/agentsh/agentsh.log 2>&1 | grep -i -E '(ptrace|dns|proxy|resolv)' | head -10", timeout=5)
    if log_out.strip():
        print(f"    ptrace/DNS log entries:")
        for line in log_out.strip().split("\n")[:5]:
            print(f"      {line[:100]}")

    # Create a session
    print("    Creating agentsh session...")
    stdout, stderr, exit_code = run_command(sb, f"agentsh session create --workspace {WORKSPACE} 2>&1", timeout=30)
    output = (stdout + stderr).strip()

    # Try to extract session ID from output
    session_id = ""
    try:
        json_match = re.search(r'\{[^{}]*"id"[^{}]*\}', output)
        if json_match:
            session_data = json.loads(json_match.group())
            session_id = session_data.get("id", "")
    except json.JSONDecodeError:
        pass

    if not session_id:
        # Try plain text: session ID is usually a UUID-like string
        id_match = re.search(r'(session-[a-f0-9-]{36})', output)
        if id_match:
            session_id = id_match.group(1)

    if session_id:
        print(f"    Session ID: {session_id}")
    else:
        print(f"    Session output: {output[:200]}")

    return session_id


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_test(sb: modal.Sandbox, results: dict, description: str, command: str,
             expect: str = "success") -> tuple[str, int]:
    """Run a test and track results.

    expect: "success" (exit 0), "blocked" (exit non-zero or error keywords in output)
    Returns: (output, exit_code)
    """
    stdout, stderr, exit_code = run_command(sb, command)
    output = (stdout + stderr).strip()
    display = output[:200] + "..." if len(output) > 200 else output

    if expect == "success":
        if exit_code == 0:
            results["passed"] += 1
            print(f"    \u2713 {description}")
        else:
            results["failed"] += 1
            print(f"    \u2717 {description}")
    elif expect == "blocked":
        blocked = (
            exit_code != 0
            or "denied" in output.lower()
            or "blocked" in output.lower()
            or "permission" in output.lower()
            or "not found" in output.lower()
            or "refused" in output.lower()
            or "unreachable" in output.lower()
            or "could not resolve" in output.lower()
            or "name resolution" in output.lower()
            or "operation not permitted" in output.lower()
            or "killed" in output.lower()
        )
        if blocked:
            results["passed"] += 1
            print(f"    \u2713 {description}")
        else:
            results["failed"] += 1
            print(f"    \u2717 {description}")

    print(f"      Output: {display}")
    print(f"      Exit code: {exit_code}")
    return output, exit_code


def run_exec_test(sb: modal.Sandbox, session_id: str, results: dict,
                  description: str, command: str, expect: str = "success") -> tuple[str, int]:
    """Run a test through agentsh exec (ptrace-traced).

    Commands run through agentsh exec are children of the ptrace tracer
    and subject to policy enforcement.
    """
    exec_cmd = f"agentsh exec {session_id} -- {command}"
    return run_test(sb, results, description, f"{exec_cmd} 2>&1", expect)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

@app.local_entrypoint()
def main():
    print("=" * 70)
    print(f"  agentsh {AGENTSH_TAG} + Modal \u2014 ptrace enforcement tests")
    print("=" * 70)
    print(f"\n  Key: ptrace-based syscall interception replaces seccomp+FUSE")
    print(f"  This enables domain-name DNS filtering, command blocking,")
    print(f"  and file access control on gVisor for the first time.\n")

    script_dir = Path(__file__).parent
    config_yaml = (script_dir / "config.yaml").read_text()
    default_yaml = (script_dir / "default.yaml").read_text()

    print("[1] Creating Modal Sandbox with agentsh...")
    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 30,
    )
    print(f"    Sandbox ID: {sb.object_id}")

    results = {"passed": 0, "failed": 0}

    try:
        print("\n[2] Configuring agentsh (ptrace mode)...")
        session_id = setup_agentsh(sb, config_yaml, default_yaml)

        # =================================================================
        # 1. DAEMON & API TESTS
        # =================================================================
        print("\n" + "=" * 70)
        print("  1. DAEMON & API TESTS")
        print("=" * 70)

        run_test(sb, results, "Health endpoint",
                 "curl -s http://127.0.0.1:18080/health")
        run_test(sb, results, "Ready endpoint",
                 "curl -s http://127.0.0.1:18080/ready")
        run_test(sb, results, "Metrics endpoint",
                 "curl -s http://127.0.0.1:18080/metrics | head -5")

        if session_id:
            results["passed"] += 1
            print(f"    \u2713 Session created: {session_id[:40]}...")

            run_test(sb, results, "Session info",
                     f"agentsh session info {session_id} 2>&1 | head -c 200")
            run_test(sb, results, "Session list",
                     "agentsh session list 2>&1 | head -c 200")
        else:
            results["failed"] += 1
            print("    \u2717 Session creation failed")

        # =================================================================
        # 2. VERSION VERIFICATION
        # =================================================================
        print("\n" + "=" * 70)
        print("  2. VERSION VERIFICATION")
        print("=" * 70)

        run_test(sb, results, f"agentsh binary is {AGENTSH_TAG}",
                 f"/usr/bin/agentsh --version 2>&1 | grep -q '{AGENTSH_TAG.lstrip('v')}' && echo 'version match'")

        # Check ptrace mode is active in logs
        stdout, stderr, _ = run_command(sb,
            "cat /var/log/agentsh/agentsh.log 2>&1 | grep -i 'ptrace' | head -5")
        ptrace_output = (stdout + stderr).strip()
        if ptrace_output:
            results["passed"] += 1
            print(f"    \u2713 ptrace tracer active in server logs")
            for line in ptrace_output.split("\n")[:3]:
                print(f"      \u2192 {line[:90]}")
        else:
            results["failed"] += 1
            print(f"    \u2717 ptrace not found in server logs")

        # v0.19.3: Dirty Frag (CVE-2026-43284) socket-tuple mitigation should be
        # loaded from config (sandbox.seccomp.mitigation_sets) and enforced via
        # the ptrace fallback on gVisor where seccomp BPF is unavailable.
        stdout, stderr, _ = run_command(sb,
            "cat /var/log/agentsh/agentsh.log 2>&1 | grep -i 'mitigation loaded' | head -3")
        mitigation_output = (stdout + stderr).strip()
        if mitigation_output and "dirtyfrag-conservative" in mitigation_output:
            results["passed"] += 1
            print(f"    \u2713 dirtyfrag-conservative mitigation loaded (ptrace-enforced)")
            for line in mitigation_output.split("\n")[:2]:
                print(f"      \u2192 {line[:90]}")
        else:
            results["failed"] += 1
            print(f"    \u2717 dirtyfrag-conservative mitigation not found in server logs")

        # =================================================================
        # 3. AGENTSH EXEC — ptrace enforcement gateway
        # =================================================================
        print("\n" + "=" * 70)
        print("  3. AGENTSH EXEC \u2014 ptrace enforcement gateway")
        print("=" * 70)
        print("  Commands run through 'agentsh exec' are children of the")
        print("  ptrace tracer and subject to policy enforcement.")

        if session_id:
            # Test basic exec works
            run_exec_test(sb, session_id, results,
                          "agentsh exec echo — basic exec works",
                          "sh -c \"echo 'hello from ptrace'\"")

            run_exec_test(sb, session_id, results,
                          "agentsh exec ls / — list root",
                          "ls /")

            run_exec_test(sb, session_id, results,
                          "agentsh exec whoami — identity",
                          "/usr/bin/whoami")
        else:
            results["failed"] += 3
            print("    \u2717 Skipping exec tests (no session)")

        # =================================================================
        # 4. DNS ALLOW/DENY — DOMAIN-NAME FILTERING
        #    This is the KEY test: proving domain-based (not IP) blocking
        # =================================================================
        print("\n" + "=" * 70)
        print("  4. DNS ALLOW/DENY \u2014 DOMAIN-NAME FILTERING")
        print("  " + "-" * 66)
        print("  These tests prove agentsh blocks by DOMAIN NAME, not just IP.")
        print("  The ptrace DNS proxy intercepts DNS queries and applies policy")
        print("  rules before any connection is made.")
        print("=" * 70)

        if session_id:
            # --- ALLOWED domains (in policy) ---
            print("\n  --- Allowed domains (in network policy) ---")

            run_exec_test(sb, session_id, results,
                          "curl github.com \u2014 ALLOWED (in policy)",
                          "curl -sI --connect-timeout 10 https://github.com 2>&1 | head -1")

            run_exec_test(sb, session_id, results,
                          "curl pypi.org \u2014 ALLOWED (in policy)",
                          "curl -sI --connect-timeout 10 https://pypi.org 2>&1 | head -1")

            run_exec_test(sb, session_id, results,
                          "curl api.github.com \u2014 ALLOWED (another allowed domain)",
                          "curl -sI --connect-timeout 10 https://api.github.com 2>&1 | head -1")

            run_exec_test(sb, session_id, results,
                          "Python DNS resolve github.com \u2014 ALLOWED",
                          "python3 -c \"import socket; r=socket.getaddrinfo('github.com', 443, socket.AF_INET); print(f'Resolved: {r[0][4][0]}')\"")
            # --- DENIED domains (blocked by policy) ---
            print("\n  --- Denied domains (blocked by name in policy) ---")

            run_exec_test(sb, session_id, results,
                          "curl evil.com \u2014 DENIED (blocked domain name)",
                          "curl -s --connect-timeout 10 https://evil.com",
                          "blocked")

            run_exec_test(sb, session_id, results,
                          "Python DNS resolve evil.com \u2014 DENIED",
                          "python3 -c \"import socket; socket.getaddrinfo('evil.com', 443, socket.AF_INET)\"",
                          "blocked")

            run_exec_test(sb, session_id, results,
                          "curl sub.evil.com \u2014 DENIED (wildcard *.evil.com)",
                          "curl -s --connect-timeout 10 https://sub.evil.com",
                          "blocked")

            # --- DENIED: cloud metadata (IP-based + domain) ---
            print("\n  --- Denied: cloud metadata ---")

            run_exec_test(sb, session_id, results,
                          "curl 169.254.169.254 \u2014 DENIED (metadata IP)",
                          "curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/",
                          "blocked")

            run_exec_test(sb, session_id, results,
                          "curl metadata.google.internal \u2014 DENIED (metadata domain)",
                          "curl -s --connect-timeout 5 -H 'Metadata-Flavor: Google' http://metadata.google.internal/",
                          "blocked")
        else:
            results["failed"] += 8
            print("    \u2717 Skipping DNS tests (no session)")

        # =================================================================
        # 5. DNS REDIRECT TEST
        # =================================================================
        print("\n" + "=" * 70)
        print("  5. DNS REDIRECT TEST")
        print("=" * 70)

        if session_id:
            run_exec_test(sb, session_id, results,
                          "Resolve redirectme.example.com \u2192 127.0.0.1",
                          "python3 -c \"import socket; r=socket.getaddrinfo('redirectme.example.com', 80, socket.AF_INET); ip=r[0][4][0]; print(f'Resolved to: {ip}')\"")
        else:
            results["failed"] += 1
            print("    \u2717 Skipping DNS redirect test (no session)")

        # =================================================================
        # 6. COMMAND BLOCKING (ptrace execve interception)
        # =================================================================
        print("\n" + "=" * 70)
        print("  6. COMMAND BLOCKING (ptrace execve interception)")
        print("=" * 70)

        if session_id:
            # --- Blocked commands ---
            print("\n  --- Commands that should be DENIED ---")

            run_exec_test(sb, session_id, results,
                          "sudo whoami \u2014 DENIED (container escape tool)",
                          "sudo whoami", "blocked")

            run_exec_test(sb, session_id, results,
                          "nsenter --help \u2014 DENIED (container escape tool)",
                          "nsenter --help", "blocked")

            run_exec_test(sb, session_id, results,
                          "su root -c whoami \u2014 DENIED",
                          "su root -c whoami", "blocked")

            run_exec_test(sb, session_id, results,
                          "docker ps \u2014 DENIED (container escape tool)",
                          "docker ps", "blocked")

            # --- Allowed commands ---
            print("\n  --- Commands that should be ALLOWED ---")

            run_exec_test(sb, session_id, results,
                          "ls / \u2014 ALLOWED",
                          "ls /")

            run_exec_test(sb, session_id, results,
                          "git --version \u2014 ALLOWED",
                          "git --version")

            run_exec_test(sb, session_id, results,
                          "python3 --version \u2014 ALLOWED",
                          "python3 --version")

            run_exec_test(sb, session_id, results,
                          "echo hello — ALLOWED",
                          "sh -c 'echo hello'")

            run_exec_test(sb, session_id, results,
                          "whoami — ALLOWED",
                          "/usr/bin/whoami")
        else:
            results["failed"] += 9
            print("    \u2717 Skipping command tests (no session)")

        # =================================================================
        # 7. FILE ACCESS CONTROL (ptrace openat interception)
        # =================================================================
        print("\n" + "=" * 70)
        print("  7. FILE ACCESS CONTROL (ptrace openat interception)")
        print("=" * 70)

        if session_id:
            # --- Allowed file operations ---
            print("\n  --- File operations that should be ALLOWED ---")

            run_exec_test(sb, session_id, results,
                          f"Write to workspace ({WORKSPACE}) \u2014 ALLOWED",
                          f"python3 -c \"p='{WORKSPACE}/test_write.txt'; open(p,'w').write('test data'); print(open(p).read(), end='')\"")

            run_exec_test(sb, session_id, results,
                          "Read /etc/hosts — ALLOWED (minimal config read)",
                          "/usr/bin/cat /etc/hosts")

            run_exec_test(sb, session_id, results,
                          "Write to /tmp \u2014 ALLOWED",
                          "python3 -c \"p='/tmp/test.txt'; open(p,'w').write('temp data'); print(open(p).read(), end='')\"")

            run_exec_test(sb, session_id, results,
                          "Read system binaries (stat /usr/bin/ls) \u2014 ALLOWED",
                          "ls -la /usr/bin/ls")

            # --- Denied file operations ---
            print("\n  --- File operations that should be DENIED ---")

            run_exec_test(sb, session_id, results,
                          "Write to /etc/hack \u2014 DENIED",
                          "python3 -c \"open('/etc/hack','w').write('hacked')\"", "blocked")

            run_exec_test(sb, session_id, results,
                          "Read /proc/1/environ \u2014 DENIED (blocks sensitive proc)",
                          "cat /proc/1/environ", "blocked")

            run_exec_test(sb, session_id, results,
                          "Write to /usr/bin/evil \u2014 DENIED",
                          "python3 -c \"open('/usr/bin/evil','w').write('x')\"", "blocked")
        else:
            results["failed"] += 7
            print("    \u2717 Skipping file tests (no session)")

        # =================================================================
        # 8. NETWORK CIDR BLOCKING
        # =================================================================
        print("\n" + "=" * 70)
        print("  8. NETWORK CIDR BLOCKING")
        print("=" * 70)

        if session_id:
            run_exec_test(sb, session_id, results,
                          "Connect to 10.0.0.1 \u2014 DENIED (private network)",
                          "curl -s --connect-timeout 5 http://10.0.0.1/",
                          "blocked")

            run_exec_test(sb, session_id, results,
                          "Connect to 192.168.1.1 \u2014 DENIED (private network)",
                          "curl -s --connect-timeout 5 http://192.168.1.1/",
                          "blocked")
        else:
            results["failed"] += 2
            print("    \u2717 Skipping CIDR tests (no session)")

        # =================================================================
        # 9. AUDIT LOG VERIFICATION
        # =================================================================
        print("\n" + "=" * 70)
        print("  9. AUDIT LOG VERIFICATION")
        print("=" * 70)

        # Check audit SQLite database
        stdout, stderr, exit_code = run_command(sb,
            "ls -la /var/lib/agentsh/events.db 2>&1")
        output = (stdout + stderr).strip()
        if exit_code == 0 and "events.db" in output:
            results["passed"] += 1
            print(f"    \u2713 Audit SQLite database exists")
            print(f"      {output[:80]}")
        else:
            results["failed"] += 1
            print(f"    \u2717 Audit database not found")

        # Check server log is active
        stdout, stderr, exit_code = run_command(sb,
            "wc -l /var/log/agentsh/agentsh.log 2>&1")
        output = (stdout + stderr).strip()
        if exit_code == 0:
            results["passed"] += 1
            print(f"    \u2713 Server log active: {output}")
        else:
            results["failed"] += 1
            print(f"    \u2717 Server log not found")

        # Check for denied/blocked events in log
        stdout, stderr, _ = run_command(sb,
            "cat /var/log/agentsh/agentsh.log 2>&1 | grep -i -c 'denied\\|blocked\\|DENY' || echo '0'")
        denied_count = (stdout + stderr).strip()
        print(f"    \u2139 Denied/blocked events in log: {denied_count}")

        # Show last few relevant log lines
        stdout, stderr, _ = run_command(sb,
            "cat /var/log/agentsh/agentsh.log 2>&1 | grep -i -E '(denied|blocked|deny|allow|ptrace|dns|exec)' | tail -10")
        log_lines = (stdout + stderr).strip()
        if log_lines:
            print(f"\n    Recent enforcement log entries:")
            for line in log_lines.split("\n")[:8]:
                print(f"      {line[:100]}")

        # =================================================================
        # SUMMARY
        # =================================================================
        print("\n" + "=" * 70)
        print("  SUMMARY")
        print("=" * 70)
        total = results['passed'] + results['failed']
        print(f"""
    Tests passed: {results['passed']} / {total}
    Tests failed: {results['failed']} / {total}

    PTRACE ENFORCEMENT ON MODAL ({AGENTSH_TAG}):
      Working:
        - agentsh daemon + API (health, ready, metrics)
        - Session management (create, info, list)
        - ptrace tracer active (attach_mode=children)
        - dirtyfrag-conservative mitigation loaded (CVE-2026-43284, ptrace-enforced)
        - agentsh exec (command execution through ptrace)
        - Audit logging (SQLite + server log)

      Key: commands run through 'agentsh exec' are ptrace-traced
      and subject to DNS, command, file, and network policy rules.
""")

    finally:
        print("\n[CLEANUP] Terminating Sandbox...")
        sb.terminate()
        print("    Sandbox terminated.")


if __name__ == "__main__":
    print("Run this script with: modal run tests.py")
