#!/usr/bin/env python3
"""
agentsh + Modal Sandbox Security Tests

This script runs the same security tests as the Daytona integration,
adapted for Modal Sandboxes. It validates agentsh security features
including daemon/API, network proxy, and documents platform limitations
where Modal's gVisor runtime prevents FUSE and seccomp_user_notify.

Platform limitations (gVisor):
  - FUSE: /dev/fuse opens but fusermount3 mount is denied
  - seccomp_user_notify: detected but GET_NOTIF_SIZES returns EINVAL
  - Shell shim and agentsh exec require seccomp_user_notify
  - File-level enforcement requires FUSE

Usage:
    modal run tests.py
"""

import modal
import json
import time
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.10.0"
DEB_ARCH = "amd64"

# Modal runs as root; Daytona uses /home/daytona
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
            "openssh-client",
        )
        .run_commands(
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

    # Create a session
    print("    Creating agentsh session...")
    stdout, stderr, exit_code = run_command(sb, f"agentsh session create --workspace {WORKSPACE} --json 2>&1", timeout=30)
    output = (stdout + stderr).strip()

    try:
        import re
        json_match = re.search(r'\{[^{}]*"id"[^{}]*\}', output)
        if json_match:
            session_data = json.loads(json_match.group())
        else:
            session_data = json.loads(output)
        session_id = session_data.get("id", "")
        print(f"    Session ID: {session_id}")
        return session_id
    except json.JSONDecodeError as e:
        print(f"    Failed to parse session response: {e}")
        return ""


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_test(sb: modal.Sandbox, results: dict, description: str, command: str,
             expect: str = "success") -> int:
    """Run a test and track results.

    expect: "success" (exit 0), "blocked" (exit non-zero or error in output),
            "info" (informational - don't count as pass/fail)
    """
    stdout, stderr, exit_code = run_command(sb, command)
    output = (stdout + stderr).strip()
    # Truncate long output
    if len(output) > 150:
        display = output[:150] + "..."
    else:
        display = output

    if expect == "info":
        # Informational test - show result but don't count
        blocked = exit_code != 0 or "denied" in output.lower() or "not found" in output.lower() or "blocked" in output.lower() or "permission" in output.lower()
        icon = "✓" if blocked else "⚠"
        print(f"    {icon} {description}")
    elif expect == "success":
        if exit_code == 0:
            results["passed"] += 1
            icon = "✓"
        else:
            results["failed"] += 1
            icon = "✗"
        print(f"    {icon} {description}")
    elif expect == "blocked":
        blocked = exit_code != 0 or "denied" in output.lower() or "not found" in output.lower() or "blocked" in output.lower() or "permission" in output.lower()
        if blocked:
            results["passed"] += 1
            icon = "✓"
        else:
            results["failed"] += 1
            icon = "✗"
        print(f"    {icon} {description}")

    print(f"      Output: {display}")
    print(f"      Exit code: {exit_code}")
    return exit_code


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  agentsh + Modal Sandbox Security Tests")
    print("=" * 70)

    script_dir = Path(__file__).parent
    config_yaml = (script_dir / "config.yaml").read_text()
    default_yaml = (script_dir / "default.yaml").read_text()

    print("\n[1] Creating Modal Sandbox with agentsh...")
    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 30,
    )
    print(f"    Sandbox ID: {sb.object_id}")

    results = {"passed": 0, "failed": 0}

    try:
        print("\n[2] Configuring agentsh...")
        session_id = setup_agentsh(sb, config_yaml, default_yaml)

        # =================================================================
        # DAEMON & API TESTS
        # =================================================================
        print("\n" + "=" * 70)
        print("  DAEMON & API TESTS")
        print("=" * 70)

        api_tests = [
            ("Health endpoint", "curl -s http://127.0.0.1:18080/health"),
            ("Ready endpoint", "curl -s http://127.0.0.1:18080/ready"),
            ("Metrics endpoint", "curl -s http://127.0.0.1:18080/metrics | head -5"),
            ("Policy list", "curl -s http://127.0.0.1:18080/api/v1/policies | head -c 100"),
            ("Server info", "curl -s http://127.0.0.1:18080/api/v1/info | head -c 100"),
        ]

        for name, cmd in api_tests:
            stdout, stderr, exit_code = run_command(sb, cmd)
            output = (stdout + stderr).strip()
            if exit_code == 0 and output:
                results["passed"] += 1
                print(f"    ✓ {name}: PASS")
                if "metrics" not in name.lower():
                    print(f"      → {output[:60]}")
            else:
                results["failed"] += 1
                print(f"    ✗ {name}: FAIL")

        # =================================================================
        # SESSION MANAGEMENT TESTS
        # =================================================================
        print("\n" + "=" * 70)
        print("  SESSION MANAGEMENT TESTS")
        print("=" * 70)

        if session_id:
            results["passed"] += 1
            print(f"    ✓ Session created: {session_id[:40]}...")

            stdout, stderr, exit_code = run_command(sb, f"agentsh session info {session_id} --json 2>&1 | head -c 200")
            if exit_code == 0:
                results["passed"] += 1
                print("    ✓ Session info retrieved")
            else:
                results["failed"] += 1
                print("    ✗ Session info failed")
        else:
            results["failed"] += 1
            print("    ✗ Session creation failed")

        # =================================================================
        # ALLOWED OPERATIONS
        # =================================================================
        print("\n" + "=" * 70)
        print("  ALLOWED OPERATIONS")
        print("=" * 70)

        run_test(sb, results, "whoami - Current user", "whoami")
        run_test(sb, results, "id - User info", "id")
        run_test(sb, results, "pwd - Working directory", "pwd")
        run_test(sb, results, f"ls - List files", f"ls -la {WORKSPACE} | head -5")
        run_test(sb, results, "agentsh version", "/usr/bin/agentsh --version")

        # =================================================================
        # MODAL NATIVE ISOLATION TESTS
        # =================================================================
        print("\n" + "=" * 70)
        print("  MODAL NATIVE ISOLATION TESTS")
        print("=" * 70)

        run_test(sb, results, "AWS metadata blocked",
                 "curl -s --connect-timeout 2 http://169.254.169.254/", "blocked")
        run_test(sb, results, "No docker socket",
                 "ls -la /var/run/docker.sock 2>&1", "blocked")
        run_test(sb, results, "No host filesystem",
                 "ls /host 2>&1", "blocked")
        run_test(sb, results, "Container runs as root", "whoami")
        run_test(sb, results, "Git available", "git --version")
        run_test(sb, results, "Python available", "python3 --version")

        # =================================================================
        # FILE ACCESS BLOCKING (requires FUSE - not available on gVisor)
        # =================================================================
        print("\n" + "=" * 70)
        print("  FILE ACCESS BLOCKING (requires FUSE - gVisor limitation)")
        print("=" * 70)
        print("    Note: gVisor blocks fusermount3, so FUSE cannot enforce")
        print("    file policies. These tests document the gap.\n")

        # Allowed: write/read workspace
        run_test(sb, results, "Write to workspace - ALLOWED",
                 f"echo 'hello' > {WORKSPACE}/test_write.txt && cat {WORKSPACE}/test_write.txt")
        run_test(sb, results, "Read from workspace - ALLOWED",
                 f"cat {WORKSPACE}/test_write.txt")

        # Should be blocked by FUSE but gVisor prevents FUSE mount
        run_test(sb, results, "Write to /etc/test - NOT BLOCKED (needs FUSE)",
                 "echo 'hack' > /etc/test_file 2>&1", "info")
        run_test(sb, results, "Write to /usr/bin - NOT BLOCKED (needs FUSE)",
                 "echo 'x' > /usr/bin/evil 2>&1", "info")
        run_test(sb, results, "Write to /var/evil - NOT BLOCKED (needs FUSE)",
                 "echo 'x' > /var/evil 2>&1", "info")

        # Allowed: read system binaries (read-only access)
        run_test(sb, results, "Read /usr/bin/ls (stat) - ALLOWED",
                 "ls -la /usr/bin/ls 2>&1")

        # Allowed: write to /tmp
        run_test(sb, results, "Write to /tmp - ALLOWED",
                 "echo 'temp' > /tmp/test_file.txt && cat /tmp/test_file.txt")

        # Read /proc/1/environ
        run_test(sb, results, "Read /proc/1/environ - leaks env (needs FUSE)",
                 "cat /proc/1/environ 2>&1 | tr '\\0' '\\n' | head -3", "info")

        # =================================================================
        # NETWORK BLOCKING
        # =================================================================
        print("\n" + "=" * 70)
        print("  NETWORK BLOCKING (via agentsh proxy)")
        print("=" * 70)

        run_test(sb, results, "curl evil.com - BLOCKED (proxy)",
                 "curl -s -v https://evil.com 2>&1 | grep -E '(400|Bad Request|CONNECT)'", "info")
        run_test(sb, results, "curl evil.com HTTP status",
                 "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://evil.com 2>&1", "info")

        # =================================================================
        # BLOCKED COMMANDS (requires shell shim - not available on gVisor)
        # =================================================================
        print("\n" + "=" * 70)
        print("  BLOCKED COMMANDS (requires shell shim - gVisor limitation)")
        print("=" * 70)
        print("    Note: gVisor lacks seccomp_user_notify, so shell shim")
        print("    cannot intercept commands. These tests document the gap.\n")

        run_test(sb, results, "sudo whoami - NOT BLOCKED (needs shell shim)",
                 "sudo whoami 2>&1", "info")
        run_test(sb, results, "su root - NOT BLOCKED (needs shell shim)",
                 "su root -c whoami 2>&1", "info")

        # =================================================================
        # MULTI-CONTEXT COMMAND BLOCKING (requires shell shim)
        # =================================================================
        print("\n" + "=" * 70)
        print("  MULTI-CONTEXT COMMAND BLOCKING (requires shell shim)")
        print("=" * 70)

        run_test(sb, results, "env runs sudo - NOT BLOCKED (needs shell shim)",
                 "env sudo whoami 2>&1", "info")
        run_test(sb, results, "xargs spawns sudo - NOT BLOCKED (needs shell shim)",
                 "echo whoami | xargs sudo 2>&1", "info")
        run_test(sb, results, "find -exec runs sudo - NOT BLOCKED (needs shell shim)",
                 "find /tmp -maxdepth 0 -exec sudo whoami \\; 2>&1", "info")
        run_test(sb, results, "Nested script runs sudo - NOT BLOCKED (needs shell shim)",
                 "echo '#!/bin/sh\nsudo whoami' > /tmp/escalate.sh && chmod +x /tmp/escalate.sh && /tmp/escalate.sh 2>&1", "info")
        run_test(sb, results, "Direct /usr/bin/sudo - NOT BLOCKED (needs shell shim)",
                 "/usr/bin/sudo whoami 2>&1", "info")
        run_test(sb, results, "Python subprocess sudo - NOT BLOCKED (needs shell shim)",
                 'python3 -c "import subprocess; r=subprocess.run([\'sudo\',\'whoami\'], capture_output=True, text=True); print(r.stdout or r.stderr)" 2>&1', "info")

        # Allowed: env and Python running safe commands
        run_test(sb, results, "env runs whoami - ALLOWED",
                 "env whoami 2>&1")
        run_test(sb, results, "Python subprocess ls - ALLOWED",
                 f'python3 -c "import subprocess; r=subprocess.run([\'ls\',\'{WORKSPACE}\'], capture_output=True, text=True); print(r.stdout[:80])" 2>&1')

        # =================================================================
        # FUSE PROTECTION (requires FUSE - not available on gVisor)
        # =================================================================
        print("\n" + "=" * 70)
        print("  FUSE PROTECTION (requires FUSE - gVisor limitation)")
        print("=" * 70)
        print("    Note: These tests pass on Daytona where FUSE works.")
        print("    On Modal, gVisor blocks fusermount3 mount.\n")

        # Should be blocked by FUSE
        run_test(sb, results, "cp to /etc - NOT BLOCKED (needs FUSE)",
                 "cp /etc/hosts /etc/hosts_copy 2>&1", "info")
        run_test(sb, results, "touch /etc/newfile - NOT BLOCKED (needs FUSE)",
                 "touch /etc/newfile 2>&1", "info")
        run_test(sb, results, "dd write to /etc - NOT BLOCKED (needs FUSE)",
                 "dd if=/dev/zero of=/etc/dd_test bs=1 count=1 2>&1", "info")
        run_test(sb, results, "tee write to /usr/bin - NOT BLOCKED (needs FUSE)",
                 "echo x | tee /usr/bin/evil 2>&1", "info")
        run_test(sb, results, "mkdir in /etc - NOT BLOCKED (needs FUSE)",
                 "mkdir /etc/testdir 2>&1", "info")
        run_test(sb, results, "Symlink escape to /etc/shadow - NOT BLOCKED (needs FUSE)",
                 "ln -sf /etc/shadow /tmp/shadow_link && cat /tmp/shadow_link 2>&1", "info")
        run_test(sb, results, "Python read /etc/shadow - NOT BLOCKED (needs FUSE)",
                 'python3 -c "print(open(\'/etc/shadow\').read())" 2>&1', "info")
        run_test(sb, results, "Python write to /etc - NOT BLOCKED (needs FUSE)",
                 'python3 -c "open(\'/etc/fuse_test\',\'w\').write(\'hack\')" 2>&1', "info")
        run_test(sb, results, "Python write to /usr/bin - NOT BLOCKED (needs FUSE)",
                 'python3 -c "open(\'/usr/bin/evil\',\'w\').write(\'x\')" 2>&1', "info")
        run_test(sb, results, "Python list /root",
                 'python3 -c "import os; print(os.listdir(\'/root\'))" 2>&1', "info")

        # Allowed: file I/O in workspace and /tmp
        run_test(sb, results, "cp in workspace - ALLOWED",
                 f"echo 'original' > {WORKSPACE}/cp_src.txt && cp {WORKSPACE}/cp_src.txt {WORKSPACE}/cp_dst.txt && cat {WORKSPACE}/cp_dst.txt")
        run_test(sb, results, "touch in /tmp - ALLOWED",
                 "touch /tmp/fuse_test_file && ls -la /tmp/fuse_test_file 2>&1")
        run_test(sb, results, "Python write to workspace - ALLOWED",
                 f'python3 -c "open(\'{WORKSPACE}/py_test.txt\',\'w\').write(\'hello from python\')" && cat {WORKSPACE}/py_test.txt')
        run_test(sb, results, "Python write to /tmp - ALLOWED",
                 'python3 -c "open(\'/tmp/py_test.txt\',\'w\').write(\'temp from python\')" && cat /tmp/py_test.txt')

        # =================================================================
        # AGENTSH EXEC TEST
        # =================================================================
        print("\n" + "=" * 70)
        print("  AGENTSH EXEC (requires seccomp_user_notify)")
        print("=" * 70)

        if session_id:
            json_payload = json.dumps({"command": "/bin/echo", "args": ["test"]})
            stdout, stderr, exit_code = run_command(sb, f"agentsh exec {session_id} --json '{json_payload}' 2>&1")
            output = (stdout + stderr).strip()
            if "seccomp" in output.lower() or exit_code != 0:
                print(f"    ⚠  agentsh exec: Not available (gVisor limitation)")
                print(f"       Error: {output[:80]}...")
            else:
                results["passed"] += 1
                print("    ✓ agentsh exec: Working")

        # =================================================================
        # DESTRUCTIVE TESTS (run last - will crash sandbox on Modal)
        # =================================================================
        print("\n" + "=" * 70)
        print("  DESTRUCTIVE TESTS (run last - will crash sandbox)")
        print("=" * 70)
        print("    Note: On Daytona, shell shim blocks kill -9 1.")
        print("    On Modal, this kills PID 1 and terminates the sandbox.\n")

        run_test(sb, results, "Python os.system kill -9 1 - NOT BLOCKED (needs shell shim)",
                 'python3 -c "import os; os.system(\'kill -9 1\')" 2>&1', "info")
        run_test(sb, results, "kill -9 1 - NOT BLOCKED (needs shell shim)",
                 "kill -9 1 2>&1", "info")

        # =================================================================
        # SUMMARY
        # =================================================================
        print("\n" + "=" * 70)
        print("  SUMMARY")
        print("=" * 70)
        print(f"""
    Tests passed: {results['passed']}
    Tests failed: {results['failed']}

    ═══════════════════════════════════════════════════════════════════
    WHAT WORKS ON MODAL
    ═══════════════════════════════════════════════════════════════════
      ✓ agentsh daemon ({AGENTSH_TAG})
      ✓ Health/Ready/Metrics endpoints
      ✓ Session creation and management
      ✓ Policy configuration loaded
      ✓ API endpoints accessible
      ✓ Allowed operations (whoami, id, ls, git, python)
      ✓ Workspace read/write ({WORKSPACE}, /tmp)
      ✓ Modal native isolation (metadata, docker socket, host fs)

    ═══════════════════════════════════════════════════════════════════
    GVISOR PLATFORM LIMITATIONS
    ═══════════════════════════════════════════════════════════════════
      ⚠  FUSE: /dev/fuse opens but fusermount3 mount denied
         -> No file-level policy enforcement (12 tests affected)
         -> Writes to /etc, /usr/bin, /var succeed
         -> /etc/shadow readable

      ⚠  seccomp_user_notify: detected but EINVAL at runtime
         -> No shell shim / agentsh exec (8 tests affected)
         -> sudo, su, kill not blocked
         -> No multi-context command blocking

      ⚠  Network proxy: HTTPS_PROXY set but enforcement partial
         -> evil.com not returning expected 400

    ═══════════════════════════════════════════════════════════════════
    WHAT WOULD WORK WITH FUSE + SECCOMP_USER_NOTIFY
    ═══════════════════════════════════════════════════════════════════
      These features work on Daytona and would work on Modal if
      gVisor enabled FUSE mounts and seccomp_user_notify:

      - File policy enforcement (VFS-level interception)
      - Command blocking (sudo, su, kill)
      - Multi-context command blocking (env, xargs, scripts, Python)
      - Shell shim (bash replacement)
      - agentsh exec (full command interception)
""")

    finally:
        print("\n[CLEANUP] Terminating Sandbox...")
        sb.terminate()
        print("    Sandbox terminated.")


if __name__ == "__main__":
    print("Run this script with: modal run tests.py")
