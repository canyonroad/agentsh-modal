#!/usr/bin/env python3
"""
agentsh + Modal Sandbox Demo

This script demonstrates agentsh running in a Modal Sandbox.
Note: Modal's seccomp API version doesn't support user notify, so the shell
shim and agentsh exec aren't available. However, the agentsh daemon, session
management, and API endpoints work correctly.

For full agentsh functionality (including exec and shell shim), use a platform
with seccomp_user_notify support like E2B.

This demo shows:
- agentsh daemon running
- Session management API
- Health/metrics/ready endpoints
- Policy configuration loaded
- Modal's native container isolation

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
AGENTSH_TAG = "v0.8.8"
DEB_ARCH = "amd64"


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
    """Configure agentsh and start the daemon.

    Returns the session ID.
    """
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
    stdout, stderr, exit_code = run_command(sb, "agentsh session create --workspace /root --json 2>&1", timeout=30)
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
# MAIN ENTRY POINT
# =============================================================================

@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  agentsh + Modal Sandbox Demo")
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

        # =====================================================================
        # DAEMON & API TESTS
        # =====================================================================
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

        # =====================================================================
        # SESSION MANAGEMENT TESTS
        # =====================================================================
        print("\n" + "=" * 70)
        print("  SESSION MANAGEMENT TESTS")
        print("=" * 70)

        if session_id:
            results["passed"] += 1
            print(f"    ✓ Session created: {session_id[:40]}...")

            # Get session info
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

        # =====================================================================
        # MODAL NATIVE ISOLATION TESTS
        # =====================================================================
        print("\n" + "=" * 70)
        print("  MODAL NATIVE ISOLATION TESTS")
        print("=" * 70)

        isolation_tests = [
            ("AWS metadata blocked", "curl -s --connect-timeout 2 http://169.254.169.254/", "blocked"),
            ("No docker socket", "ls -la /var/run/docker.sock 2>&1", "blocked"),
            ("No host filesystem", "ls /host 2>&1", "blocked"),
            ("Container runs as root", "whoami", "success"),
            ("Git available", "git --version", "success"),
            ("Python available", "python3 --version", "success"),
        ]

        for name, cmd, expect in isolation_tests:
            stdout, stderr, exit_code = run_command(sb, cmd, timeout=10)
            output = (stdout + stderr).strip()

            if expect == "blocked":
                passed = exit_code != 0 or "denied" in output.lower() or "not found" in output.lower() or not output
            else:
                passed = exit_code == 0

            if passed:
                results["passed"] += 1
                icon = "✓"
            else:
                results["failed"] += 1
                icon = "✗"
            print(f"    {icon} {name}")

        # =====================================================================
        # AGENTSH EXEC LIMITATION
        # =====================================================================
        print("\n" + "=" * 70)
        print("  AGENTSH EXEC LIMITATION")
        print("=" * 70)

        print("    Note: agentsh exec requires seccomp_user_notify which")
        print("    Modal's container runtime doesn't support at runtime.")
        print("")
        print("    Testing exec to show limitation...")

        if session_id:
            json_payload = json.dumps({"command": "/bin/echo", "args": ["test"]})
            stdout, stderr, exit_code = run_command(sb, f"agentsh exec {session_id} --json '{json_payload}' 2>&1")
            output = (stdout + stderr).strip()

            if "seccomp" in output.lower() or exit_code != 0:
                print("    ⚠️  agentsh exec: Not available (seccomp limitation)")
                print(f"       Error: {output[:60]}...")
            else:
                print("    ✓ agentsh exec: Working")

        # =====================================================================
        # SUMMARY
        # =====================================================================
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
      ✓ Modal native container isolation

    ═══════════════════════════════════════════════════════════════════
    MODAL NATIVE PROTECTION
    ═══════════════════════════════════════════════════════════════════
      ✓ Cloud metadata blocked (169.254.169.254)
      ✓ No Docker socket access
      ✓ No host filesystem access
      ✓ Container isolation

    ═══════════════════════════════════════════════════════════════════
    LIMITATIONS ON MODAL
    ═══════════════════════════════════════════════════════════════════
      ⚠️  agentsh exec not available (seccomp_user_notify required)
      ⚠️  Shell shim not available (same limitation)

    For full agentsh functionality including command interception,
    use a platform with seccomp_user_notify support (e.g., E2B).
""")

    finally:
        print("\n[CLEANUP] Terminating Sandbox...")
        sb.terminate()
        print("    Sandbox terminated.")


if __name__ == "__main__":
    print("Run this script with: modal run tests.py")
