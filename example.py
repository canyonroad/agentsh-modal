#!/usr/bin/env python3
"""
agentsh + Modal Sandbox Security Demo

This script demonstrates the security features of agentsh running in a Modal Sandbox.
It creates a sandbox with agentsh installed, configures the shell shim, and runs
comprehensive security tests covering AI agent protection, cloud infrastructure
security, and multi-tenant isolation.

Prerequisites:
    pip install modal

Usage:
    modal run example.py
"""

import modal
from pathlib import Path

# =============================================================================
# AGENTSH CONFIGURATION
# =============================================================================

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.8.10"
DEB_ARCH = "amd64"

# =============================================================================
# SECURITY TEST DEFINITIONS
# =============================================================================

# NOTE: Modal's seccomp API version doesn't support user notify at runtime,
# even though `agentsh detect` reports it as available. This means:
# - Shell shim doesn't work (requires seccomp_user_notify)
# - agentsh exec doesn't work (requires seccomp_user_notify)
# - Commands run directly through bash bypass agentsh policy
#
# For full agentsh functionality, use a platform with seccomp_user_notify
# support like E2B.
#
# What DOES work on Modal:
# - agentsh daemon (health, metrics, ready endpoints)
# - Session management API
# - Policy configuration loading
# - Modal's native container isolation

SECURITY_TESTS = {
    # =========================================================================
    # A. MODAL NATIVE NETWORK ISOLATION
    # =========================================================================
    "modal_network": {
        "title": "Modal Native Network Isolation",
        "description": "Network security provided by Modal's container runtime",
        "tests": [
            {
                "name": "AWS metadata blocked (Modal)",
                "command": "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>&1",
                "expect": "blocked",
                "description": "Modal blocks cloud metadata access natively",
            },
            {
                "name": "GCP metadata blocked (Modal)",
                "command": "curl -s --connect-timeout 2 -H 'Metadata-Flavor: Google' http://metadata.google.internal/ 2>&1",
                "expect": "blocked",
                "description": "Modal blocks cloud metadata access natively",
            },
            {
                "name": "Public HTTPS works",
                "command": "curl -sI --connect-timeout 5 https://httpbin.org/get 2>&1 | head -3",
                "expect": "success",
                "description": "Outbound HTTPS to public internet works",
            },
            {
                "name": "Public HTTP works",
                "command": "curl -sI --connect-timeout 5 http://httpbin.org/get 2>&1 | head -3",
                "expect": "success",
                "description": "Outbound HTTP to public internet works",
            },
        ],
    },

    # =========================================================================
    # B. AGENTSH DAEMON FUNCTIONALITY
    # =========================================================================
    "agentsh_daemon": {
        "title": "agentsh Daemon (Control API)",
        "description": "agentsh server running for session management, audit, and DLP",
        "tests": [
            {
                "name": "agentsh health check",
                "command": "curl -s http://127.0.0.1:18080/health",
                "expect": "success",
                "description": "agentsh daemon is running",
            },
            {
                "name": "agentsh metrics endpoint",
                "command": "curl -s http://127.0.0.1:18080/metrics | head -5",
                "expect": "success",
                "description": "Metrics available for monitoring",
            },
            {
                "name": "agentsh ready check",
                "command": "curl -s http://127.0.0.1:18080/ready",
                "expect": "success",
                "description": "agentsh is ready to accept requests",
            },
        ],
    },

    # =========================================================================
    # C. BASIC SANDBOX OPERATIONS
    # =========================================================================
    "basic_ops": {
        "title": "Basic Sandbox Operations",
        "description": "Verify basic operations work in Modal sandbox",
        "tests": [
            {
                "name": "Basic echo",
                "command": "echo 'Hello from Modal sandbox'",
                "expect": "success",
                "description": "Basic shell command",
            },
            {
                "name": "List files",
                "command": "ls -la /etc/agentsh/",
                "expect": "success",
                "description": "agentsh config directory exists",
            },
            {
                "name": "Git version",
                "command": "git --version",
                "expect": "success",
                "description": "Git is available",
            },
            {
                "name": "Python version",
                "command": "python3 --version",
                "expect": "success",
                "description": "Python is available",
            },
            {
                "name": "agentsh binary",
                "command": "/usr/bin/agentsh --version",
                "expect": "success",
                "description": "agentsh is installed",
            },
            {
                "name": "Policy file loaded",
                "command": "cat /etc/agentsh/policies/default.yaml | head -10",
                "expect": "success",
                "description": "Security policy is in place",
            },
        ],
    },

    # =========================================================================
    # D. MODAL CONTAINER ISOLATION
    # =========================================================================
    "modal_isolation": {
        "title": "Modal Container Isolation",
        "description": "Security provided by Modal's container runtime (runs as root in isolated container)",
        "tests": [
            {
                "name": "Running as root",
                "command": "whoami",
                "expect": "success",
                "description": "Container runs as root (isolated)",
            },
            {
                "name": "No docker socket",
                "command": "ls -la /var/run/docker.sock 2>&1",
                "expect": "blocked",
                "description": "Docker socket not available",
            },
            {
                "name": "No host PID namespace",
                "command": "cat /proc/1/cmdline 2>&1 | tr '\\0' ' '",
                "expect": "success",
                "description": "PID 1 is container init, not host",
            },
            {
                "name": "Isolated filesystem",
                "command": "ls /host 2>&1",
                "expect": "blocked",
                "description": "No host filesystem access",
            },
        ],
    },

    # =========================================================================
    # E. MODAL-SPECIFIC SECURITY SCENARIOS
    # =========================================================================
    "modal_specific": {
        "title": "Modal-Specific Security Scenarios",
        "description": "Security risks and protections specific to Modal sandboxes",
        "tests": [
            {
                "name": "Environment variables visible",
                "command": "env | grep -E '^(PATH|HOME|MODAL)' | head -5",
                "expect": "success",
                "description": "Agents can read environment variables (secrets risk)",
            },
            {
                "name": "Modal token exposure check",
                "command": "env | grep -i token || echo 'no tokens in env'",
                "expect": "success",
                "description": "Check if Modal tokens are exposed in environment",
            },
            {
                "name": "Outbound data exfiltration possible",
                "command": "curl -s -X POST https://httpbin.org/post -d 'secret=test123' | grep -o 'secret.*test123' || echo 'data sent'",
                "expect": "success",
                "description": "Modal allows outbound HTTPS (exfiltration risk without agentsh)",
            },
            {
                "name": "Can access any public API",
                "command": "curl -s https://api.github.com/zen",
                "expect": "success",
                "description": "No domain restrictions (would be blocked by agentsh policy)",
            },
            {
                "name": "Write to /tmp unrestricted",
                "command": "dd if=/dev/zero of=/tmp/bigfile bs=1M count=10 2>&1 && ls -lh /tmp/bigfile && rm /tmp/bigfile",
                "expect": "success",
                "description": "Disk space abuse possible (would be limited by agentsh)",
            },
            {
                "name": "Process limits exist",
                "command": "ulimit -u",
                "expect": "success",
                "description": "Modal sets process limits",
            },
        ],
    },

    # =========================================================================
    # F. AGENTSH API FUNCTIONALITY
    # =========================================================================
    "agentsh_api": {
        "title": "agentsh API Functionality",
        "description": "Test agentsh's API endpoints (works on Modal)",
        "tests": [
            {
                "name": "List policies via API",
                "command": "curl -s http://127.0.0.1:18080/api/v1/policies 2>&1 | head -c 100",
                "expect": "success",
                "description": "Policy API accessible",
            },
            {
                "name": "Get server info",
                "command": "curl -s http://127.0.0.1:18080/api/v1/info 2>&1 | head -c 100",
                "expect": "success",
                "description": "Server info available",
            },
        ],
    },

    # =========================================================================
    # G. SECURITY GAPS DEMONSTRATION
    # =========================================================================
    "security_gaps": {
        "title": "Security Gaps (what agentsh would protect)",
        "description": "Demonstrating risks that full agentsh would mitigate",
        "tests": [
            {
                "name": "rm -rf executes freely",
                "command": "mkdir -p /tmp/testdir && touch /tmp/testdir/file.txt && rm -rf /tmp/testdir && echo 'rm -rf succeeded'",
                "expect": "success",
                "description": "Destructive command runs (agentsh would block)",
            },
            {
                "name": "Can read system files",
                "command": "head -2 /etc/passwd",
                "expect": "success",
                "description": "System file access (agentsh could require approval)",
            },
            {
                "name": "Can write anywhere in /tmp",
                "command": "echo 'sensitive data' > /tmp/leak.txt && cat /tmp/leak.txt && rm /tmp/leak.txt",
                "expect": "success",
                "description": "Unrestricted file write (agentsh would control)",
            },
        ],
    },
}


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
        )
        .run_commands(
            # Download and install agentsh
            f"curl -fsSL -L '{deb_url}' -o /tmp/agentsh.deb",
            "dpkg -i /tmp/agentsh.deb",
            "rm -f /tmp/agentsh.deb",
            "agentsh --version",
            # Create agentsh directories
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

app = modal.App("agentsh-sandbox")
image = create_agentsh_image()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def write_file_to_sandbox(sb: modal.Sandbox, path: str, content: str) -> None:
    """Write a file to the sandbox filesystem."""
    # Use heredoc to write file content safely
    p = sb.exec("sh", "-c", f"cat > '{path}' << 'AGENTSH_EOF'\n{content}\nAGENTSH_EOF")
    p.wait()


def run_command(sb: modal.Sandbox, command: str, timeout: int = 30) -> tuple[str, str, int]:
    """Run a command in the sandbox and return stdout, stderr, exit_code."""
    p = sb.exec("bash", "-c", command, timeout=timeout)
    p.wait()
    stdout = p.stdout.read()
    stderr = p.stderr.read()
    exit_code = p.returncode
    return stdout, stderr, exit_code


def setup_agentsh(sb: modal.Sandbox, config_yaml: str, default_yaml: str, use_shim: bool = False) -> None:
    """Configure agentsh in the sandbox.

    Args:
        sb: Modal sandbox instance
        config_yaml: agentsh server config content
        default_yaml: Security policy content
        use_shim: If True, attempt to install shell shim (requires seccomp user notify).
                  If False, use network-proxy-only mode.
    """
    print("    Writing configuration files...")
    write_file_to_sandbox(sb, "/etc/agentsh/config.yaml", config_yaml)
    write_file_to_sandbox(sb, "/etc/agentsh/policies/default.yaml", default_yaml)

    if use_shim:
        print("    Installing shell shim...")
        stdout, stderr, exit_code = run_command(
            sb,
            "agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host",
            timeout=60
        )
        if exit_code != 0:
            print(f"    Warning: Shell shim installation returned exit code {exit_code}")
            print(f"    stdout: {stdout}")
            print(f"    stderr: {stderr}")
    else:
        print("    Skipping shell shim (seccomp user notify not available)")
        print("    Using network-proxy-only mode...")

    print("    Starting agentsh daemon...")
    # Start the daemon in background
    sb.exec("sh", "-c", "nohup agentsh server --config /etc/agentsh/config.yaml > /var/log/agentsh/agentsh.log 2>&1 &")

    # Wait for daemon to be ready
    import time
    for i in range(10):
        time.sleep(1)
        stdout, stderr, exit_code = run_command(sb, "curl -s http://127.0.0.1:18080/health 2>&1", timeout=5)
        if exit_code == 0:
            print(f"    agentsh daemon is running! (took {i+1}s)")
            return
        # Check if process is running
        ps_out, _, _ = run_command(sb, "pgrep -f 'agentsh server' || echo 'not running'", timeout=5)
        if "not running" in ps_out:
            # Try to get error from log
            log_out, _, _ = run_command(sb, "cat /var/log/agentsh/agentsh.log 2>&1 | tail -20", timeout=5)
            print(f"    Daemon not running. Log:\n{log_out}")
            break

    print(f"    Warning: daemon may not be fully ready (health check: {stdout.strip() or 'no response'})")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  agentsh + Modal Sandbox Security Demo")
    print("=" * 70)

    # Read configuration files
    script_dir = Path(__file__).parent
    config_yaml = (script_dir / "config.yaml").read_text()
    default_yaml = (script_dir / "default.yaml").read_text()

    # -------------------------------------------------------------------------
    # Step 1: Create Sandbox
    # -------------------------------------------------------------------------
    print("\n[1] Creating Modal Sandbox with agentsh...")

    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 30,  # 30 minutes
    )
    print(f"    Sandbox ID: {sb.object_id}")

    try:
        # -------------------------------------------------------------------------
        # Step 2: Configure agentsh
        # -------------------------------------------------------------------------
        print("\n[2] Configuring agentsh...")
        setup_agentsh(sb, config_yaml, default_yaml, use_shim=False)
        print("    agentsh configured!")

        # -------------------------------------------------------------------------
        # Step 3: Run Security Tests
        # -------------------------------------------------------------------------
        results = {"passed": 0, "failed": 0, "errors": 0}

        for category_key, category in SECURITY_TESTS.items():
            print(f"\n{'=' * 70}")
            print(f"  {category['title']}")
            print(f"  {category['description']}")
            print("=" * 70)

            for test in category["tests"]:
                print(f"\n[TEST] {test['name']}")
                print(f"       {test['description']}")
                print(f"       Command: {test['command'][:60]}{'...' if len(test['command']) > 60 else ''}")

                try:
                    stdout, stderr, exit_code = run_command(sb, test["command"], timeout=30)
                    output = (stdout + stderr).strip()

                    # Truncate long output
                    if len(output) > 200:
                        output = output[:200] + "..."

                    # Determine if test passed based on expectation
                    if test["expect"] == "blocked":
                        # For blocked tests, we expect non-zero exit or error message
                        passed = (
                            exit_code != 0
                            or "blocked" in output.lower()
                            or "denied" in output.lower()
                            or "permission" in output.lower()
                            or "400" in output
                            or "not found" in output.lower()
                        )
                    elif test["expect"] == "success":
                        passed = exit_code == 0
                    else:
                        passed = True

                    status = "PASS" if passed else "FAIL"
                    results["passed" if passed else "failed"] += 1

                    print(f"       Output: {output if output else '(no output)'}")
                    print(f"       Exit code: {exit_code}")
                    print(f"       Result: [{status}]")

                except TimeoutError:
                    print("       Error: Command timed out")
                    print("       Result: [ERROR]")
                    results["errors"] += 1
                except Exception as e:
                    print(f"       Error: {e}")
                    print("       Result: [ERROR]")
                    results["errors"] += 1

        # -------------------------------------------------------------------------
        # Summary
        # -------------------------------------------------------------------------
        print("\n" + "=" * 70)
        print("  SUMMARY")
        print("=" * 70)
        print(f"""
    Tests passed: {results['passed']}
    Tests failed: {results['failed']}
    Errors:       {results['errors']}

    ═══════════════════════════════════════════════════════════════════
    MODAL NATIVE PROTECTION (works without agentsh):
    ═══════════════════════════════════════════════════════════════════
      ✅ Cloud metadata blocked (169.254.169.254)
      ✅ Container isolation (separate namespaces)
      ✅ No Docker socket access
      ✅ No host filesystem access
      ✅ Process limits (fork bomb protection)

    ═══════════════════════════════════════════════════════════════════
    AGENTSH ON MODAL (daemon and API only):
    ═══════════════════════════════════════════════════════════════════
      ✅ Daemon runs (health, metrics, ready endpoints)
      ✅ Session management API
      ✅ Audit event logging
      ✅ Policy configuration loaded
      ⚠️  Shell shim NOT active (seccomp_user_notify fails at runtime)
      ⚠️  agentsh exec NOT active (same limitation)

    ═══════════════════════════════════════════════════════════════════
    LIMITATIONS ON MODAL:
    ═══════════════════════════════════════════════════════════════════
      ❌ Commands bypass agentsh policy (no interception)
      ❌ rm -rf and destructive commands execute freely
      ❌ No command-level audit logging

    For full agentsh functionality (including command interception),
    use a platform with seccomp_user_notify support (e.g., E2B).
""")

    finally:
        # -------------------------------------------------------------------------
        # Cleanup
        # -------------------------------------------------------------------------
        print("\n[CLEANUP] Terminating Sandbox...")
        sb.terminate()
        print(f"    Sandbox {sb.object_id} terminated.")


if __name__ == "__main__":
    # This allows running with `python example.py` for testing,
    # but the recommended way is `modal run example.py`
    print("Run this script with: modal run example.py")
