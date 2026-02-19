#!/usr/bin/env python3
"""
Run agentsh detect inside a Modal sandbox to discover capabilities.
"""

import modal

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.10.0"
DEB_ARCH = "amd64"


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
        )
        .run_commands(
            f"curl -fsSL -L '{deb_url}' -o /tmp/agentsh.deb",
            "dpkg -i /tmp/agentsh.deb",
            "rm -f /tmp/agentsh.deb",
            "agentsh --version",
        )
    )


app = modal.App("agentsh-detect")
image = create_agentsh_image()


@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  Running agentsh detect + diagnostics inside Modal sandbox")
    print("=" * 70)

    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 5,
    )

    def run(cmd, label=None):
        if label:
            print(f"\n=== {label} ===")
        p = sb.exec("bash", "-c", cmd)
        p.wait()
        stdout = p.stdout.read().strip()
        stderr = p.stderr.read().strip()
        if stdout:
            print(stdout)
        if stderr:
            print(f"stderr: {stderr}")
        return stdout, stderr, p.returncode

    try:
        print(f"\nSandbox ID: {sb.object_id}\n")

        run("agentsh --version", "agentsh version")
        run("agentsh detect 2>&1", "agentsh detect")
        run("agentsh detect config 2>&1", "agentsh detect config")

        # =============================================
        # SECCOMP DIAGNOSTICS
        # =============================================
        print("\n" + "=" * 70)
        print("  SECCOMP DIAGNOSTICS")
        print("=" * 70)

        run("cat /proc/version", "Kernel version")
        run("cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || echo 'not available'",
            "seccomp actions available")
        run("cat /proc/sys/kernel/seccomp/actions_logged 2>/dev/null || echo 'not available'",
            "seccomp actions logged")

        # Check prctl seccomp support
        run('''python3 -c "
import ctypes, ctypes.util
PR_GET_SECCOMP = 21
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_GET_ACTION_AVAIL = 2
SECCOMP_GET_NOTIF_SIZES = 3

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# Check current seccomp mode
mode = libc.prctl(PR_GET_SECCOMP, 0, 0, 0, 0)
print(f'Current seccomp mode: {mode}')

# Check seccomp syscall API
import os
SYS_seccomp = 317  # x86_64
ret = libc.syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, 0)
errno = ctypes.get_errno()
print(f'seccomp(GET_NOTIF_SIZES): ret={ret}, errno={errno} ({os.strerror(errno) if errno else \"success\"})')
" 2>&1''', "seccomp API probe (Python)")

        # Check if /dev/fuse exists and is usable
        print("\n" + "=" * 70)
        print("  FUSE DIAGNOSTICS")
        print("=" * 70)

        run("ls -la /dev/fuse 2>&1", "/dev/fuse")
        run("stat /dev/fuse 2>&1", "/dev/fuse stat")
        run("mount | grep -i fuse 2>&1 || echo 'no fuse mounts'", "FUSE mounts")

        # Try a simple FUSE test
        run('''python3 -c "
import os
try:
    fd = os.open('/dev/fuse', os.O_RDWR)
    print(f'Opened /dev/fuse successfully, fd={fd}')
    os.close(fd)
except Exception as e:
    print(f'Failed to open /dev/fuse: {e}')
" 2>&1''', "FUSE device open test (Python)")

        # =============================================
        # AGENTSH EXEC DIAGNOSTICS
        # =============================================
        print("\n" + "=" * 70)
        print("  AGENTSH EXEC DIAGNOSTICS")
        print("=" * 70)

        # Start server with verbose logging
        print("\nStarting agentsh server with debug logging...")

        config = """
server:
  http:
    addr: "127.0.0.1:18080"
auth:
  type: "none"
logging:
  level: "debug"
  format: "text"
  output: "stderr"
sandbox:
  enabled: true
  allow_degraded: true
  fuse:
    enabled: true
    deferred: false
  network:
    enabled: false
policies:
  dir: "/etc/agentsh/policies"
  default: "default"
development:
  disable_auth: true
  verbose_errors: true
"""
        policy = """
version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["**"]
    operations: ["*"]
    decision: allow
"""
        run("mkdir -p /etc/agentsh/policies")
        sb.exec("bash", "-c", f"cat > /etc/agentsh/config.yaml << 'EOF'\n{config}\nEOF")
        sb.exec("bash", "-c", f"cat > /etc/agentsh/policies/default.yaml << 'EOF'\n{policy}\nEOF")

        # Ensure /dev/fuse is accessible
        run("chmod 666 /dev/fuse 2>&1 || true")

        # Start server
        sb.exec("bash", "-c", "agentsh server --config /etc/agentsh/config.yaml > /tmp/agentsh.log 2>&1 &")

        import time
        time.sleep(3)

        run("curl -s http://127.0.0.1:18080/health", "Server health")

        # Check server log for FUSE/seccomp messages
        run("cat /tmp/agentsh.log 2>&1 | grep -i -E '(fuse|seccomp|exec|mount|filter|notify)' | head -20",
            "Server log (fuse/seccomp/exec)")

        # Check if FUSE got mounted
        run("mount | grep -i fuse 2>&1 || echo 'no fuse mounts'", "FUSE mounts after server start")

        # Create a session
        stdout, _, rc = run("agentsh session create --workspace /root --json 2>&1", "Create session")
        import json, re
        session_id = ""
        try:
            m = re.search(r'\{[^{}]*"id"[^{}]*\}', stdout)
            if m:
                session_id = json.loads(m.group()).get("id", "")
        except:
            pass

        if session_id:
            print(f"\nSession ID: {session_id}")

            # Try exec with verbose output
            run(f"agentsh exec {session_id} --json '{{\"command\": \"/bin/echo\", \"args\": [\"hello\"]}}' 2>&1",
                "agentsh exec test")

            # Check server log after exec attempt
            run("cat /tmp/agentsh.log 2>&1 | tail -30",
                "Server log (last 30 lines)")
        else:
            print("No session created, skipping exec test")

        # Full server log
        run("wc -l /tmp/agentsh.log", "Server log line count")

    finally:
        print("\nTerminating sandbox...")
        sb.terminate()
        print("Done.")


if __name__ == "__main__":
    print("Run this script with: modal run detect.py")
