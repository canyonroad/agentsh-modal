#!/usr/bin/env python3
"""
Run agentsh detect inside a Modal sandbox with Docker enabled.
This may use a different runtime that supports seccomp_user_notify.
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


app = modal.App("agentsh-detect-docker")
image = create_agentsh_image()


@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  Running agentsh detect inside Modal sandbox WITH enable_docker")
    print("=" * 70)

    # Create sandbox with Docker enabled - this may use a different runtime
    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 5,
        experimental_options={"enable_docker": True},
    )

    try:
        print(f"\nSandbox ID: {sb.object_id}\n")

        # Check the runtime environment
        print("=== Runtime Environment ===")
        p = sb.exec("bash", "-c", "cat /proc/version 2>&1 || echo 'cannot read'")
        p.wait()
        print(p.stdout.read())

        p = sb.exec("bash", "-c", "env | grep -i MODAL | head -10")
        p.wait()
        print(p.stdout.read())

        # Run agentsh version
        print("=== agentsh version ===")
        p = sb.exec("agentsh", "--version")
        p.wait()
        print(p.stdout.read())

        # Run agentsh detect
        print("\n=== agentsh detect ===")
        p = sb.exec("agentsh", "detect")
        p.wait()
        print(p.stdout.read())
        stderr = p.stderr.read()
        if stderr:
            print(stderr)

        # Run agentsh detect config
        print("\n=== agentsh detect config ===")
        p = sb.exec("agentsh", "detect", "config")
        p.wait()
        print(p.stdout.read())
        stderr = p.stderr.read()
        if stderr:
            print(stderr)

        # Test if seccomp user notify actually works at runtime
        print("\n=== Testing seccomp_user_notify at runtime ===")

        # Create a minimal config for testing
        config = """
server:
  http:
    addr: "127.0.0.1:18080"
auth:
  type: "none"
sandbox:
  enabled: true
  seccomp:
    enabled: true
policies:
  dir: "/etc/agentsh/policies"
  default_policy: "default"
"""
        policy = """
version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
"""
        # Write config files
        p = sb.exec("mkdir", "-p", "/etc/agentsh/policies")
        p.wait()

        p = sb.exec("bash", "-c", f"cat > /etc/agentsh/config.yaml << 'EOF'\n{config}\nEOF")
        p.wait()

        p = sb.exec("bash", "-c", f"cat > /etc/agentsh/policies/default.yaml << 'EOF'\n{policy}\nEOF")
        p.wait()

        # Try to start agentsh server and test exec
        print("Starting agentsh server...")
        sb.exec("bash", "-c", "agentsh server --config /etc/agentsh/config.yaml > /tmp/agentsh.log 2>&1 &")

        import time
        time.sleep(2)

        # Check if server is running
        p = sb.exec("bash", "-c", "curl -s http://127.0.0.1:18080/health || echo 'server not responding'")
        p.wait()
        health = p.stdout.read().strip()
        print(f"Health check: {health}")

        if health == "ok":
            print("\nTrying agentsh exec (requires seccomp_user_notify)...")
            p = sb.exec("bash", "-c", "agentsh exec -- echo 'seccomp_user_notify works!' 2>&1")
            p.wait()
            stdout = p.stdout.read()
            stderr = p.stderr.read()
            print(f"stdout: {stdout}")
            if stderr:
                print(f"stderr: {stderr}")
            print(f"exit code: {p.returncode}")

            if p.returncode == 0 and "seccomp_user_notify works" in stdout:
                print("\n✅ SUCCESS! seccomp_user_notify works with enable_docker!")
            else:
                print("\n❌ seccomp_user_notify still doesn't work at runtime")
                # Show server log for debugging
                p = sb.exec("bash", "-c", "cat /tmp/agentsh.log | tail -30")
                p.wait()
                print(f"Server log:\n{p.stdout.read()}")

    finally:
        print("\nTerminating sandbox...")
        sb.terminate()
        print("Done.")


if __name__ == "__main__":
    print("Run this script with: modal run detect_docker.py")
