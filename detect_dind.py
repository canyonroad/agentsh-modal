#!/usr/bin/env python3
"""
Run agentsh inside Docker-in-Docker within a Modal sandbox.
The Docker container inside Modal might have real seccomp_user_notify support.
"""

import modal

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.10.0"
DEB_ARCH = "amd64"


def create_docker_image() -> modal.Image:
    """Create a Modal image with Docker installed."""
    return (
        modal.Image.debian_slim(python_version="3.11")
        .apt_install(
            "ca-certificates",
            "curl",
            "bash",
            "iptables",
            "procps",
        )
        .run_commands(
            # Install Docker
            "curl -fsSL https://get.docker.com | sh",
            # Use iptables-legacy (gVisor doesn't support nftables)
            "update-alternatives --set iptables /usr/sbin/iptables-legacy || true",
            "update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy || true",
        )
    )


app = modal.App("agentsh-docker-in-docker")
image = create_docker_image()


@app.local_entrypoint()
def main():
    print("=" * 70)
    print("  Testing agentsh inside Docker-in-Docker on Modal")
    print("=" * 70)

    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 10,
        experimental_options={"enable_docker": True},
    )

    def run(cmd: str, timeout: int = 60) -> tuple[str, str, int]:
        p = sb.exec("bash", "-c", cmd, timeout=timeout)
        p.wait()
        return p.stdout.read(), p.stderr.read(), p.returncode

    try:
        print(f"\nSandbox ID: {sb.object_id}\n")

        # Step 1: Start Docker daemon
        print("=== Starting Docker daemon ===")
        # Start dockerd with iptables disabled (gVisor limitation)
        sb.exec("bash", "-c", "dockerd --iptables=false --ip6tables=false > /tmp/dockerd.log 2>&1 &")

        import time
        for i in range(30):
            time.sleep(1)
            stdout, stderr, rc = run("docker info 2>&1", timeout=10)
            if rc == 0:
                print(f"Docker daemon ready! (took {i+1}s)")
                # Print key info
                for line in stdout.split('\n')[:10]:
                    print(line)
                break
            if i == 29:
                print("Docker daemon failed to start")
                stdout, _, _ = run("cat /tmp/dockerd.log | tail -30")
                print(f"Docker log:\n{stdout}")
                return

        # Step 2: Check Docker runtime info
        print("\n=== Docker Runtime Info ===")
        stdout, _, _ = run("docker info 2>&1 | grep -E '(Runtime|Cgroup|Security)'")
        print(stdout)

        # Step 3: Build/pull an image with agentsh
        print("\n=== Building agentsh container ===")
        version = AGENTSH_TAG.lstrip("v")
        deb_url = f"https://github.com/{AGENTSH_REPO}/releases/download/{AGENTSH_TAG}/agentsh_{version}_linux_{DEB_ARCH}.deb"

        dockerfile = f"""
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl libseccomp2 fuse3 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -L '{deb_url}' -o /tmp/agentsh.deb && dpkg -i /tmp/agentsh.deb && rm /tmp/agentsh.deb
"""
        run(f"cat > /tmp/Dockerfile << 'EOF'\n{dockerfile}\nEOF")
        # Use --network=host for build to get DNS resolution (iptables disabled)
        stdout, stderr, rc = run("docker build --network=host -t agentsh-test /tmp 2>&1", timeout=120)
        if rc != 0:
            print(f"Build failed:\n{stdout}\n{stderr}")
            return
        print("Image built successfully")

        # Step 4: Run agentsh detect inside Docker container
        print("\n=== agentsh detect (inside Docker container) ===")
        stdout, stderr, rc = run("docker run --rm --network=host agentsh-test agentsh detect 2>&1")
        print(stdout)
        if stderr:
            print(stderr)

        # Step 5: Check kernel version inside container
        print("\n=== Kernel info inside Docker container ===")
        stdout, _, _ = run("docker run --rm --network=host agentsh-test cat /proc/version")
        print(stdout)

        # Step 6: Test seccomp_user_notify inside Docker container
        print("\n=== Testing seccomp_user_notify inside Docker container ===")

        # Create test script
        test_script = """
#!/bin/bash
set -e

# Create minimal config
mkdir -p /etc/agentsh/policies
cat > /etc/agentsh/config.yaml << 'CONF'
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
CONF

cat > /etc/agentsh/policies/default.yaml << 'POLICY'
version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
POLICY

# Start server
agentsh server --config /etc/agentsh/config.yaml > /tmp/server.log 2>&1 &
sleep 2

# Check health
if curl -s http://127.0.0.1:18080/health | grep -q ok; then
    echo "Server running"

    # Try agentsh exec
    echo "Testing agentsh exec..."
    if agentsh exec -- echo "SUCCESS: seccomp_user_notify works!" 2>&1; then
        echo "RESULT: seccomp_user_notify WORKS inside Docker-in-Docker!"
    else
        echo "RESULT: seccomp_user_notify still fails"
        cat /tmp/server.log | tail -20
    fi
else
    echo "Server failed to start"
    cat /tmp/server.log
fi
"""
        run(f"cat > /tmp/test.sh << 'SCRIPT'\n{test_script}\nSCRIPT")
        run("chmod +x /tmp/test.sh")

        # Run test in Docker container (try with different security options)
        # Use --network=host since iptables is disabled
        print("\n--- Test 1: Default Docker run (network=host) ---")
        stdout, stderr, rc = run("docker run --rm --network=host -v /tmp/test.sh:/test.sh agentsh-test bash /test.sh 2>&1", timeout=60)
        print(stdout)
        if stderr:
            print(stderr)

        print("\n--- Test 2: With --privileged ---")
        stdout, stderr, rc = run("docker run --rm --privileged --network=host -v /tmp/test.sh:/test.sh agentsh-test bash /test.sh 2>&1", timeout=60)
        print(stdout)
        if stderr:
            print(stderr)

        print("\n--- Test 3: With --security-opt seccomp=unconfined ---")
        stdout, stderr, rc = run("docker run --rm --security-opt seccomp=unconfined --network=host -v /tmp/test.sh:/test.sh agentsh-test bash /test.sh 2>&1", timeout=60)
        print(stdout)
        if stderr:
            print(stderr)

    finally:
        print("\nTerminating sandbox...")
        sb.terminate()
        print("Done.")


if __name__ == "__main__":
    print("Run with: modal run detect_dind.py")
