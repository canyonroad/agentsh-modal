#!/usr/bin/env python3
"""
Run agentsh detect inside a Modal sandbox to discover capabilities.
"""

import modal

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.8.8"
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
    print("  Running agentsh detect inside Modal sandbox")
    print("=" * 70)

    sb = modal.Sandbox.create(
        app=app,
        image=image,
        timeout=60 * 5,
    )

    try:
        print(f"\nSandbox ID: {sb.object_id}\n")

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
        if p.stderr.read():
            print("stderr:", p.stderr.read())

        # Run agentsh detect config
        print("\n=== agentsh detect config ===")
        p = sb.exec("agentsh", "detect", "config")
        p.wait()
        print(p.stdout.read())
        if p.stderr.read():
            print("stderr:", p.stderr.read())

    finally:
        print("\nTerminating sandbox...")
        sb.terminate()
        print("Done.")


if __name__ == "__main__":
    print("Run this script with: modal run detect.py")
