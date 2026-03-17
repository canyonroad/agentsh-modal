#!/usr/bin/env python3
"""
Functional ptrace probe inside a Modal sandbox.

Verifies that PTRACE_SEIZE (used by agentsh v0.16.1 attach_mode: "children")
actually works, not just that capabilities are advertised.
Also tests DNS resolution and blocking through agentsh's ptrace DNS proxy.
"""

import modal
import json
import time
import re
from pathlib import Path

AGENTSH_REPO = "canyonroad/agentsh"
AGENTSH_TAG = "v0.16.1"
DEB_ARCH = "amd64"

# C program that probes PTRACE_SEIZE / INTERRUPT / CONT / DETACH
PTRACE_SEIZE_PROBE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE     0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

int main(void) {
    pid_t child = fork();
    if (child < 0) {
        printf("fork:              FAIL (%s)\n", strerror(errno));
        printf("RESULT: ptrace SEIZE NOT supported\n");
        return 1;
    }

    if (child == 0) {
        /* Child: just sleep, parent will seize us */
        sleep(30);
        return 0;
    }

    /* Parent: give child a moment to start */
    usleep(100000);

    int ok = 1;

    /* PTRACE_SEIZE */
    long ret = ptrace(PTRACE_SEIZE, child, NULL, NULL);
    if (ret == -1) {
        printf("PTRACE_SEIZE:      FAIL (%s)\n", strerror(errno));
        ok = 0;
    } else {
        printf("PTRACE_SEIZE:      OK\n");
    }

    /* PTRACE_INTERRUPT — only meaningful if SEIZE succeeded */
    if (ok) {
        ret = ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_INTERRUPT:  FAIL (%s)\n", strerror(errno));
            ok = 0;
        } else {
            printf("PTRACE_INTERRUPT:  OK\n");
            int status;
            waitpid(child, &status, 0);
            if (WIFSTOPPED(status)) {
                printf("  (child stopped, signal %d)\n", WSTOPSIG(status));
            }
        }
    }

    /* PTRACE_CONT */
    if (ok) {
        ret = ptrace(PTRACE_CONT, child, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_CONT:       FAIL (%s)\n", strerror(errno));
            ok = 0;
        } else {
            printf("PTRACE_CONT:       OK\n");
        }
    }

    /* PTRACE_DETACH — stop child again first, then detach */
    if (ok) {
        ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
        int status;
        waitpid(child, &status, 0);

        ret = ptrace(PTRACE_DETACH, child, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_DETACH:     FAIL (%s)\n", strerror(errno));
            ok = 0;
        } else {
            printf("PTRACE_DETACH:     OK\n");
        }
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    if (ok) {
        printf("RESULT: ptrace SEIZE supported\n");
    } else {
        printf("RESULT: ptrace SEIZE NOT supported\n");
    }
    return ok ? 0 : 1;
}
"""


def create_image() -> modal.Image:
    """Debian-slim with gcc (for probe) and agentsh (for DNS filtering test)."""
    version = AGENTSH_TAG.lstrip("v")
    deb_name = f"agentsh_{version}_linux_{DEB_ARCH}.deb"
    deb_url = (
        f"https://github.com/{AGENTSH_REPO}/releases/download/{AGENTSH_TAG}/{deb_name}"
    )

    return (
        modal.Image.debian_slim(python_version="3.11")
        .apt_install("ca-certificates", "curl", "gcc", "libc6-dev")
        .run_commands(
            f"curl -fsSL -L '{deb_url}' -o /tmp/agentsh.deb",
            "dpkg -i /tmp/agentsh.deb",
            "rm -f /tmp/agentsh.deb",
            "agentsh --version",
            "mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine "
            "/var/lib/agentsh/sessions /var/log/agentsh",
            "chmod 777 /etc/agentsh /etc/agentsh/policies "
            "/var/lib/agentsh /var/lib/agentsh/quarantine "
            "/var/lib/agentsh/sessions /var/log/agentsh",
        )
        .env({"AGENTSH_SERVER": "http://127.0.0.1:18080"})
    )


app = modal.App("agentsh-detect")
image = create_image()


@app.local_entrypoint()
def main():
    print("=" * 60)
    print("  agentsh ptrace detection — Modal sandbox")
    print("=" * 60)

    sb = modal.Sandbox.create(app=app, image=image, timeout=300)

    def run(cmd, label=None):
        if label:
            print(f"\n--- {label} ---")
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
        print(f"\nSandbox: {sb.object_id}\n")

        # --- 1. Kernel info ---
        run("cat /proc/version", "Kernel")

        # --- 2. Functional probe ---
        print("\n" + "=" * 60)
        print("  PTRACE_SEIZE functional probe")
        print("=" * 60)

        sb.exec(
            "bash",
            "-c",
            f"cat > /tmp/seize_probe.c << 'CEOF'\n{PTRACE_SEIZE_PROBE}\nCEOF",
        ).wait()

        _, _, compile_rc = run(
            "gcc -o /tmp/seize_probe /tmp/seize_probe.c 2>&1", "Compile"
        )

        probe_supported = False
        if compile_rc != 0:
            print("COMPILE FAILED — cannot run probe")
        else:
            probe_out, _, _ = run("/tmp/seize_probe 2>&1", "Probe")
            probe_supported = "RESULT: ptrace SEIZE supported" in probe_out

        # --- 3. agentsh detect (capability check, for comparison) ---
        print("\n" + "=" * 60)
        print("  agentsh detect (capability check)")
        print("=" * 60)

        run("agentsh detect 2>&1", "agentsh detect")
        run("agentsh detect config 2>&1", "agentsh detect config")

        # --- 4. DNS probe (through agentsh ptrace proxy) ---
        print("\n" + "=" * 60)
        print("  DNS resolution probe")
        print("=" * 60)

        # 4a. Raw DNS (no agentsh) — should always work
        raw_out, _, raw_rc = run(
            'python3 -c "import socket; r=socket.getaddrinfo(\'github.com\', 443, socket.AF_INET); print(f\'Resolved: {r[0][4][0]}\')" 2>&1',
            "Raw DNS resolve github.com (no agentsh)",
        )
        raw_dns_ok = raw_rc == 0 and "Resolved:" in raw_out

        # 4b. Start agentsh server + create session for ptrace-proxied DNS
        script_dir = Path(__file__).parent
        config_yaml = (script_dir / "config.yaml").read_text()
        default_yaml = (script_dir / "default.yaml").read_text()

        sb.exec(
            "sh", "-c",
            f"cat > /etc/agentsh/config.yaml << 'AGENTSH_EOF'\n{config_yaml}\nAGENTSH_EOF",
        ).wait()
        sb.exec(
            "sh", "-c",
            f"cat > /etc/agentsh/policies/default.yaml << 'AGENTSH_EOF'\n{default_yaml}\nAGENTSH_EOF",
        ).wait()

        sb.exec(
            "sh", "-c",
            "agentsh server --config /etc/agentsh/config.yaml > /var/log/agentsh/agentsh.log 2>&1 &",
        )

        # Wait for server
        dns_allow_ok = False
        dns_block_ok = False
        session_id = ""

        for i in range(15):
            time.sleep(1)
            out, _, rc = run(
                "curl -s http://127.0.0.1:18080/health 2>&1",
            )
            if rc == 0 and out:
                print(f"\n    agentsh server ready (took {i+1}s)")
                break
        else:
            print("\n    Warning: agentsh server may not be ready")

        # Create session
        sess_out, sess_err, _ = run(
            "agentsh session create --workspace /root 2>&1",
            "Create session",
        )
        sess_output = (sess_out + "\n" + sess_err).strip()
        try:
            m = re.search(r'\{[^{}]*"id"[^{}]*\}', sess_output)
            if m:
                session_id = json.loads(m.group()).get("id", "")
        except (json.JSONDecodeError, AttributeError):
            pass
        if not session_id:
            m = re.search(r'(session-[a-f0-9-]{36})', sess_output)
            if m:
                session_id = m.group(1)

        if session_id:
            print(f"    Session: {session_id}")

            # 4c. DNS ALLOW — resolve github.com through agentsh exec
            allow_out, _, allow_rc = run(
                f"agentsh exec {session_id} -- python3 -c "
                "\"import socket; r=socket.getaddrinfo('github.com', 443, socket.AF_INET); "
                "print(f'Resolved: {r[0][4][0]}')\" 2>&1",
                "agentsh exec: DNS resolve github.com (ALLOWED)",
            )
            dns_allow_ok = "Resolved:" in allow_out

            # 4d. DNS DENY — resolve evil.com through agentsh exec (should be blocked)
            deny_out, _, deny_rc = run(
                f"agentsh exec {session_id} -- python3 -c "
                "\"import socket; socket.getaddrinfo('evil.com', 443, socket.AF_INET)\" 2>&1",
                "agentsh exec: DNS resolve evil.com (DENIED)",
            )
            deny_output = deny_out.lower()
            dns_block_ok = (
                deny_rc != 0
                or "denied" in deny_output
                or "blocked" in deny_output
                or "name resolution" in deny_output
                or "could not resolve" in deny_output
                or "refused" in deny_output
            )
        else:
            print("    No session — skipping agentsh exec DNS tests")

        # --- 5. Summary ---
        print("\n" + "=" * 60)
        verdict = "SUPPORTED" if probe_supported else "NOT SUPPORTED"
        print(f"  ptrace enforcement:   {verdict}")
        print(f"  raw DNS resolution:   {'OK' if raw_dns_ok else 'FAIL'}")
        if session_id:
            print(f"  DNS allow (github):   {'OK' if dns_allow_ok else 'FAIL'}")
            print(f"  DNS block (evil.com): {'OK' if dns_block_ok else 'FAIL'}")
        print("=" * 60)

    finally:
        sb.terminate()
        print("\nSandbox terminated.")


if __name__ == "__main__":
    print("Run this script with: modal run detect.py")
