#!/usr/bin/env python3
"""Test ptrace support inside a Modal Sandbox (gVisor)."""

import modal

app = modal.App("ptrace-test")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("strace", "gcc", "libc6-dev")
)


def run_cmd(sb, command, timeout=30):
    """Run a command and return stdout+stderr and exit code."""
    try:
        p = sb.exec("bash", "-c", command, timeout=timeout)
        p.wait()
        stdout = p.stdout.read() if p.stdout else ""
        stderr = p.stderr.read() if p.stderr else ""
        return (stdout + stderr).strip(), p.returncode or 0
    except Exception as e:
        return str(e), -1


@app.local_entrypoint()
def main():
    print("=" * 60)
    print("  ptrace Support Test in Modal Sandbox (gVisor)")
    print("=" * 60)

    sb = modal.Sandbox.create(app=app, image=image, timeout=300)
    print(f"Sandbox: {sb.object_id}\n")

    try:
        # Test 1: strace on a simple command
        print("[1] strace echo hello")
        out, rc = run_cmd(sb, "strace -f echo hello 2>&1 | tail -20")
        print(f"    exit={rc}")
        print(f"    output:\n{_indent(out)}\n")

        # Test 2: C program using PTRACE_TRACEME
        print("[2] C program: PTRACE_TRACEME")
        c_code = r'''
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        // Child: request to be traced
        long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (ret == -1) {
            printf("PTRACE_TRACEME failed: %s (errno=%d)\n", strerror(errno), errno);
            return 1;
        }
        printf("PTRACE_TRACEME succeeded\n");
        // Signal parent we're ready
        raise(SIGSTOP);
        printf("Child resumed after SIGSTOP\n");
        return 0;
    } else {
        // Parent: wait for child to stop
        int status;
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status)) {
            printf("Parent: child stopped with signal %d\n", WSTOPSIG(status));
            // Resume child
            long ret = ptrace(PTRACE_CONT, child, NULL, NULL);
            if (ret == -1) {
                printf("PTRACE_CONT failed: %s (errno=%d)\n", strerror(errno), errno);
            } else {
                printf("PTRACE_CONT succeeded\n");
            }
            waitpid(child, &status, 0);
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else {
            printf("Parent: child did not stop as expected (status=0x%x)\n", status);
        }
    }
    return 0;
}
'''
        # Write, compile, run
        run_cmd(sb, f"cat > /tmp/ptrace_test.c << 'CEOF'\n{c_code}\nCEOF")
        out, rc = run_cmd(sb, "gcc -o /tmp/ptrace_test /tmp/ptrace_test.c 2>&1")
        if rc != 0:
            print(f"    compile failed: {out}")
        else:
            out, rc = run_cmd(sb, "/tmp/ptrace_test 2>&1")
            print(f"    exit={rc}")
            print(f"    output:\n{_indent(out)}\n")

        # Test 3: PTRACE_ATTACH to another process
        print("[3] C program: PTRACE_ATTACH to sleep process")
        c_attach = r'''
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

int main() {
    // Spawn a target process
    pid_t target = fork();
    if (target == 0) {
        sleep(10);
        return 0;
    }

    // Try to attach
    usleep(100000); // 100ms
    long ret = ptrace(PTRACE_ATTACH, target, NULL, NULL);
    if (ret == -1) {
        printf("PTRACE_ATTACH failed: %s (errno=%d)\n", strerror(errno), errno);
        kill(target, SIGKILL);
        return 1;
    }
    printf("PTRACE_ATTACH succeeded (pid=%d)\n", target);

    int status;
    waitpid(target, &status, 0);
    printf("Target stopped: %d\n", WIFSTOPPED(status));

    // Detach
    ret = ptrace(PTRACE_DETACH, target, NULL, NULL);
    if (ret == -1) {
        printf("PTRACE_DETACH failed: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("PTRACE_DETACH succeeded\n");
    }

    kill(target, SIGKILL);
    return 0;
}
'''
        run_cmd(sb, f"cat > /tmp/ptrace_attach.c << 'CEOF'\n{c_attach}\nCEOF")
        out, rc = run_cmd(sb, "gcc -o /tmp/ptrace_attach /tmp/ptrace_attach.c 2>&1")
        if rc != 0:
            print(f"    compile failed: {out}")
        else:
            out, rc = run_cmd(sb, "/tmp/ptrace_attach 2>&1")
            print(f"    exit={rc}")
            print(f"    output:\n{_indent(out)}\n")

        # Test 4: PTRACE_PEEKDATA - read memory of child
        print("[4] C program: PTRACE_PEEKDATA (read child memory)")
        c_peek = r'''
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        return 42;
    }

    int status;
    waitpid(child, &status, 0);

    // Try to peek at child's memory (read the stack pointer area)
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, child, (void*)0x7fff00000000UL, NULL);
    if (errno != 0) {
        printf("PTRACE_PEEKDATA failed: %s (errno=%d)\n", strerror(errno), errno);
        // This may fail due to address, try reading from /proc/pid/maps first
    } else {
        printf("PTRACE_PEEKDATA succeeded: val=0x%lx\n", val);
    }

    // Try PTRACE_GETREGS
    #include <sys/user.h>
    struct user_regs_struct regs;
    long ret = ptrace(PTRACE_GETREGS, child, NULL, &regs);
    if (ret == -1) {
        printf("PTRACE_GETREGS failed: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("PTRACE_GETREGS succeeded: rip=0x%llx\n", regs.rip);
    }

    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
    return 0;
}
'''
        run_cmd(sb, f"cat > /tmp/ptrace_peek.c << 'CEOF'\n{c_peek}\nCEOF")
        out, rc = run_cmd(sb, "gcc -o /tmp/ptrace_peek /tmp/ptrace_peek.c 2>&1")
        if rc != 0:
            print(f"    compile failed: {out}")
        else:
            out, rc = run_cmd(sb, "/tmp/ptrace_peek 2>&1")
            print(f"    exit={rc}")
            print(f"    output:\n{_indent(out)}\n")

        # Test 5: Check /proc/sys/kernel/yama/ptrace_scope
        print("[5] Yama ptrace_scope")
        out, rc = run_cmd(sb, "cat /proc/sys/kernel/yama/ptrace_scope 2>&1")
        print(f"    exit={rc}")
        print(f"    value: {out}\n")

        # Test 6: prctl PR_SET_PTRACER
        print("[6] prctl PR_SET_PTRACER check")
        out, rc = run_cmd(sb, """python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PR_SET_PTRACER = 0x59616d61
PR_SET_PTRACER_ANY = -1
ret = libc.prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
import ctypes
err = ctypes.get_errno()
print(f'prctl PR_SET_PTRACER_ANY: ret={ret} errno={err}')
" 2>&1""")
        print(f"    exit={rc}")
        print(f"    output: {out}\n")

        # Summary
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print("  See results above for each ptrace operation.")
        print("  If PTRACE_TRACEME/ATTACH/CONT succeed, ptrace works in gVisor.")
        print("  If they fail with EPERM or similar, gVisor blocks them.")

    finally:
        sb.terminate()
        print(f"\nSandbox terminated.")


def _indent(text, prefix="      "):
    return "\n".join(prefix + line for line in text.split("\n"))
