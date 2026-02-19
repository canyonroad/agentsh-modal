# agentsh + Modal Sandboxes

Integration of [agentsh](https://github.com/canyonroad/agentsh) (v0.10.0) with [Modal Sandboxes](https://modal.com/products/sandboxes) for running AI agent code securely.

## Quick Start

```bash
pip install modal
modal setup

# Run capability detection
modal run detect.py

# Run the full security test suite
modal run tests.py

# Run the example demo
modal run example.py
```

## Current Status

**agentsh detection reports 100% protection score** inside Modal sandboxes (`agentsh detect` shows `Security Mode: full`). However, two critical kernel features fail at runtime due to Modal's gVisor application kernel, preventing enforcement of file-level and command-level security policies.

### What Works

| Feature | Status | Details |
|---------|--------|---------|
| agentsh daemon | **Working** | HTTP API on port 18080, health/ready/metrics endpoints |
| Session management | **Working** | Create, list, info via HTTP API |
| Policy configuration | **Working** | File rules, command rules, network rules loaded and parsed |
| Audit logging | **Working** | Events stored in SQLite |
| DLP patterns | **Working** | Regex-based API key / credential redaction |
| Network proxy | **Working** | Embedded proxy with domain/CIDR rules |
| Modal native isolation | **Working** | Cloud metadata blocked, no Docker socket, isolated filesystem |

### What Doesn't Work (gVisor Limitations)

| Feature | Requires | gVisor Behavior | Impact |
|---------|----------|-----------------|--------|
| **FUSE filesystem** | `fusermount3` / mount | `/dev/fuse` opens but mount returns `EPERM` | No file-level policy enforcement |
| **seccomp_user_notify** | `SECCOMP_GET_NOTIF_SIZES` | Returns `EINVAL` (errno 22) | No `agentsh exec`, no shell shim |
| **Shell shim** | seccomp_user_notify | Not functional | No command interception |
| **agentsh exec** | seccomp_user_notify | Not functional | Cannot execute commands through agentsh |

### Security Gap Summary

Without FUSE and seccomp_user_notify, the following security policies are **configured but not enforced**:

- **File policies**: Writes to `/etc`, `/usr/bin`, `/var` succeed despite deny rules
- **Command blocking**: `sudo`, `su`, `kill`, `chroot` all execute normally
- **Multi-context command blocking**: Commands via `env`, `xargs`, `find -exec`, Python subprocess are not intercepted
- **Bash builtin blocking**: `kill`, `enable`, `ulimit` builtins bypass any policy
- **Process protection**: `kill -9 1` terminates the sandbox (would be blocked by shell shim)

## Diagnostic Evidence

### gVisor Runtime Detection

Modal sandboxes run on [gVisor](https://gvisor.dev/), a user-space application kernel:

```
MODAL_FUNCTION_RUNTIME=gvisor
```

The emulated kernel version is 4.4.0:

```
Linux version 4.4.0 (SANDBOX)
```

### FUSE Failure

`/dev/fuse` device exists and can be opened, but the mount syscall is blocked:

```
$ ls -la /dev/fuse
crw-rw-rw- 1 root root 10, 229 ... /dev/fuse

$ python3 -c "import os; fd = os.open('/dev/fuse', os.O_RDWR); print(f'fd={fd}'); os.close(fd)"
fd=3

$ fusermount3 ...
fusermount3: mount failed: Operation not permitted
```

The agentsh server log confirms:
```
/usr/bin/fusermount3: mount failed: Operation not permitted
```

### seccomp_user_notify Failure

`agentsh detect` reports seccomp_user_notify as available (the feature flag check passes), but the actual API call fails:

```python
import ctypes, ctypes.util, os

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
SYS_seccomp = 317  # x86_64
SECCOMP_GET_NOTIF_SIZES = 3

ret = libc.syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, 0)
errno = ctypes.get_errno()
# ret=-1, errno=22 (Invalid argument)
```

The `agentsh detect` check is lighter than actual runtime usage, causing a false positive — it reports the feature as available, but it fails when agentsh attempts to install a seccomp filter with `SECCOMP_RET_USER_NOTIF`.

## Test Suite

The test suite (`tests.py`) mirrors the [Daytona integration tests](https://github.com/canyonroad/daytona-test) adapted for Modal. Tests are categorized as:

- **Pass/Fail tests**: Features that work on Modal (daemon, sessions, basic operations, native isolation)
- **Informational tests** (`expect="info"`): Features that require FUSE or shell shim — shown but not counted as pass/fail

### Test Categories

| Category | Count | Status |
|----------|-------|--------|
| Daemon & API | 5 | All pass |
| Session Management | 2 | All pass |
| Allowed Operations | 5 | All pass |
| Modal Native Isolation | 6 | All pass |
| File Access Blocking (FUSE) | ~15 | Informational — FUSE not available |
| Network Blocking (proxy) | 2 | Informational — proxy partially working |
| Blocked Commands (shell shim) | ~8 | Informational — shell shim not available |
| Multi-Context Command Blocking | ~8 | Informational — shell shim not available |
| FUSE Protection | ~14 | Informational — FUSE not available |
| agentsh exec | 1 | Informational — seccomp not available |
| Destructive Tests | 2 | Informational — `kill -9 1` crashes sandbox |

Run the full suite:

```bash
modal run tests.py
```

## Files

| File | Description |
|------|-------------|
| `tests.py` | Full security test suite (mirrors Daytona tests) |
| `example.py` | Demo showing Modal + agentsh capabilities |
| `detect.py` | Runs `agentsh detect` with comprehensive diagnostics |
| `config.yaml` | agentsh server configuration for Modal |
| `default.yaml` | Security policy (file, command, network rules) |
| `detect_docker.py` | Detection with `enable_docker` runtime option |
| `detect_dind.py` | Detection with Docker-in-Docker setup |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│               Modal Sandbox (gVisor runtime)                  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  agentsh daemon v0.10.0 (port 18080)                    │ │
│  │                                                         │ │
│  │  ✅ Working:                                            │ │
│  │    • HTTP API (health, ready, metrics, info, policies)  │ │
│  │    • Session management (create, list, info)            │ │
│  │    • Policy engine (loaded, parsed)                     │ │
│  │    • Audit logging (SQLite)                             │ │
│  │    • DLP patterns (API key redaction)                   │ │
│  │    • Network proxy (embedded, domain filtering)         │ │
│  │                                                         │ │
│  │  ❌ Not working (gVisor blocks):                        │ │
│  │    • FUSE filesystem (mount denied)                     │ │
│  │    • seccomp_user_notify (EINVAL)                       │ │
│  │    • Shell shim (requires seccomp)                      │ │
│  │    • agentsh exec (requires seccomp)                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  gVisor provides:                                             │
│    ✅ Syscall interception (user-space kernel)                │
│    ✅ Cloud metadata blocking (169.254.169.254)               │
│    ✅ Isolated container filesystem                           │
│    ✅ No Docker socket access                                 │
│    ❌ No FUSE mount support                                   │
│    ❌ No seccomp_user_notify support                          │
└──────────────────────────────────────────────────────────────┘
```

## Asks for Modal

To enable full agentsh security enforcement on Modal sandboxes, the following gVisor runtime capabilities are needed. These are both supported features within gVisor but appear to be disabled or restricted in Modal's configuration.

### 1. Enable FUSE (Filesystem in Userspace)

**What**: Allow `fusermount3` / the `mount` syscall for FUSE filesystems inside sandboxes.

**Current behavior**: `/dev/fuse` exists and can be opened (`O_RDWR`), but `mount()` returns `EPERM`.

**What this enables for agentsh**:
- VFS-level file policy enforcement — intercept all file reads/writes/creates/deletes
- Deny writes to system paths (`/etc`, `/usr/bin`, `/var`)
- Soft-delete (quarantine) for workspace files
- Block access to `/etc/shadow`, `/proc/1/environ`, and other sensitive files
- File audit logging at the filesystem level

**gVisor support**: gVisor documents FUSE support. The kernel has `mount` listed as "Full Support" in the [gVisor syscall reference](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/). FUSE support may need to be enabled via gVisor's `--fuse` flag or equivalent OCI runtime option.

**Possible gVisor configurations**:
- Enable the `fuse` option in the gVisor OCI spec (`runtimeArgs` or `features`)
- Allow `CAP_SYS_ADMIN` scoped to FUSE mount operations only
- Alternatively, expose a pre-mounted FUSE filesystem or a bind-mount mechanism

### 2. Enable seccomp_user_notify (Seccomp User-Space Notification)

**What**: Allow the `seccomp()` syscall with `SECCOMP_RET_USER_NOTIF` action and `SECCOMP_GET_NOTIF_SIZES` operation.

**Current behavior**: `seccomp(SECCOMP_GET_NOTIF_SIZES)` returns `-1` with `errno=22` (`EINVAL`). The seccomp filter installation with `SECCOMP_RET_USER_NOTIF` also fails.

**What this enables for agentsh**:
- **Shell shim**: Replace `/bin/bash` to intercept all command executions
- **agentsh exec**: Route all process execution through agentsh policy engine
- Command blocking (deny `sudo`, `su`, `kill`, `chroot`, `docker`, `nsenter`)
- Depth-aware policy enforcement (allow `curl` directly, require approval when nested in scripts)
- Multi-context command interception (commands via `env`, `xargs`, `find -exec`, Python `subprocess`)
- Bash builtin blocking (prevent `kill`, `enable`, `ulimit` bypass of seccomp)
- Process protection (block `kill -9 1` which currently crashes the sandbox)

**gVisor support**: gVisor's [compatibility documentation](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/) lists `seccomp` as having "Full Support". The `SECCOMP_RET_USER_NOTIF` action was added to Linux 5.0. gVisor may need to enable this specific action type, as it appears the basic seccomp filter mechanism works but the user notification variant is not enabled.

**Possible gVisor configurations**:
- Enable `SECCOMP_RET_USER_NOTIF` in gVisor's seccomp emulation
- This may require gVisor version updates or configuration changes in the OCI runtime spec

### 3. Alternative: Provide a Non-gVisor Runtime Option

If enabling FUSE and seccomp_user_notify within gVisor is not feasible, an alternative would be to offer a sandbox runtime option that uses a standard Linux kernel instead of gVisor. This could be:

- A VM-based sandbox option (e.g., Firecracker, Cloud Hypervisor)
- A container runtime with a real kernel (e.g., standard runc with seccomp profiles)
- The existing `enable_docker=True` experimental option (currently does not change gVisor behavior for these features)

### Impact Summary

| Capability | Tests Affected | Security Features Unlocked |
|-----------|---------------|---------------------------|
| FUSE mount | ~15 tests | File policy enforcement, quarantine, audit |
| seccomp_user_notify | ~10 tests | Command blocking, shell shim, exec interception |
| **Both combined** | **~25 tests** | **Full agentsh protection (100% enforced)** |

With both features enabled, Modal sandboxes would achieve parity with the [Daytona integration](https://github.com/canyonroad/daytona-test) where all 35+ security tests pass.

## Configuration

### config.yaml

Key settings for the Modal environment:

```yaml
sandbox:
  enabled: true
  allow_degraded: true  # Start even if FUSE/seccomp fail

  seccomp:
    file_monitor:
      enabled: true
      enforce_without_fuse: true   # Try file monitoring without FUSE
      audit_under_fuse: true

  fuse:
    enabled: true
    deferred: true                            # Wait for marker file
    deferred_marker_file: "/tmp/.agentsh-fuse-enabled"
    deferred_enable_command: ["/bin/chmod", "666", "/dev/fuse"]

  network:
    enabled: true
    intercept_mode: "all"

  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
```

### default.yaml Policy

Comprehensive security policy with:
- **File rules**: Workspace read/write, tmp access, deny system paths, approve credential access
- **Command rules**: Safe command allowlist, block privilege escalation, git safety, depth-aware curl/wget
- **Network rules**: Allow package registries and code hosting, block cloud metadata, block private networks
- **Environment policy**: Allowlist essential vars, deny secrets
- **Resource limits**: Memory, CPU, PID, disk I/O caps

## Comparison: Modal vs Daytona

| Feature | Modal (gVisor) | Daytona |
|---------|---------------|---------|
| agentsh daemon | ✅ | ✅ |
| Session management | ✅ | ✅ |
| Network proxy | ✅ | ✅ |
| DLP / audit | ✅ | ✅ |
| FUSE file enforcement | ❌ (mount denied) | ✅ |
| Shell shim | ❌ (no seccomp_user_notify) | ✅ |
| agentsh exec | ❌ (no seccomp_user_notify) | ✅ |
| Command blocking | ❌ | ✅ |
| File write blocking | ❌ | ✅ |
| kill -9 1 protection | ❌ (crashes sandbox) | ✅ (blocked) |
| **Protection score** | **~40% enforced** | **100% enforced** |

## Links

- [agentsh](https://github.com/canyonroad/agentsh) — Runtime security for AI agents
- [Modal Sandboxes](https://modal.com/products/sandboxes) — Serverless container execution
- [gVisor](https://gvisor.dev/) — Application kernel used by Modal
- [gVisor syscall compatibility](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/) — Syscall support reference
