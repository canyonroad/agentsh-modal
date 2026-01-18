# agentsh + Modal: Secure AI Agent Sandbox

This project explores integrating [agentsh](https://github.com/canyonroad/agentsh) with [Modal Sandboxes](https://modal.com/products/sandboxes) for running AI agent code.

## Important: Modal Platform Limitations

**Modal sandboxes do not support the kernel features required for agentsh's full security interception.** This is documented here for reference. For full agentsh functionality, use a platform that supports seccomp user notifications.

### What Works on Modal

| Feature | Status | Notes |
|---------|--------|-------|
| agentsh daemon | ✅ | Health, metrics, ready endpoints |
| Policy configuration | ✅ | Files loaded and parsed |
| Session management API | ✅ | Available via HTTP/gRPC |
| Audit logging | ✅ | Events stored in SQLite |
| DLP patterns | ✅ | API key redaction configured |

### What Doesn't Work on Modal

| Feature | Requires | Modal Support | Impact |
|---------|----------|---------------|--------|
| **Shell shim** | `SECCOMP_RET_USER_NOTIF` | ❌ | Cannot intercept shell commands |
| **FUSE filesystem** | `CAP_SYS_ADMIN` + mount | ❌ | Cannot intercept file operations |
| **iptables/netfilter** | `CAP_NET_ADMIN` | ❌ | Cannot intercept network calls |
| **Transparent proxy** | iptables REDIRECT | ❌ | Cannot force traffic through proxy |

### Why These Limitations Exist: gVisor Runtime

Modal sandboxes run on **[gVisor](https://gvisor.dev/)**, a user-space kernel that intercepts syscalls for security isolation. This is visible in the environment:

```
MODAL_FUNCTION_RUNTIME=gvisor
```

gVisor intentionally doesn't implement many kernel features that agentsh requires:

1. **Seccomp user notifications** - gVisor doesn't support `SECCOMP_RET_USER_NOTIF`. Error: `seccomp API version 2 lacks user notify`

2. **FUSE mounts** - gVisor intercepts file operations itself; allowing FUSE would bypass its isolation. Error: `fusermount: mount failed: Operation not permitted`

3. **mount() syscall** - `CAP_SYS_ADMIN` is not granted. Error: `mount: /mnt: permission denied`

4. **iptables/netfilter** - gVisor doesn't implement netfilter. Error: `iptables: Failed to initialize nft: Protocol not supported`

5. **New namespaces** - Network and PID namespace creation blocked. Error: `unshare failed: Operation not permitted`

These are fundamental architectural decisions in gVisor, not configuration options.

### Can You Install FUSE/Other Packages?

**Yes, packages install fine. No, they won't work at runtime.**

| Package | Installs? | Works? | Error |
|---------|-----------|--------|-------|
| fuse3, libfuse3-dev | ✅ | ❌ | `mount failed: Operation not permitted` |
| bindfs, sshfs | ✅ | ❌ | `mount failed: Operation not permitted` |
| iptables | ✅ | ❌ | `Protocol not supported` |
| kmod (modprobe) | ✅ | ❌ | No `/proc/modules` |
| util-linux (unshare) | ✅ | ❌ | `Operation not permitted` (net/pid ns) |

The `/dev/fuse` device exists and FUSE is in `/proc/filesystems`, but the actual `mount()` syscall is blocked by gVisor. **Installing different packages cannot work around kernel-level restrictions.**

### What Does Work in gVisor

| Feature | Status | Notes |
|---------|--------|-------|
| User namespace | ✅ | `unshare --user` works |
| Network inspection | ✅ | `ip link`, `ip route` work |
| Cgroups visibility | ✅ | Can read `/sys/fs/cgroup/` |
| Process capabilities | ✅ | `capsh --print` works |
| Basic syscalls | ✅ | File I/O, networking, etc. |

## What Modal Does Provide

Modal sandboxes have their own isolation that provides some security:

| Security Feature | Status | Details |
|------------------|--------|---------|
| Cloud metadata blocked | ✅ | 169.254.169.254 times out |
| Container isolation | ✅ | Separate PID/network/mount namespaces |
| No Docker socket | ✅ | `/var/run/docker.sock` doesn't exist |
| No host filesystem | ✅ | Isolated root filesystem |
| Resource limits | ✅ | CPU, memory, timeout limits |

## Quick Start

```bash
# Install dependencies
pip install modal

# Authenticate with Modal
modal setup
# Or set environment variables:
# export MODAL_TOKEN_ID=<your-token-id>
# export MODAL_TOKEN_SECRET=<your-token-secret>

# Run the demo
modal run example.py
```

## Test Results

The demo runs **17 tests** showing what works:

```
======================================================================
  Modal Native Network Isolation
======================================================================
[TEST] AWS metadata blocked (Modal)     -> [PASS] (timeout)
[TEST] GCP metadata blocked (Modal)     -> [PASS] (timeout)
[TEST] Public HTTPS works               -> [PASS] (HTTP/2 200)
[TEST] Public HTTP works                -> [PASS] (HTTP/1.1 200)

======================================================================
  agentsh Daemon (Control API)
======================================================================
[TEST] agentsh health check             -> [PASS] (ok)
[TEST] agentsh metrics endpoint         -> [PASS] (metrics returned)
[TEST] agentsh ready check              -> [PASS] (ready)

======================================================================
  Basic Sandbox Operations
======================================================================
[TEST] Basic echo                       -> [PASS]
[TEST] List files                       -> [PASS]
[TEST] Git version                      -> [PASS] (git 2.39.5)
[TEST] Python version                   -> [PASS] (Python 3.11.12)
[TEST] agentsh binary                   -> [PASS] (agentsh 0.7.9)
[TEST] Policy file loaded               -> [PASS]

======================================================================
  Modal Container Isolation
======================================================================
[TEST] Running as root                  -> [PASS] (isolated root)
[TEST] No docker socket                 -> [PASS]
[TEST] No host PID namespace            -> [PASS]
[TEST] Isolated filesystem              -> [PASS]

======================================================================
  SUMMARY: 17 passed, 0 failed
======================================================================
```

## Architecture on Modal

```
┌─────────────────────────────────────────────────────────────────┐
│                   Modal Sandbox (gVisor runtime)                 │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  agentsh daemon (port 18080)                              │  │
│  │  • Health/ready endpoints                                 │  │
│  │  • Metrics (Prometheus format)                            │  │
│  │  • Session management API                                 │  │
│  │  • Policy configuration loaded                            │  │
│  │  • DLP patterns ready                                     │  │
│  │                                                           │  │
│  │  ⚠️  Shell shim NOT active (gVisor lacks seccomp notify)  │  │
│  │  ⚠️  FUSE filesystem NOT active (gVisor blocks mount)     │  │
│  │  ⚠️  iptables NOT active (gVisor lacks netfilter)         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  gVisor Isolation:                                               │
│  ✅ User-space kernel intercepts syscalls                       │
│  ✅ Cloud metadata blocked (169.254.169.254)                    │
│  ✅ Isolated container filesystem                                │
│  ✅ Separate PID namespace                                       │
│  ✅ No Docker socket access                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `example.py` | Demo script showing what works on Modal |
| `config.yaml` | agentsh server configuration |
| `default.yaml` | Security policy rules (loaded but not enforced without shim) |

## Alternatives for Full agentsh Support

For full agentsh functionality (command interception, file monitoring, network filtering), you need a platform that provides:

- **Seccomp user notifications** (`SECCOMP_RET_USER_NOTIF`) - for command interception
- **FUSE support** (`CAP_SYS_ADMIN` + mount) - for file operation monitoring
- **Network capabilities** (`CAP_NET_ADMIN`) - for network filtering

### Docker with --privileged

```bash
docker run --privileged -it agentsh-image
```

Gives full access to kernel features but reduces isolation.

### Full VM (EC2, GCE, etc.)

Running on a full VM gives complete control over kernel features.

## Policy Configuration (Reference)

The policy files are included for reference. They would be enforced if running on a platform that supports agentsh's interception features.

### Command Rules (default.yaml)

```yaml
command_rules:
  - name: block-container-escape
    commands: [sudo, su, chroot, nsenter, unshare, docker, podman]
    decision: deny

  - name: block-rm-recursive
    commands: [rm]
    args_patterns: ["*-rf*", "*-r*"]
    decision: deny

  - name: block-network-tools
    commands: [nc, netcat, socat, telnet, ssh]
    decision: deny
```

### Network Rules (default.yaml)

```yaml
network_rules:
  - name: block-cloud-metadata
    cidrs: ["169.254.169.254/32"]
    decision: deny

  - name: block-private-networks
    cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    decision: deny

  - name: allow-package-registries
    domains: ["registry.npmjs.org", "pypi.org", "crates.io"]
    decision: allow
```

### File Rules (default.yaml)

```yaml
file_rules:
  - name: approve-ssh-access
    paths: ["${HOME}/.ssh/**"]
    decision: approve
    message: "Agent wants to access SSH keys"

  - name: soft-delete-workspace
    paths: ["${PROJECT_ROOT}/**"]
    operations: [delete]
    decision: soft_delete
```

## Use Cases for Modal + agentsh

Even with limitations, this setup can be useful for:

1. **Testing agentsh configuration** - Validate policy syntax before deploying
2. **Daemon API development** - Test agentsh HTTP/gRPC APIs
3. **DLP pattern testing** - Verify regex patterns for sensitive data detection
4. **CI/CD validation** - Ensure agentsh installs and starts correctly

## Troubleshooting

### Check agentsh daemon status

```python
p = sb.exec("curl", "-s", "http://127.0.0.1:18080/health")
p.wait()
print(p.stdout.read())  # Should print "ok"
```

### View agentsh logs

```python
p = sb.exec("cat", "/var/log/agentsh/agentsh.log")
p.wait()
print(p.stdout.read())
```

### Verify policy loaded

```python
p = sb.exec("cat", "/etc/agentsh/policies/default.yaml")
p.wait()
print(p.stdout.read())
```

## License

MIT License - See LICENSE file for details.

## Links

- [agentsh](https://github.com/canyonroad/agentsh) - Runtime security for AI agents
- [Modal](https://modal.com) - Serverless cloud platform
- [Modal Sandboxes](https://modal.com/products/sandboxes) - Isolated container execution
- [Modal Docs](https://modal.com/docs/guide/sandboxes) - Sandbox documentation
- [gVisor](https://gvisor.dev/) - User-space kernel used by Modal for isolation
