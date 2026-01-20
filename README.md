# agentsh + Modal: Secure AI Agent Sandbox

This project demonstrates integrating [agentsh](https://github.com/canyonroad/agentsh) v0.8.8 with [Modal Sandboxes](https://modal.com/products/sandboxes) for running AI agent code.

## Important: Modal Platform Limitations

**Modal sandboxes do not support the kernel features required for agentsh's full security interception.** While `agentsh detect` reports seccomp_user_notify as available, it fails at runtime. For full agentsh functionality, use a platform like [E2B](https://e2b.dev) that supports seccomp user notifications.

### What Works on Modal

| Feature | Status | Notes |
|---------|--------|-------|
| agentsh daemon | ✅ | Health, metrics, ready endpoints |
| Policy configuration | ✅ | Files loaded and parsed |
| Session management API | ✅ | Create, list, info via HTTP/gRPC |
| Audit logging | ✅ | Events stored in SQLite |
| DLP patterns | ✅ | API key redaction configured |
| Modal native isolation | ✅ | Metadata blocked, container isolation |

### What Doesn't Work on Modal

| Feature | Requires | Modal Support | Impact |
|---------|----------|---------------|--------|
| **agentsh exec** | `SECCOMP_RET_USER_NOTIF` | ❌ | Cannot execute commands through agentsh |
| **Shell shim** | `SECCOMP_RET_USER_NOTIF` | ❌ | Cannot intercept shell commands |
| **FUSE filesystem** | `CAP_SYS_ADMIN` + mount | ❌ | Cannot intercept file operations |
| **iptables/netfilter** | `CAP_NET_ADMIN` | ❌ | Cannot intercept network calls |

### Why These Limitations Exist: gVisor Runtime

Modal sandboxes run on **[gVisor](https://gvisor.dev/)**, a user-space kernel that intercepts syscalls for security isolation:

```
MODAL_FUNCTION_RUNTIME=gvisor
```

Key limitation: gVisor reports seccomp_user_notify as available during detection, but fails at runtime:
```
install seccomp filter: seccomp API version 2 lacks user notify
agentsh: command failed
```

## Quick Start

```bash
# Install dependencies
pip install modal

# Authenticate with Modal
modal setup

# Run capability detection
modal run detect.py

# Run the test suite
modal run tests.py

# Run the full demo
modal run example.py
```

## Test Results

The test suite (`tests.py`) runs **13 tests** showing what works:

```
======================================================================
  DAEMON & API TESTS
======================================================================
    ✓ Health endpoint: PASS
    ✓ Ready endpoint: PASS
    ✓ Metrics endpoint: PASS
    ✓ Policy list: PASS
    ✓ Server info: PASS

======================================================================
  SESSION MANAGEMENT TESTS
======================================================================
    ✓ Session created: session-xxx...
    ✓ Session info retrieved

======================================================================
  MODAL NATIVE ISOLATION TESTS
======================================================================
    ✓ AWS metadata blocked
    ✓ No docker socket
    ✓ No host filesystem
    ✓ Container runs as root
    ✓ Git available
    ✓ Python available

======================================================================
  AGENTSH EXEC LIMITATION
======================================================================
    ⚠️  agentsh exec: Not available (seccomp limitation)

======================================================================
  SUMMARY: 13 passed, 0 failed
======================================================================
```

## Files

| File | Description |
|------|-------------|
| `example.py` | Full demo showing Modal + agentsh capabilities |
| `tests.py` | Test suite verifying what works on Modal |
| `detect.py` | Runs `agentsh detect` inside Modal sandbox |
| `config.yaml` | agentsh server configuration |
| `default.yaml` | Security policy rules (loaded but not enforced without exec) |

## Architecture on Modal

```
┌─────────────────────────────────────────────────────────────────┐
│                   Modal Sandbox (gVisor runtime)                 │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  agentsh daemon v0.8.8 (port 18080)                       │  │
│  │  • Health/ready endpoints                                 │  │
│  │  • Metrics (Prometheus format)                            │  │
│  │  • Session management API                                 │  │
│  │  • Policy configuration loaded                            │  │
│  │  • DLP patterns ready                                     │  │
│  │                                                           │  │
│  │  ⚠️  agentsh exec NOT working (gVisor seccomp limitation) │  │
│  │  ⚠️  Shell shim NOT active (same limitation)              │  │
│  │  ⚠️  FUSE filesystem NOT active (gVisor blocks mount)     │  │
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

## Configuration

### config.yaml

The server configuration is optimized for Modal's environment:

```yaml
# Key settings for Modal
sandbox:
  enabled: true
  allow_degraded: true
  seccomp:
    enabled: false  # Doesn't work at runtime on Modal
  fuse:
    enabled: false
  cgroups:
    enabled: false
```

### default.yaml Policy

Policy rules are loaded but only enforced when commands go through `agentsh exec`:

```yaml
command_rules:
  - name: block-container-escape
    commands: [sudo, su, chroot, nsenter, docker, podman]
    decision: deny

  - name: block-rm-recursive
    commands: [rm]
    args_patterns: [".*-r.*", ".*--recursive.*"]
    decision: deny

  - name: block-network-tools
    commands: [nc, netcat, socat, telnet, ssh]
    decision: deny

network_rules:
  - name: block-cloud-metadata
    cidrs: ["169.254.169.254/32"]
    decision: deny

  - name: allow-package-registries
    domains: ["registry.npmjs.org", "pypi.org", "crates.io"]
    decision: allow
```

## Alternatives for Full agentsh Support

For full agentsh functionality (command interception, file monitoring, network filtering):

### E2B (Recommended)

[E2B](https://e2b.dev) sandboxes support seccomp_user_notify:

```typescript
import { Sandbox } from 'e2b'
const sbx = await Sandbox.create('e2b-agentsh')
// Full agentsh exec and shim work!
```

### Docker with --privileged

```bash
docker run --privileged -it agentsh-image
```

### Full VM (EC2, GCE, etc.)

Running on a full VM gives complete control over kernel features.

## Use Cases for Modal + agentsh

Even with limitations, this setup is useful for:

1. **Testing agentsh configuration** - Validate policy syntax before deploying
2. **Daemon API development** - Test agentsh HTTP/gRPC APIs
3. **DLP pattern testing** - Verify regex patterns for sensitive data detection
4. **CI/CD validation** - Ensure agentsh installs and starts correctly
5. **Session management testing** - Test session create/list/info workflows

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

### Test session creation

```python
p = sb.exec("agentsh", "session", "create", "--workspace", "/root", "--json")
p.wait()
print(p.stdout.read())  # Returns session JSON
```

## License

MIT License - See LICENSE file for details.

## Links

- [agentsh](https://github.com/canyonroad/agentsh) - Runtime security for AI agents
- [Modal](https://modal.com) - Serverless cloud platform
- [Modal Sandboxes](https://modal.com/products/sandboxes) - Isolated container execution
- [E2B](https://e2b.dev) - Cloud sandboxes with full seccomp support
- [gVisor](https://gvisor.dev/) - User-space kernel used by Modal for isolation
