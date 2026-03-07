# agentsh + Modal

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.14.0 with [Modal Sandboxes](https://modal.com/products/sandboxes).

## Why agentsh + Modal?

**Modal provides isolation. agentsh provides governance.**

Modal sandboxes give AI agents a secure, isolated compute environment. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently

agentsh adds the governance layer that controls what agents can do inside the sandbox, providing defense-in-depth:

```
+---------------------------------------------------------+
|  Modal Sandbox (Isolation)                              |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O is intercepted (FUSE)           |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Modal Provides | agentsh Adds |
|----------------|--------------|
| Compute isolation (gVisor) | Command blocking (shell shim) |
| Process sandboxing | File I/O policy (FUSE) |
| Sandbox API | Domain allowlist/blocklist |
| Cloud metadata blocking | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | MCP tool call security (v0.11.0) |
| | Threat intelligence feeds (v0.12.0) |
| | Package install scanning (v0.12.0) |
| | LLM request auditing |
| | Complete audit logging |

## Quick Start

```bash
pip install modal
modal setup

# Run the full security test suite
modal run tests.py

# Run the example demo
modal run example.py
```

## How It Works

Modal sandboxes use [gVisor](https://gvisor.dev/), a user-space application kernel. gVisor blocks the two kernel features agentsh needs for full enforcement (FUSE mounts and `seccomp_user_notify`), so agentsh runs in **daemon + API mode**:

```
modal.Sandbox.create()
        |
        v
+-------------------+
|  agentsh daemon   |  HTTP API on port 18080
|  (policy engine)  |  Session mgmt, audit, DLP
+--------+----------+
         |
   +-----+-----+
   v             v
Working:       Config loaded,
  Health API     not enforced:
  Sessions       FUSE file blocking
  MCP API        Shell shim
  Audit log      Command blocking
  DLP            agentsh exec
  Network proxy
```

The daemon starts, loads all policy configuration, and provides API endpoints. Features requiring FUSE or `seccomp_user_notify` are configured but cannot enforce until Modal enables those gVisor capabilities.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [FUSE settings](https://www.agentsh.org/docs/#fuse), [MCP security](https://www.agentsh.org/docs/#mcp), [env_inject](https://www.agentsh.org/docs/#shell-shim)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-modal/
├── config.yaml         # Server config (FUSE, DLP, MCP, network, threat feeds)
├── default.yaml        # Security policy (commands, network, files, env)
├── tests.py            # Full security test suite (mirrors Daytona tests)
├── example.py          # Demo showing Modal + agentsh capabilities
├── detect.py           # Runs agentsh detect with diagnostics
├── detect_docker.py    # Detection with enable_docker runtime option
└── detect_dind.py      # Detection with Docker-in-Docker setup
```

## Testing

The `tests.py` script creates a Modal sandbox and runs security tests across these categories:

- **Daemon & API** -- Health, ready, metrics endpoints
- **Session management** -- Create, info, list sessions
- **Allowed operations** -- whoami, id, ls, git, python
- **Modal native isolation** -- Metadata blocked, no docker socket, no host filesystem
- **MCP API** -- Tools and servers endpoints (v0.11.0)
- **File access** -- Workspace/tmp writes allowed; /etc, /usr/bin writes not blocked (needs FUSE)
- **Network blocking** -- Proxy-based domain filtering
- **Command blocking** -- sudo, su, kill not blocked (needs shell shim)
- **Audit logs** -- SQLite database and server log active

```bash
modal run tests.py
```

## Platform Status

| Feature | Modal | Daytona | Blocker |
|---------|-------|---------|---------|
| agentsh daemon | Working | Working | -- |
| Session management | Working | Working | -- |
| MCP API (v0.11.0) | Working | Working | -- |
| Network proxy | Working | Working | -- |
| DLP / audit | Working | Working | -- |
| FUSE file enforcement | Not working | Working | gVisor blocks `mount()` |
| Shell shim | Not working | Working | gVisor blocks `seccomp_user_notify` |
| Command blocking | Not working | Working | Needs shell shim |
| agentsh exec | Not working | Working | Needs `seccomp_user_notify` |

## For Modal Engineers

Two gVisor capabilities would unlock full agentsh enforcement on Modal:

1. **FUSE mounts** -- `/dev/fuse` exists and opens, but `mount()` returns `EPERM`. Enabling FUSE would unlock VFS-level file policy enforcement (block writes to `/etc`, `/usr/bin`, quarantine, audit).

2. **`seccomp_user_notify`** -- `seccomp(SECCOMP_GET_NOTIF_SIZES)` returns `EINVAL`. Enabling this would unlock the shell shim, command blocking, `agentsh exec`, path canonicalization (v0.14.0), and transparent command unwrapping (v0.14.0).

Both are [supported by gVisor](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/) but appear disabled in Modal's configuration. With both enabled, Modal would achieve parity with the [Daytona integration](https://github.com/canyonroad/daytona-test) where all 50+ security tests pass.

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [agentsh + Daytona](https://github.com/canyonroad/daytona-test) -- agentsh integration with Daytona sandboxes
- [agentsh + E2B](https://github.com/canyonroad/e2b-agentsh) -- agentsh integration with E2B sandboxes

## License

MIT
