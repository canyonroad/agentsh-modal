# agentsh + Modal

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.16.8 with [Modal Sandboxes](https://modal.com/products/sandboxes).

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
|  |  |  - DNS queries filtered by domain name      |  |  |
|  |  |  - Commands intercepted (ptrace execve)     |  |  |
|  |  |  - File I/O intercepted (ptrace openat)     |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Modal Provides | agentsh Adds |
|----------------|--------------|
| Compute isolation (gVisor) | DNS domain-name filtering (ptrace) |
| Process sandboxing | Command blocking (ptrace execve) |
| Sandbox API | File access control (ptrace openat) |
| Cloud metadata blocking | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | DNS redirect rules |
| | MCP tool call security |
| | Threat intelligence feeds |
| | Package install scanning |
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

Modal sandboxes use [gVisor](https://gvisor.dev/), a user-space application kernel. Previous versions of agentsh required FUSE mounts and `seccomp_user_notify` which gVisor blocks. **agentsh v0.16+ uses ptrace-based enforcement** which works natively on gVisor:

```
modal.Sandbox.create()
        |
        v
+-------------------+
|  agentsh daemon   |  HTTP API on port 18080
|  (policy engine)  |  Session mgmt, audit, DLP
+--------+----------+
         |
   ptrace tracer
   (v0.16.8)
         |
   +-----+------+
   v      v      v
 execve  openat  connect/sendto
 (cmds)  (files) (network + DNS)
```

The ptrace tracer attaches to child processes and intercepts syscalls:
- **execve** — command allow/deny (blocks sudo, docker, nsenter, etc.)
- **openat** — file access control (workspace allowed, /etc writes denied)
- **connect/sendto** — network filtering with built-in DNS proxy for domain-based allow/deny

### Full Protection via ptrace

On platforms with full kernel access, agentsh uses FUSE for file control and seccomp for network filtering. Modal's gVisor kernel doesn't support FUSE or seccomp user-notify — but ptrace provides **equivalent protection** by intercepting the same syscalls at the tracer level:

| Protection | FUSE / seccomp | Modal (ptrace) |
|------------|----------------|----------------|
| File reads/writes | FUSE (openat) | ptrace (openat) |
| Command execution | Shell shim (execve) | ptrace (execve) |
| DNS filtering | seccomp (connect) | ptrace (connect/sendto) |
| Network blocking | seccomp (connect) | ptrace (connect) |

Running `modal run detect.py` verifies all protections work on gVisor:

```
  ptrace enforcement:   SUPPORTED
  raw DNS resolution:   OK
  DNS allow (github):   OK        # github.com resolves
  DNS block (evil.com): OK        # evil.com → NXDOMAIN
  file allow (workspace): OK      # write /root/test.txt → success
  file deny (write /etc): OK      # write /etc/hack → EACCES
  file deny (read proc):  OK      # read /proc/1/environ → EACCES
```

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: ptrace settings, network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [MCP security](https://www.agentsh.org/docs/#mcp), [env_inject](https://www.agentsh.org/docs/#shell-shim)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), DNS redirects, [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-modal/
├── config.yaml         # Server config (ptrace, DLP, MCP, network, threat feeds)
├── default.yaml        # Security policy (commands, network, files, DNS redirects, env)
├── tests.py            # Full security test suite (ptrace enforcement)
├── example.py          # Demo showing Modal + agentsh capabilities
├── detect.py           # Ptrace probe + DNS + file access control verification
├── detect_docker.py    # Detection with enable_docker runtime option
└── detect_dind.py      # Detection with Docker-in-Docker setup
```

## Testing

The `tests.py` script creates a Modal sandbox and runs security tests across these categories:

- **Daemon & API** -- Health, ready, metrics, session management
- **Version verification** -- Confirm v0.16.8 with ptrace active
- **DNS domain-name filtering** -- Allow github.com/pypi.org, deny evil.com (by name!)
- **DNS redirect** -- redirectme.example.com → 127.0.0.1
- **Command blocking** -- sudo, docker, nsenter denied; ls, git, python allowed
- **File access control** -- Workspace/tmp writes allowed; /etc, /usr/bin writes denied
- **Network CIDR blocking** -- Private networks and metadata IPs denied
- **Audit logs** -- SQLite database and server log active

```bash
modal run tests.py
```

## Platform Status

| Feature | Status | Mechanism |
|---------|--------|-----------|
| agentsh daemon | Working | HTTP API |
| Session management | Working | -- |
| DNS domain filtering | **Working** | ptrace connect/sendto + DNS proxy |
| DNS redirect | **Working** | ptrace DNS proxy |
| Command blocking | **Working** | ptrace execve |
| File access control | **Working** | ptrace openat |
| Network CIDR blocking | Working | ptrace connect |
| DLP / audit | Working | LLM proxy |
| MCP API | Working | -- |

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))

## License

MIT
