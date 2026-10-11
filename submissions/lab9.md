# Lab 9 — Runtime Detection and Policy as Code

Falco 0.43.1 (modern eBPF), Conftest 0.71.0 / OPA 1.21.
> Kernel note: macOS has no host Linux kernel. Falco ran against a Linux kernel via Docker Desktop's VM and (for the network bonus) Colima. On both, syscall/file/exec events are captured, but the per-syscall `sys_enter_connect` tracepoint cannot be attached, so a `connect` event's socket tuple (`fd.sport`, `fd.rip`, `fd.rport`) comes back `<NA>` — see the bonus.

## Task 1

### The two built-in rules (9.2)
`docker exec -t ... sh` and `cat /etc/shadow` triggered:

**Terminal shell in container** (Notice) — a shell with a TTY attached was spawned in a container:
```
Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root
process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell
terminal=34816 container_id=6a4af8dfa67b container_name=lab9-target container_image=alpine:3.20
```
Triggered by the interactive `docker exec -t` (the rule keys on `proc.tty != 0`).

**Read sensitive file untrusted** (Warning) — a non-trusted program read a sensitive file:
```
Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow evt_type=openat
user=root process=cat proc_exepath=/bin/busybox command=cat /etc/shadow container_id=6a4af8dfa67b
container_name=lab9-target container_image=alpine:3.20
```
Triggered by `cat /etc/shadow` (the rule keys on an `open_read` of a sensitive-file path by a non-allowlisted program).

### My custom rule (9.3)
```yaml
- rule: Write to /tmp in a container
  desc: Detect any file opened for writing under /tmp from inside a container (drift)
  condition: >
    open_write and container.id != "host" and fd.name startswith /tmp/
  output: >
    Write under /tmp in container
    (container=%container.name id=%container.id user=%user.name
     file=%fd.name proc=%proc.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```
After `SIGHUP` reload, `echo test > /tmp/my-write.txt` fired it exactly once:
```json
{"priority":"Warning","rule":"Write to /tmp in a container","source":"syscall",
 "tags":["container","drift"],"time":"2026-10-11T15:29:57.661Z",
 "output":"Write under /tmp in container (container=lab9-target id=6a4af8dfa67b user=root
  file=/tmp/my-write.txt proc=sh cmdline=sh -lc echo test > /tmp/my-write.txt) ...",
 "output_fields":{"container.id":"6a4af8dfa67b","container.image.repository":"alpine",
  "container.image.tag":"3.20","fd.name":"/tmp/my-write.txt","proc.cmdline":"sh -lc echo test > /tmp/my-write.txt",
  "proc.name":"sh","user.name":"root"}}
```

### An incident-relevant field not in the human message
`container.image.repository` + `container.image.tag` (here `alpine:3.20`). The human line names the container and process, but during an incident the **image** is what tells you *what is actually running* in that container — whether it's the expected workload or an attacker's image — and lets you scope every other container built from the same image. It's in `output_fields` but not in the rendered message.

### False positive and tuning
This rule fires on **every** `/tmp` write in **every** container, and writing to `/tmp` is completely normal: package managers, language runtimes (Python's `tempfile`, Node), nginx's `client_body_temp`, and the Juice Shop app itself all write scratch files to `/tmp`. So a routine CI build container or the app under normal load would flood this rule. To keep the detection but drop the noise I would narrow the *what* rather than suppress the *where*: alert only on writes of **executable or script files** under `/tmp` (e.g. `fd.name` ending in `.sh`/`.py` or files later made executable), or exclude known-good `(container.image, proc.name)` pairs via a macro/list, rather than every write. That keeps the interesting signal — an attacker staging a payload in `/tmp` — while ignoring ordinary temp I/O.

## Task 2

### Counts
| Manifest | Pass | Warn | Fail |
|----------|-----:|-----:|-----:|
| `juice-hardened.yaml` (shipped policy) | 30 | 0 | 0 |
| `juice-hardened.yaml` (+ my extra policy) | 34 | 0 | 0 |
| `juice-unhardened.yaml` | 20 | 2 | 8 |
| `compose/juice-compose.yml` | 15 | 0 | 0 |

Two failures mapped to their Rego rules in `k8s-security.rego`:
- *"container "juice" must set readOnlyRootFilesystem: true"* → the `deny` rule `not c.securityContext.readOnlyRootFilesystem == true`.
- *"container "juice" uses disallowed :latest tag"* → the `deny` rule `endswith(c.image, ":latest")`.

### Compose vs Kubernetes, and the passing file
The same requirement needs a separate rule per tool because the **documents have different shapes**: a Rego rule walks a concrete path, and in Kubernetes "read-only root" lives at `spec.template.spec.containers[].securityContext.readOnlyRootFilesystem`, while in Compose it's `services.<name>.read_only` — different keys, different nesting, so one rule cannot match both. The Compose file **passing all 15** is the useful negative control: it proves the policy set actually distinguishes compliant from non-compliant input (a suite that only ever fails tells you nothing), and that this Compose file already meets its policy's bar while the unhardened K8s manifest did not.

### My policy and the violating manifest
`labs/lab9/policies/extra/hardening.rego`:
```rego
package k8s.security

# DENY: images must be pinned by digest, never a mutable tag
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  indexof(c.image, "@sha256:") == -1
  msg := sprintf("container %q image must be pinned by digest (@sha256:), not a tag", [c.name])
}

# WARN: every container should declare a containerPort
warn contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.ports
  msg := sprintf("container %q should declare a containerPort", [c.name])
}
```
Both **pass** on `juice-hardened.yaml` (digest-pinned image, declares `ports`) — `34 tests, 34 passed`. My `violates-my-policy.yaml` (image pinned by a *tag* `:v20.0.0`, no `ports`, otherwise fully hardened so only my rules fire):
```
WARN - container "juice" should declare a containerPort
FAIL - container "juice" image must be pinned by digest (@sha256:), not a tag
17 tests, 15 passed, 1 warning, 1 failure
```

### CI vs runtime for this control
For digest-pinning I'd keep the **Conftest/CI** check: it's a deploy-time property of the manifest, so catching it before admission is cheaper, earlier and deterministic — the bad image never runs. Falco can't meaningfully enforce "pinned by digest" at runtime anyway. But the runtime layer still buys what CI can't see: it catches manifests that **bypass CI** (someone `kubectl apply`-ing by hand, or a tag repointed *after* admission to a different image — the Lab 8 attack), and it observes actual behaviour (syscalls, connections) that no static manifest check can predict. CI prevents the known-bad config; Falco detects the unknown-bad action.

## Bonus — catch a cryptominer

```yaml
- rule: Likely cryptominer outbound connection
  desc: Combines a completed outbound connect with a suspicious process identity in a container.
  condition: >
    evt.type = connect and container.id != "host"
    and proc.name in (xmrig, minerd, cpuminer, cryptonight, xmr-stak, ethminer, nc, ncat, netcat)
  output: >
    Possible cryptomining connection (container=%container.name id=%container.id proc=%proc.name
    cmdline=%proc.cmdline dest=%fd.rip:%fd.rport sport=%fd.sport user=%user.name)
  priority: CRITICAL
  tags: [network, mitre_command_and_control, cryptomining]
```
`nc -w 2 127.0.0.1 3333` fired it (CRITICAL):
```json
{"priority":"Critical","rule":"Likely cryptominer outbound connection",
 "tags":["cryptomining","mitre_command_and_control","network"],
 "output":"Possible cryptomining connection (container=lab9-target id=e35086f903c5 proc=nc
  cmdline=nc -w 2 127.0.0.1 3333 dest=<NA>:<NA> sport=<NA> user=root) ...",
 "output_fields":{"container.name":"lab9-target","proc.name":"nc","proc.cmdline":"nc -w 2 127.0.0.1 3333"}}
```
The spec's example second signal is a **pool port** (`fd.sport in (3333,4444,5555,7777,14444)`); I kept it as a commented refinement because on this host `fd.sport`/`fd.rip` are `<NA>` (the `sys_enter_connect` tracepoint won't attach on the macOS-backed kernel, so the connect's *arguments* aren't captured — only that a connect happened and by which process). The two working signals here are **a completed outbound connect** and **a suspicious process identity**.

### Why a refused connection is enough
Falco hooks the `connect` **syscall** via eBPF, so it sees the process's *attempt to connect* the instant the kernel handles the call — it needs no successful handshake, no accepted session, and no bytes on the wire. That means Falco sits **below the network stack, at the kernel/syscall boundary**: it observes intent, not traffic, so a connection the firewall or the remote refuses is still a fully observed event.

### Cheap vs expensive to evade
Changing the **port** is *free* — one line of miner config — so a port-only signal is the weakest. Renaming the **binary** is also cheap, so a process-name list is evadable too. What's expensive to evade is the **behaviour**: a container that normally makes no outbound connections suddenly opening long-lived egress, plus sustained CPU, is hard to hide while still mining. To catch the evasion I'd add an **egress-baseline** rule (alert on *any* outbound from a container whose normal profile has none — pairs with the Lab 7 default-deny NetworkPolicy so unlisted egress is also *blocked*), and a CPU/compute heuristic, rather than relying on a fixed port or name list.
