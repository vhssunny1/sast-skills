# Linux / VPS Deployment Guide

Step-by-step setup for running the SAST pipeline headlessly on a fresh Linux box (tested on
a 1vCPU/2GB Ubuntu 20.04 droplet) via the CLI harness — no web server, no browser, no login
page. Every step below was actually run and verified on a real fresh VPS; the troubleshooting
section documents real failures hit along the way, not hypothetical ones.

## 1. Prerequisites check

```bash
lsb_release -a          # OS/version
df -h /                 # disk — need a few GB free; Joern's archive alone is ~2GB downloaded
                         #   + ~2.6GB extracted, so budget ~5GB free before installing it
free -h                  # RAM — Joern (JVM-based) is memory-hungry; 2GB total is workable but tight
gcc --version             # needed for tree-sitter grammar compilation — ships by default on most distros
git --version
```

If disk is tight, safe cleanup targets on a long-lived box:
```bash
journalctl --vacuum-size=200M   # systemd journal logs often balloon to several GB
apt-get clean                    # apt package cache
truncate -s 0 /var/log/btmp /var/log/btmp.1 /var/log/wtmp /var/log/wtmp.1   # stale login logs
```

## 2. Get the project onto the box

Either `git clone` your fork of this repo, or copy it from a working machine:

```bash
# from your local machine, excluding scan outputs/other repos (see .git/info/exclude)
tar --exclude='__pycache__' --exclude='*.pyc' -czf transfer.tar.gz .claude CLAUDE.md README.md harness
scp transfer.tar.gz root@<vps-ip>:/root/sast-tools/
ssh root@<vps-ip> "cd /root/sast-tools && tar -xzf transfer.tar.gz && rm transfer.tar.gz && git init -q"
```

**The target directory needs its own `.git`** — Claude Code discovers project-level slash
commands (`.claude/commands/*.md`) by walking up to find a git root. `git init -q` with no
commits is sufficient; you don't need to commit anything for this to work.

## 3. Install Node.js (needed for tree-sitter)

Most stock distro Node packages are ancient (e.g. Ubuntu 20.04 ships Node 10, EOL). Use NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install nodejs -y
node --version   # v20.x
npm --version    # v10.x
```

## 4. Install tree-sitter CLI + grammars

**This is the step most likely to trip you up on an older distro — read this before running anything.**

The prebuilt `tree-sitter-cli` npm binaries only support glibc 2.32+ starting at version 0.25.0,
but versions before that (0.23.x/0.24.x) don't support `--json`/`--json-summary` output at all.
On Ubuntu 20.04 (glibc 2.31) there is **no prebuilt version that has both** — you must build from
source, which compiles against whatever glibc is actually on the box:

```bash
# Rust toolchain (needed to build tree-sitter-cli from source)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
. "$HOME/.cargo/env"

# libclang is needed by one of tree-sitter-cli's dependencies (bindgen, for its JS-engine binding)
apt-get install -y libclang-dev clang

cargo install tree-sitter-cli --locked
```

**Watch for a PATH shadowing trap**: if you `npm install -g tree-sitter-cli` at any point
(even a failed attempt), that installs a broken prebuilt binary at `/usr/bin/tree-sitter`
which sits *earlier* on PATH than `~/.cargo/bin`. Non-interactive shells (like the ones this
harness spawns over SSH) won't have `~/.cargo/bin` on PATH by default anyway. Fix both at once:

```bash
npm uninstall -g tree-sitter-cli 2>/dev/null   # remove the broken prebuilt if present
ln -sf ~/.cargo/bin/tree-sitter /usr/local/bin/tree-sitter   # /usr/local/bin outranks /usr/bin
tree-sitter --version
tree-sitter parse --help | grep -i json   # should show --json-summary
```

Now install the actual language grammars and register them:

```bash
npm install -g tree-sitter-typescript tree-sitter-python tree-sitter-java tree-sitter-javascript

tree-sitter init-config
python3 -c "
import json
p = '$HOME/.config/tree-sitter/config.json'
d = json.load(open(p))
d['parser-directories'].append('/usr/lib/node_modules')
json.dump(d, open(p, 'w'), indent=2)
"
tree-sitter dump-languages   # should list java, javascript, python, typescript, tsx
```

Verify with a real parse (not just `--version`):

```bash
echo 'const x: number = 1;' > /tmp/t.ts
tree-sitter parse -x /tmp/t.ts   # -x/--xml is the actual full-tree output — see note below
```

> **Why `-x` and not `--json`?** In every current tree-sitter CLI release (0.23–0.26),
> `--json`/`--json-summary` only report parse success/failure and timing — never the tree
> structure. This project's `crawl-tree-sitter.md` skill was originally written against an
> older CLI behavior where `--json` dumped the full AST; it's since been fixed to use `-x`
> (XML), which does give the full tree with `field="..."` attributes and exact row/col
> positions. If you see a skill file anywhere still referencing `tree-sitter parse --json`
> for tree extraction, that's the same bug — it silently produces no usable tree data.

## 5. Install Java + Joern

```bash
apt-get install -y openjdk-17-jdk-headless

cd /root   # or wherever you want it installed
curl -L https://github.com/joernio/joern/raw/master/joern-install.sh -o joern-install.sh
chmod +x joern-install.sh
./joern-install.sh --interactive=false
# installs to /opt/joern, symlinks joern/joern-parse/etc into /usr/local/bin

java -version
joern --version   # note: --version isn't a real flag, expect a harmless "Unknown option" warning
which joern joern-parse
```

The installer downloads a ~2GB archive and extracts ~2.6GB — **delete the archive immediately
after extraction succeeds** if disk is tight:

```bash
rm -f /root/joern-cli.zip   # only after confirming /opt/joern/joern-cli exists and is populated
```

Sanity-test it actually works (don't just trust that install finished with no errors):

```bash
mkdir -p /tmp/joern-test && cd /tmp/joern-test
echo 'const express = require("express"); const app = express(); app.get("/x", (req,res)=>{ res.send(req.query.q); });' > app.js
joern-parse .
# should end with "Successfully wrote graph to: /tmp/joern-test/cpg.bin"
```

On a small box (~2GB RAM), Joern's JVM will auto-limit its heap (you may see a warning
suggesting `-Xmx494m` or similar) — this works for small test files but expect `joern-parse`
against a real repo (hundreds of files) to take much longer than on a bigger machine (30+
minutes is normal on a 1vCPU/2GB box, vs. a few minutes on a workstation) and to be the
single most memory-hungry step in the whole pipeline. It hasn't been observed to OOM at this
scale in practice, but if it does, the swap file is your first line of defense — make sure
one exists (`swapon --show`), and increasing the JVM heap ceiling (`-J-Xmx<N>`, see the
warning text for the exact invocation) is the next lever.

## 6. Install and authenticate the claude CLI

```bash
npm install -g @anthropic-ai/claude-code
which claude
claude --version
```

Authenticate — this step needs a human, it can't be scripted:

```bash
claude
# inside the TUI: /login
# it prints a URL — open it in a browser on ANY machine, sign in, approve
```

Verify:

```bash
claude --print "say OK"   # should print OK, not "Not logged in"
```

## 7. Understand the permission model before running anything

This is the part that will silently hang or fail with no useful error if you don't know about
it going in. **`agent.py` already handles this automatically as of the current version of this
repo** — this section explains *why*, for troubleshooting if something regresses.

Every pipeline step invokes `claude --print` — fully unattended, no TTY, no human present to
click "allow" on a tool-use permission prompt. Three things had to be worked out:

1. **A brand-new working directory has zero established trust.** Claude Code tracks tool-use
   trust *per exact directory path* — and this pipeline creates a fresh timestamped
   `sast-runs/<run-id>/workdir/` on every run, so there's no way to pre-establish trust once
   and have it carry over. Critically, **this trust does not reliably inherit from a parent
   git root's `.claude/settings.local.json`** — a settings file at the project root is not
   enough on its own. The fix implemented in `agent.py` (`_ensure_workdir_trust`) writes a
   `.claude/settings.local.json` with `{"permissions": {"allow": ["Bash","Write","Edit","Read"]}}`
   directly into *every* fresh `workdir` before the first `claude` invocation in it.

2. **`--dangerously-skip-permissions` and `--permission-mode bypassPermissions` are both
   refused outright when running as root** ("cannot be used with root/sudo privileges for
   security reasons") — which is exactly the account most single-user VPS boxes run
   everything as. The settings-file approach above is a different mechanism and isn't
   subject to this check, which is precisely why it's used instead.

3. **The target repo being scanned is a sibling directory, not a subdirectory of `workdir`**,
   so it's outside the sandbox by default too. `agent.py` passes `--add-dir <repo_path>` to
   grant access to it. **Argument order matters**: `--add-dir` is variadic (accepts multiple
   paths) and will greedily swallow the next bare argument if placed before it — so the
   prompt-file argument (`@prompt.txt`) must come *before* `--add-dir <path>` on the command
   line, never after.

If you ever see a skill's raw output log say something like *"I need your approval to write
this file"* or *"the target repo is not accessible from here"*, this section is what broke —
check `workdir/.claude/settings.local.json` exists and that `--add-dir` is being passed with
the repo path.

## 8. Run the pipeline via the CLI harness

No server, no port, no login page — this runs the same orchestrator (`pipeline.py`) as the
web harness, just printing progress to the terminal instead of streaming over SSE.

```bash
cd /root/sast-tools/harness
python3 cli.py /root/sast-tools/juice-shop
```

Runs in the foreground by default. For a long scan over SSH, background it so it survives a
dropped connection:

```bash
nohup python3 cli.py /root/sast-tools/juice-shop > /root/sast-tools/cli-scan.log 2>&1 &
tail -f /root/sast-tools/cli-scan.log
```

`nohup` + `&` is sufficient — no `disown`, no `screen`/`tmux` needed. The process detaches
from your shell's signal handling; only a VPS reboot, an explicit `kill`, or the process
crashing on its own (e.g. OOM) will stop it. A dropped SSH connection will not.

Useful flags (same as the web harness's request body, see `cli.py --help`):

```bash
python3 cli.py <repo> --skip-joern          # skip CPG generation (faster, less coverage)
python3 cli.py <repo> --skip-tree-sitter    # force the heuristic crawl instead of AST-based
python3 cli.py <repo> --codeql              # run codeql-scan alongside find-vulns (needs CodeQL CLI)
python3 cli.py <repo> --dast                # generate a DAST test script at the end
python3 cli.py <repo> --fresh                # ignore any incomplete prior run for this repo
python3 cli.py <repo> --resume <run_id>     # resume a specific run instead of auto-detecting
python3 cli.py <repo> --ground-truth <path> # compute precision/recall against known bugs
```

`cli.py` itself has zero third-party dependencies — it only imports `pipeline.py`/`agent.py`/
`config.py`, which are pure standard library. You do **not** need `harness/requirements.txt`
(FastAPI/uvicorn/etc.) installed to use the CLI — those are only needed for the web UI.

## 9. After the scan — metrics

`scan-metrics` is a standalone skill, not part of the automated pipeline. Run it manually
against a completed run:

```bash
cd /root/sast-tools
RUN_ID=<the run's timestamp id, e.g. 20260723-150223>
cat .claude/commands/scan-metrics.md > /tmp/metrics-prompt.txt
echo "" >> /tmp/metrics-prompt.txt
echo "---" >> /tmp/metrics-prompt.txt
echo "Arguments: --run-dir sast-runs/$RUN_ID/" >> /tmp/metrics-prompt.txt
claude --print "@/tmp/metrics-prompt.txt" --add-dir /root/sast-tools/juice-shop
```

**Do not build this prompt file using local shell command substitution inside a double-quoted
SSH command** (e.g. `ssh host "cat \$(cat skill.md) ..."` run from your own machine) — the
`$(...)` gets expanded by *your local shell* before the command is ever sent to the remote
host, silently producing an empty/wrong prompt if the referenced file doesn't exist locally.
Always build multi-step remote prompt files with a real remote script (`ssh host 'bash -s' <<
'EOF' ... EOF`, or a heredoc executed after you've already SSH'd in).

This appends to `sast-metrics.json` (creates it fresh on the first run for a given repo) and
reports operational timing, pipeline attrition, quality/precision, severity breakdown, file
coverage, and trend deltas against any prior run for the same repo.

## Summary: fresh-box checklist

```bash
# 1. Node
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install nodejs -y

# 2. tree-sitter (build from source — see §4 for why)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
. "$HOME/.cargo/env"
apt-get install -y libclang-dev clang
cargo install tree-sitter-cli --locked
npm uninstall -g tree-sitter-cli 2>/dev/null
ln -sf ~/.cargo/bin/tree-sitter /usr/local/bin/tree-sitter
npm install -g tree-sitter-typescript tree-sitter-python tree-sitter-java tree-sitter-javascript
tree-sitter init-config
python3 -c "import json; p='$HOME/.config/tree-sitter/config.json'; d=json.load(open(p)); d['parser-directories'].append('/usr/lib/node_modules'); json.dump(d, open(p,'w'), indent=2)"

# 3. Java + Joern
apt-get install -y openjdk-17-jdk-headless
curl -L https://github.com/joernio/joern/raw/master/joern-install.sh -o /root/joern-install.sh
chmod +x /root/joern-install.sh && /root/joern-install.sh --interactive=false
rm -f /root/joern-cli.zip

# 4. claude CLI
npm install -g @anthropic-ai/claude-code
claude   # then /login inside the TUI — requires a human, once per box

# 5. Project + run (permission handling is automatic — see §7 for why it works)
cd /root/sast-tools/harness
python3 cli.py /root/sast-tools/juice-shop
```
