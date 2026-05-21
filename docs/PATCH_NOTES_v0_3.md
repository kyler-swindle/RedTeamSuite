# RedTeamSuite Patch v0.3

Focus: safer append behavior, finding dedupe, cleaner run metadata, and network-map target classification hardening.

## Files in this patch

```text
redteamsuite/cli/rts.py
redteamsuite/core/config.py
redteamsuite/core/evidence_store.py
redteamsuite/modules/network_mapper.py
redteamsuite/modules/upload_tester.py
redteamsuite/core/context.py
redteamsuite/core/utils.py
.gitignore
docs/PATCH_NOTES_v0_3.md
```

`context.py`, `utils.py`, `upload_tester.py`, and `.gitignore` are included for convenience/continuity with v0.2; the core v0.3 changes are in `rts.py`, `config.py`, `evidence_store.py`, and `network_mapper.py`.

## Major changes

### 1. Finding dedupe without evidence loss

`EvidenceStore.findings` is now a dedupe-aware append-compatible list.

Existing module code like this still works:

```python
ctx.evidence.findings.append(Finding(...))
```

But repeated findings with the same `id` and `target` are merged instead of duplicated in `findings.json`.

Merged findings now track:

```json
{
  "metadata": {
    "dedupe_key": "WEB-DATA-CREDS-001|http://192.168.56.21/data/users.txt",
    "first_seen": "...",
    "last_seen": "...",
    "occurrence_count": 3
  }
}
```

Evidence files are still append-only. Repeated evidence IDs are merged into the finding's `evidence_ids` list without deleting old artifacts.

### 2. Stable run metadata + command history

`run_metadata.json` is now run-level metadata with stable fields:

```json
{
  "created_at": "...",
  "last_updated_at": "...",
  "profile": "project3",
  "run_id": "kali-lab-001",
  "output_dir": "output/project3_test/kali-lab-001",
  "last_command": "web-enum",
  "last_target": "192.168.56.21"
}
```

Each CLI invocation also appends a row to:

```text
command_history.jsonl
```

Passwords passed through CLI args are redacted in command history.

### 3. Network mapper self/infrastructure classification

`net-map` now derives scanner-local IPs from:

```bash
hostname -I
ip addr
ip route
```

It writes:

```text
scanner_self.json
infrastructure_hosts.json
target_candidates.json
network_map.json
```

By default, scanner/self hosts and likely gateway/host/infrastructure hosts are excluded from `target_candidates` but still recorded in the JSON evidence.

New debug flags:

```bash
--include-self
--include-infrastructure
```

Use these only when you intentionally want to test scoring/debug output for excluded hosts.

### 4. Manual target selection remains required

`net-map` prints candidates but does not auto-select a target.

Expected workflow:

```bash
python -m redteamsuite.cli.rts net-map \
  --cidr 192.168.56.0/24 \
  --profile project3 \
  --out output/project3_test \
  --run-id kali-lab-001

cat output/project3_test/kali-lab-001/target_candidates.json
export TARGET=192.168.56.21
```

Then continue with deeper modules:

```bash
python -m redteamsuite.cli.rts web-enum \
  --target $TARGET \
  --profile project3 \
  --out output/project3_test \
  --run-id kali-lab-001
```

## Suggested test commands

```bash
python -m redteamsuite.cli.rts --version
python -m redteamsuite.cli.rts net-map --help
python -m redteamsuite.cli.rts net-map \
  --cidr 192.168.56.0/24 \
  --profile project3 \
  --out output/project3_test \
  --run-id kali-lab-001
```

Inspect:

```bash
cat output/project3_test/kali-lab-001/scanner_self.json
cat output/project3_test/kali-lab-001/infrastructure_hosts.json
cat output/project3_test/kali-lab-001/target_candidates.json
cat output/project3_test/kali-lab-001/network_map.json
```

After rerunning web/upload/nextjs modules multiple times, inspect dedupe:

```bash
cat output/project3_test/kali-lab-001/findings.json
cat output/project3_test/kali-lab-001/command_history.jsonl | tail -20
```
