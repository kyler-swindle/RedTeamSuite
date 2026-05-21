# RedTeamSuite Patch v0.4

Focus: introduce the default evidence-driven recon workflow and reduce Project 3 assumptions in normal usage.

## Files in this patch

```text
redteamsuite/cli/rts.py
redteamsuite/core/config.py
redteamsuite/core/evidence_store.py
redteamsuite/modules/recon.py
redteamsuite/profiles/default_profile.py
redteamsuite/profiles/__init__.py
redteamsuite/modules/network_mapper.py
redteamsuite/modules/upload_tester.py
redteamsuite/core/context.py
redteamsuite/core/utils.py
.gitignore
docs/PATCH_NOTES_v0_4.md
```

`network_mapper.py`, `upload_tester.py`, `context.py`, `utils.py`, and `.gitignore` are carried forward from v0.3 for convenience/continuity. The main v0.4 changes are in `rts.py`, `recon.py`, `default_profile.py`, `config.py`, and `evidence_store.py`.

## Major changes

### 1. `default` is now the default profile

You no longer need to explicitly pass `--profile default`.

This now defaults to the generic workflow:

```bash
python -m redteamsuite.cli.rts net-map --cidr 192.168.56.0/24 --out output/project4_test --run-id p4-fresh
```

Project-specific modules are still available, but must be explicit:

```bash
python -m redteamsuite.cli.rts run-profile --profile project3 --target 192.168.56.21 --out output/project3_test --run-id p3
```

### 2. New `recon` command

`recon` is the first generic, evidence-driven workflow stage after manual target selection.

It consumes previous JSON artifacts such as:

```text
network_services.json
network_map.json
target_candidates.json
```

Then writes:

```text
http_services.json
discovered_paths.json
content_artifacts.json
auth_surfaces.json
upload_surfaces.json
framework_fingerprints.json
recommended_next_steps.json
recon_summary.json
```

Example flow:

```bash
python -m redteamsuite.cli.rts net-map \
  --cidr 192.168.56.0/24 \
  --out output/project4_test \
  --run-id p4-fresh

export TARGET=192.168.56.X

python -m redteamsuite.cli.rts recon \
  --target $TARGET \
  --out output/project4_test \
  --run-id p4-fresh
```

### 3. Bounded snowball behavior

`recon` does not auto-run risky follow-up modules. It derives surfaces and produces recommendations.

The intended snowball is:

```text
net-map -> manual target selection -> recon -> recommended next steps -> user-selected follow-up command
```

### 4. Project 3 commands are gated

These commands are still profile-specific and require `--profile project3`:

```text
portal-test
upload-test
nextjs-test
project3 run-profile behavior
```

This prevents accidental Project 3 assumptions from leaking into default Project 4 testing.

### 5. Finding schema begins moving away from `*-001`

New recon findings use type-style IDs, for example:

```text
WEB_DIRECTORY_LISTING
WEB_CREDENTIAL_LIKE_CONTENT
WEB_AUTH_SURFACE_DISCOVERED
WEB_UPLOAD_SURFACE_DISCOVERED
WEB_FRAMEWORK_FINGERPRINT
```

`EvidenceStore` now dedupes by `finding_type` when present, falling back to `id` for older findings.

### 6. Recommendations command

Use this to reprint recommendations for a run:

```bash
python -m redteamsuite.cli.rts suggest \
  --out output/project4_test \
  --run-id p4-fresh
```

## Notes

- `recon` is intentionally conservative.
- It records discovered surfaces; it does not validate login, file upload behavior, or code execution by default.
- For unknown projects, start with the default workflow and only add project-specific modules after evidence supports them.
