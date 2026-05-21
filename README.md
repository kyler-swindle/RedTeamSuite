# RedTeamSuite

RedTeamSuite is an evidence-first, modular red-team lab helper. It is designed to collect structured notes, raw HTTP evidence, parsed artifacts, and safe validation results while keeping invasive actions opt-in.

This starter package includes a Project 3 profile/workflow, but the package layout is intentionally generic:

- `core/` contains reusable plumbing such as config, models, logging, HTTP, and evidence storage.
- `modules/` contains capability-focused testers and parsers.
- `profiles/` contains target-specific path/field definitions.
- `workflows/` composes modules into repeatable assessment passes.
- `cli/` exposes subcommands.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

```bash
python -m redteamsuite.cli.rts init --target 192.168.56.21 --profile project3
python -m redteamsuite.cli.rts run-profile --target 192.168.56.21 --profile project3 --allow-code-exec-validation --allow-upload-marker
```

Safer default run without code-exec/upload marker validation:

```bash
python -m redteamsuite.cli.rts run-profile --target 192.168.56.21 --profile project3
```

## Useful subcommands

```bash
python -m redteamsuite.cli.rts web-enum --target 192.168.56.21 --profile project3
python -m redteamsuite.cli.rts portal-test --target 192.168.56.21 --profile project3
python -m redteamsuite.cli.rts upload-test --target 192.168.56.21 --profile project3 --username mitchmarcus --password ITAdmin2026 --allow-upload-marker
python -m redteamsuite.cli.rts nextjs-test --target 192.168.56.21 --port 3000 --allow-code-exec-validation
```

## Output

Every run creates a timestamped output folder under `output/` unless you specify `--out`. The suite writes:

- `run_metadata.json`
- `run_log.jsonl`
- `host_profile.json`
- `web_paths.json`
- `credentials.json`
- `sessions.json`
- `uploads.json`
- `findings.json`
- raw HTTP evidence under `evidence/http/`

## Safety model

By default, this suite focuses on documentation and passive/safe validation. Potentially invasive checks are gated behind explicit flags:

- `--allow-code-exec-validation`
- `--allow-upload-marker`

Reverse shell automation, persistence, SSH key injection, destructive cleanup, and privilege escalation automation are intentionally not included in this starter version.
