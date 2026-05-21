# RedTeamSuite Patch v0.5 — Gobuster-backed evidence-driven web discovery

This patch shifts the default workflow further away from project-specific path assumptions.

## Goals

- Keep `default` profile as the default when `--profile` is omitted.
- Add a `web-discover` command that uses gobuster when available.
- Avoid bundling large wordlists in the repository.
- Detect gobuster JSON support before trying JSON mode.
- Fall back to parsing standard gobuster text output when JSON output is unavailable or unusable.
- Allow users to choose exact ports/service URLs for gobuster-backed discovery.
- Preserve raw gobuster output as evidence.
- Convert gobuster findings into normalized JSON artifacts.
- Expand discovered directory listings and same-origin links in a bounded, evidence-driven way.
- Let `recon` consume discovered paths instead of depending on embedded Project 3 paths.

## New command

```bash
python -m redteamsuite.cli.rts web-discover \
  --target $TARGET \
  --out output/project4_test \
  --run-id p4-fresh
```

Useful options:

```bash
--engine auto|gobuster|native
--wordlist /path/to/wordlist
--extensions php,txt,html,js,bak,old
--status-codes 200,204,301,302,307,308,401,403
--threads 50
--gobuster-timeout 10s
--ports 80,3000
--service-url http://192.168.56.21:3000
--service-url http://192.168.56.21/
--ignore-discovered-services
--crawl-depth 1
```

## Output files

`web-discover` updates or creates:

- `web_discovery.json`
- `web_discovery_summary.json`
- `discovered_paths.json`
- `content_artifacts.json`
- `auth_surfaces.json`
- `upload_surfaces.json`
- `framework_fingerprints.json`
- `recommended_next_steps.json`
- `recon_summary.json`
- `evidence/gobuster/*`
- `evidence/http/*`

## Runtime behavior

There is intentionally no hard runtime/request limiter in RedTeamSuite by default.
Gobuster runtime depends on the wordlist, extension list, thread count, and target behavior.
The command prints a warning before scans. Users can stop with `Ctrl+C`; partial gobuster output is preserved when possible.

## Wordlists

Large wordlists are not committed to the repo.
If `--wordlist` is omitted, RedTeamSuite looks for common Kali paths:

- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`

If none are found, pass `--wordlist` explicitly.

## Default profile cleanup

The default profile no longer contains a Project-3-like path checklist.
It only seeds `/`; web discovery should come from gobuster, links, directory listings, robots/sitemap findings, or previous JSON evidence.

## Recommended fresh workflow

```bash
python -m redteamsuite.cli.rts net-map \
  --cidr 192.168.56.0/24 \
  --out output/project4_test \
  --run-id p4-fresh

export TARGET=192.168.56.X

python -m redteamsuite.cli.rts web-discover \
  --target $TARGET \
  --out output/project4_test \
  --run-id p4-fresh \
  --ports 80,3000

python -m redteamsuite.cli.rts suggest \
  --out output/project4_test \
  --run-id p4-fresh
```

`recon` can still be run separately; `web-discover` now also triggers recon derivation after storing discovered paths so suggestions snowball immediately.
