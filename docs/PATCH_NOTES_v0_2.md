# RedTeamSuite Patch v0.2

## Scope

This patch adds:

1. Stable output run directories with append-by-default behavior.
2. First-class network mapping before target selection.
3. Manual target selection after `net-map` prints scored candidates.
4. Safer upload validation flags:
   - `--allow-upload-marker` for benign text upload/access validation.
   - `--allow-php-exec-marker` for double-extension PHP execution validation.
5. Hardened `.gitignore` so generated evidence and local secrets are not committed.

## Output behavior

`--out` remains the base output directory.

If `--run-id` is provided, the concrete run directory is:

```bash
<out>/<run-id>/
```

Existing data is appended/preserved by default.

Use `--new-run` to create a timestamp-suffixed fresh directory.
Use `--force-overwrite` only when you intentionally want to delete the selected run directory before writing.

## Recommended workflow

```bash
cd ~/Downloads/RedTeamSuite
source .venv/bin/activate

export CIDR=192.168.56.0/24
export RUN_ID=kali-lab-001

python -m redteamsuite.cli.rts net-map \
  --cidr $CIDR \
  --profile project3 \
  --out output/project3_test \
  --run-id $RUN_ID
```

Inspect candidates:

```bash
cat output/project3_test/$RUN_ID/target_candidates.json
cat output/project3_test/$RUN_ID/network_map.json
```

Manually select target:

```bash
export TARGET=192.168.56.21
```

Then continue:

```bash
python -m redteamsuite.cli.rts web-enum \
  --target $TARGET \
  --profile project3 \
  --out output/project3_test \
  --run-id $RUN_ID

python -m redteamsuite.cli.rts portal-test \
  --target $TARGET \
  --profile project3 \
  --out output/project3_test \
  --run-id $RUN_ID
```

Benign upload validation:

```bash
python -m redteamsuite.cli.rts upload-test \
  --target $TARGET \
  --profile project3 \
  --out output/project3_test \
  --run-id $RUN_ID \
  --username mitchmarcus \
  --password ITAdmin2026 \
  --allow-upload-marker
```

Explicit PHP execution marker validation:

```bash
python -m redteamsuite.cli.rts upload-test \
  --target $TARGET \
  --profile project3 \
  --out output/project3_test \
  --run-id $RUN_ID \
  --username mitchmarcus \
  --password ITAdmin2026 \
  --allow-upload-marker \
  --allow-php-exec-marker
```

## Files replaced/added

- `.gitignore`
- `redteamsuite/cli/rts.py`
- `redteamsuite/core/config.py`
- `redteamsuite/core/context.py`
- `redteamsuite/core/evidence_store.py`
- `redteamsuite/core/utils.py`
- `redteamsuite/modules/upload_tester.py`
- `redteamsuite/modules/network_mapper.py`

## Notes

`run-profile` still requires a manually selected `--target`. That is intentional for this patch so the suite does not automatically assume the wrong host based on target scoring alone.
