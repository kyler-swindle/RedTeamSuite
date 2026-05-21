# RedTeamSuite Patch v0.5.1

Bugfix patch for the v0.5 gobuster-backed `web-discover` workflow.

## Fixes

1. **Gobuster 3.8 status-code compatibility**
   - Gobuster 3.x sets `status-codes-blacklist` to `404` by default.
   - v0.5 passed `-s 200,204,301,302,307,308,401,403` without clearing the default blacklist, causing gobuster to exit with:
     - `status-codes and status-codes-blacklist are both set`
   - v0.5.1 now passes `-b ""` whenever an allowlisted `-s` value is used.

2. **Better failed-run reporting**
   - Each gobuster run now records:
     - `success`
     - `error_summary`
     - `stderr_sample`
   - `web_discovery.json` now records:
     - `status`
     - `failed_runs`
     - `gobuster_result_count`
   - `web_discovery_summary.json` mirrors those fields and includes `error_summaries`.

3. **Clearer CLI messaging**
   - The CLI now prints `status=partial` or `status=failed` when gobuster runs fail instead of always sounding fully successful.
   - The gobuster timeout help text now clarifies that it is a per-request HTTP timeout, not a full scan runtime limit.

## Notes

This patch does not add new discovery features. It only fixes the gobuster execution issue and improves observability around tool failures.

## Recommended retest

```bash
export CIDR=192.168.56.0/24
export RUN_ID=p3-default-v051
export TARGET=192.168.56.21

python -m redteamsuite.cli.rts net-map \
  --cidr $CIDR \
  --out output/p3_default_v051 \
  --run-id $RUN_ID

python -m redteamsuite.cli.rts web-discover \
  --target $TARGET \
  --out output/p3_default_v051 \
  --run-id $RUN_ID \
  --ports 80,3000
```

Inspect:

```bash
cat output/p3_default_v051/$RUN_ID/web_discovery_summary.json
cat output/p3_default_v051/$RUN_ID/web_discovery.json
cat output/p3_default_v051/$RUN_ID/discovered_paths.json
cat output/p3_default_v051/$RUN_ID/recommended_next_steps.json
```
