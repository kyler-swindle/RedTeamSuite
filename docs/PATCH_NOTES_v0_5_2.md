# RedTeamSuite v0.5.2 Patch Notes

Focused evidence-interpretation and readability patch on top of v0.5.1.

## Changes

1. Semantic versioning now uses three digits.
   - `python -m redteamsuite.cli.rts --version` prints `RedTeamSuite 0.5.2`.
   - Runtime metadata records `redteamsuite_version`.
   - User-Agent updated to `RedTeamSuite/0.5.2 ...`.

2. Added protected route classification.
   - Writes `protected_routes.json`.
   - Detects routes that redirect to login/auth surfaces or return 401/403.
   - Adds route type hints such as:
     - `possible_admin_surface`
     - `possible_authenticated_app_surface`
     - `possible_upload_surface`
     - `protected_route`

3. Added compact surface summary JSON.
   - Writes `surface_summary.json`.
   - Includes counts by surface/artifact type and notable URLs.

4. Improved recommendations.
   - Protected upload/admin/dashboard-like routes now produce authenticated recon recommendations.
   - Recommendations can include runtime warnings.
   - Suggested commands prefer `python -m json.tool` for readability.

5. Added `show-summary` command.
   - Prints compact run counts and notable URLs without dumping huge JSON files.

6. Improved `suggest` output.
   - Prints compact summary before recommendations by default.
   - Use `--no-summary` to only show next steps.

## Example

```bash
python -m redteamsuite.cli.rts show-summary \
  --out output/p3_default_v051 \
  --run-id p3-default-v051

python -m redteamsuite.cli.rts suggest \
  --out output/p3_default_v051 \
  --run-id p3-default-v051
```
