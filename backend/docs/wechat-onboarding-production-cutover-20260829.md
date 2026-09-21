# WeChat onboarding production cutover evidence

- Cutover date: 2026-08-29 UTC
- API release: `wechat-onboarding-c0f519a-20260829T010309Z`
- Source commit: `c0f519a2f6aebc8901a1b252cb5d94a558b35755`
- Source tree: `d9e69ce34d219e7fb9772295115a354c33fba0f5`
- Built with: Go 1.26.6, linux/amd64, CGO disabled, release profile

## Backup evidence

A fresh pre-cutover backup was completed before changing configuration or the
API symlink.

- Remote: `/var/backups/moonstone/pre-onboarding-cutover-20260829T010519Z`
- Off-host copy:
  `F:\砾石进化\服务器\moonstone-dev\pre-onboarding-cutover-20260829T010519Z`
- Remote permissions: directory `0700`, all backup files `0600`, owned by root
- Files: authority, ZITADEL and operational custom-format dumps; both cluster
  globals; runtime configuration; prior API release; source build information;
  schema versions and row counts
- Verification: remote and off-host SHA-256 manifests passed; all three custom
  dumps passed `pg_restore --list`
- Earlier full physical base/WAL backup retained at
  `/var/backups/moonstone/pre-onboarding-20260828T225328Z`

## Artifact evidence

- `united-pass-api`: 41,410,722 bytes,
  SHA-256 `a9ec2a1f8dfac162d8b6913295e27875302f72e7ea94a69ada97daa35ff9cab2`
- `united-pass-migrate-isolated`: 10,252,450 bytes,
  SHA-256 `1cf035c22255fc83abf33fd47da122a21b33a97607d3004b00c5e4459f307a04`
- Existing isolated migration copy:
  SHA-256 `18662fdab3aaa370e2bd79e093814c09525bd3aa37b4e3bcecf251966b39332b`
- Embedded build information exactly matches the source commit and tree above.
- No authority or operational migration command was run.

## Dependency readiness

- SMTP implicit-TLS connection, authentication and `MAIL FROM` acceptance
  succeeded; the test issued `RSET` and sent no message.
- Redis reports AOF enabled and `maxmemory-policy=noeviction`.
- PostgreSQL main and operational clusters were ready.
- The API readiness endpoint confirmed ZITADEL and required dependencies.

## Cutover and rollback exercise

The first validation attempt supplied the wrong native-client marker
(`mini_program`) to the route probe. The candidate itself started and passed
health/readiness, but the transport middleware correctly hid the route with
404. The guarded script restored the old feature file and prior API symlink and
restarted only `moonstone-up-api.service`. Database counts and schema versions
remained unchanged.

The corrected attempt used the canonical marker `dreamup-miniprogram`. The API
symlink and feature configuration were changed atomically, the dedicated
32-byte onboarding key was generated on-host without being printed, and only
`moonstone-up-api.service` was restarted. The invalid-body route probe returned
422 instead of 404, proving that the independently gated route is mounted while
avoiding a real WeChat or account mutation.

An authenticated Redis `SCAN` counted zero `wechat-onboarding:v2` keys after
the rollback and corrected cutover. Therefore the discarded first-attempt key
encrypted no challenge or cleanup obligation and does not need to be retained.

## Post-cutover verification

- API current release points to the release listed above.
- `moonstone-up-api.service`: active
- Loopback `/healthz`: 200, `{"status":"ok"}`
- Loopback `/readyz`: 200, `{"status":"ready"}`
- Public onboarding invalid-body probe: 422
- Production journal: no error, fatal or panic record after successful cutover
- Service `NRestarts`: 0 after cutover; no automatic crash/restart occurred
- Feature file: root-owned `0600`; exactly one enabled flag, current key and
  key ID; key material was not emitted to logs or evidence
- Onboarding key ID: `wxo-20260829-v1`; retained keyring is initially empty

The reverse proxy intentionally does not expose `/healthz` or `/readyz`
publicly and returned 404 for those two paths. This does not affect the public
API route, which passed through the same origin and returned the expected 422.

## Database invariants

The invalid probes performed no business mutation. Pre- and post-cutover
values are identical:

| Invariant | Before | After |
|---|---:|---:|
| Authority goose version | 13 applied | 13 applied |
| Authority users | 89 | 89 |
| Authority identity links | 89 | 89 |
| Authority security events | 344 | 344 |
| Operational goose version | 1 applied | 1 applied |
| WeChat provider intents | 0 | 0 |

Future writes are limited to user-authorized onboarding operations described in
ADR-0020. The backup is disaster-recovery evidence, not a reason to erase valid
links created after user consent.

## Unchanged production services

- DreamUP release remains
  `/srv/moonstone-dreamup/releases/mfa-loop-hotfix-20260828T151657Z`
- United Pass web remains
  `/srv/moonstone-up-web/releases/mini-8cd54d9-20260828T1810CST`
- DreamUP activation timestamp remained `12501337`
- United Pass web activation timestamp remained `12531674`
- Both services remained active; neither was restarted or deployed.

## Mini Program artifact

- Release ID: `dreamup-mini-20260829-r4`
- Source commit: `5706e1f742eb3e63123ed00cd93eae2a58ee6562`
- Source tree: `0883933af33530795bcc042afebcaa07ac65bd53`
- Bundle SHA-256:
  `914b9b7634f7d0f3c569d413ad094e6464f574863230f6f08ac1fbc69a776102`
- DevTools upload evidence was generated at `2026-08-29T00:56:09Z` for
  2,612,802 bytes (main 1,543,607; partner subpackage 1,069,195).

The upload is confirmed by the DevTools CLI `progressSuccess` trace and package
information file. Portal review submission and formal publication were not
executed in this cutover session because the authenticated browser-control
interface was unavailable. The artifact must not be uploaded again: in WeChat
Public Platform, confirm this exact r4 development version, submit it for
review, and publish the approved review version. Upload evidence alone is not
represented as public release.
