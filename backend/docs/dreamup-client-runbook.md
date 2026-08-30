# DreamUP OAuth client bootstrap runbook

This command creates or verifies one United Pass application named
`MoonStone DreamUP` and its single confidential `web_server` OAuth client. It
touches only United Pass PostgreSQL and the configured ZITADEL project. It has
no Beijing registration-system dependency.

## Frozen client contract

- Redirect URI: `https://moonstone.org.cn/moonstone-dreamup/auth/callback`
- Post-logout redirect URI: `https://moonstone.org.cn/moonstone-dreamup/`
- Scopes: `openid profile email`
- Consent mode: `first_authorization`
- Token endpoint authentication: `client_secret_basic`
- Response type: `code`
- Provider grants: `authorization_code refresh_token`
- Provider login version: LoginV2 at the interaction base derived from
  `UP_OAUTH_PUBLIC_ORIGIN`
- Provider development mode: disabled
- Effective provider CORS origin: `https://moonstone.org.cn`

DreamUP must generate a fresh PKCE verifier for every authorization attempt,
send an S256 code challenge, and verify the returned authorization response.
It requests `openid profile email`; it does not request `offline_access`.
Refresh-token capability is part of the provider's reviewed `web_server`
profile but does not authorize DreamUP to request offline access.

## Preconditions

1. Apply the reviewed United Pass migrations to the intended schema before
   running this command. The command never runs migrations.
2. Use the same production candidate environment as the United Pass API,
   including PostgreSQL, the session encryption key, the ZITADEL service
   account, project ID, and public OAuth origin.
3. Set `UP_DREAMUP_OWNER_USER_ID` to the stable ID of an existing United Pass
   user. The command resolves this owner through the existing user repository
   and fails when the user does not exist.
4. Create a root-owned directory that is not readable by other users. Select
   an absolute path inside it that does not exist. Do not pre-create the file.
5. Run the command as root on the Linux deployment host so the exclusively
   created `0600` file is root-owned. The command verifies the effective UID,
   parent ownership/mode, file ownership/mode, regular-file type, and link
   count before writing the secret. Non-Linux execution fails closed. Do not
   run it through a shell with command tracing enabled.

Example preparation (replace only the directory with an approved credential
location):

```sh
install -d -m 0700 -o root -g root /run/credentials/moonstone
test ! -e /run/credentials/moonstone/dreamup-oidc-client-secret
```

## First run

From `backend`, with the reviewed `.env` available to the root process:

```sh
go run ./cmd/dreamup-bootstrap \
  --secret-output /run/credentials/moonstone/dreamup-oidc-client-secret
```

Success prints only stable local/client/provider IDs, `status=created`,
`drift=none`, and `secret_provisioned=true`. The client secret is written once
to the selected file and is never printed to stdout or stderr.

Immediately verify ownership and mode without displaying the file:

```sh
test "$(stat -c '%U:%G %a' /run/credentials/moonstone/dreamup-oidc-client-secret)" = "root:root 600"
```

Transfer the value through the approved secret-store ingestion mechanism.
Confirm the stored secret version is usable by the closed-traffic DreamUP
candidate before securely removing the temporary credential file. Never paste
the secret into a terminal command, ticket, log, chat, or release record.

## Idempotency verification

Run the command again without `--secret-output`:

```sh
go run ./cmd/dreamup-bootstrap
```

The required result is `status=verified`, `drift=none`, and
`secret_provisioned=true`. This path performs provider and local read-back only:
it creates, updates, enables, rotates, and deletes nothing.

The read-back checks every non-secret security field owned by this contract,
including the exact redirect/logout strings, local scopes and consent mode,
provider app/profile/auth method/status, response and grant types, provider
mapping IDs, LoginV2 base URI, development mode, and the provider's effective
allowed origins.

## Failure handling

- `status=drift` is a hard release stop. The command reports only the safe
  drift field class and never repairs it implicitly. Investigate and use the
  reviewed application-management workflow for any correction, then run this
  verification again.
- `secret_output_required` means the pair is absent and first creation needs an
  absolute output path.
- `secret_output_unavailable` means the selected path was not safe to create,
  already existed, or could not be durably written. The command refuses to
  overwrite an existing file.
- `owner_user_id_required` means `UP_DREAMUP_OWNER_USER_ID` is missing.
- Any other failure keeps traffic closed. Do not infer provider state from a
  timeout and do not retry secret rotation blindly.

The bootstrap uses an unfiltered, non-paginated PostgreSQL read-back rather
than the normal application-service projections. It includes unfinished,
reconciliation-required, rotation-ambiguous, and soft-deleted rows. A durable
offline-only audit anchor identifies a pair created by this command even if
all mutable names and URIs later drift. Any such state reports `status=drift`;
the command never adopts, repairs, or replaces it implicitly. Resolve it
through the existing reviewed reconciliation workflow before retrying.

After provider creation succeeds, the command durably writes the one-time
secret before performing fallible local/provider verification. If that
verification fails, the root-owned file remains quarantined at the selected
path; do not ingest it until drift is resolved and verification succeeds. A
process or storage failure before the file is durably closed can still leave a
created client without a delivered secret. In that case, use the existing
reviewed client-secret rotation workflow, capture the replacement once, and
repeat closed-traffic verification. Never delete/recreate the client as an
implicit recovery step.

Real-provider execution, the mandatory second-run zero-write observation, and
traffic cutover belong to the release procedure. Unit tests and compilation do
not substitute for those production-candidate checks.
