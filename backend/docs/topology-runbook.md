# OAuth Endpoint Topology Runbook (Phase 3.6)

<!--
Copyright (c) 2026 Chen Jiajie(Ariakage)

Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
Date: 2026-08-07
Description: Reverse-proxy ownership, public origin configuration and the
             frozen rollout order for the OAuth endpoint topology (ADR-0005 §1)
-->

The OAuth protocol endpoints are **reverse-proxy infrastructure**, not
application code. Go and Next.js never implement authorize, token, revoke,
introspect, keys, userinfo, end_session, device_authorization or discovery;
the proxy forwards them verbatim to ZITADEL. This runbook pins ownership,
configuration derivation and the rollout order so the browser, the proxy and
ZITADEL can never disagree about what the public deployment looks like.

## 1. Routing ownership

| Public path | Owner | Behavior |
| --- | --- | --- |
| `GET /oauth/v2/authorize` | reverse proxy → ZITADEL | The sole public authorization endpoint; proxied verbatim with query string. |
| `GET /oauth/authorize` | reverse proxy | Compatibility 302 to `/oauth/v2/authorize`, query preserved. |
| `POST /oauth/v2/token`, `POST /oauth/v2/revoke`, `POST /oauth/v2/introspect`, `POST /oauth/v2/device_authorization`, `GET /oauth/v2/keys`, `GET /oidc/v1/userinfo`, `GET|POST /oidc/v1/end_session`, `GET /.well-known/openid-configuration` | reverse proxy → ZITADEL | Exact protocol endpoint set of ZITADEL v2.71; proxied verbatim. |
| `GET /_interaction/login` | Go backend | Authorization Interaction Gateway (ADR-0005 §12); the sole entry ZITADEL generates for LoginV2 apps. |
| `GET /login`, `/authorize` | Next.js | Interactive UI; reached only via gateway 302 with a single `requestId`. |
| `/api/v1/*` | Go backend | Frozen REST contract. |

## 2. Public origin configuration

`UP_OAUTH_PUBLIC_ORIGIN` is the single source of truth for the browser-visible
issuer origin. It is an **origin**, not a base URL:

- accepted: `https://id.example.com`, `https://id.example.com:8443`,
  `http://localhost:3000` (development only)
- rejected: any path other than `/`, userinfo (`user:pass@`), query, fragment,
  non-http(s) schemes, missing host
- production: mandatory and HTTPS-only (enforced by `config.Validate`)

Derivation — the only one, never independently configured:

```
UP_OAUTH_PUBLIC_ORIGIN        https://id.example.com
        ↓ config.OAuthConfig.InteractionBaseURI()
Interaction Base URI          https://id.example.com/_interaction
```

There is deliberately no `UP_INTERACTION_BASE_URI`. `UP_AUTH_PROVIDER_BASE_URL`
must never be reused for this value: it is the internal provider
management/API address, while `UP_OAUTH_PUBLIC_ORIGIN` is the origin the
browser sees and the issuer published in discovery.

## 3. Reverse proxy requirements

- Proxy protocol endpoints **verbatim**, including query strings; no body or
  header rewriting on `/oauth/v2/*`, `/oidc/v1/*` or discovery.
- Override `X-Forwarded-Host` / `X-Forwarded-Proto` toward ZITADEL so the
  provider renders the **public origin** as issuer and in every endpoint URL;
  otherwise discovery leaks the internal address.
- Route `/_interaction/*` to the Go backend and the remaining paths of the
  origin to the frontend, so the gateway shares the United Pass session
  cookie origin.
- The `/oauth/authorize` compatibility redirect must preserve the full query
  string when forwarding to `/oauth/v2/authorize`.

## 4. Frozen rollout order

The production backfill of LoginVersion MUST happen **before** the public
`/login` path is cut over to Next.js. Otherwise a pre-P3 app still on LoginV1
makes ZITADEL fall back to its own `/login?...`, which the proxy already
serves from Next.js — a confusing half-switched state.

1. Deploy the Gateway + API (this phase's Go changes).
2. Deploy the proxy topology, **without** cutting production traffic.
3. Enable provisioner LoginVersion support (P3.6 commit 3).
4. Backfill existing OIDC apps to `LoginV2{BaseURI=<derived interaction base>}`.
5. Read-back verify every app's OIDC config (live, not assumed).
6. Run the live path-prefix probe: `scripts/topology-probe.sh` against the
   real instance; record the observed redirect Location (authRequest redacted).
7. Verify discovery: `issuer` and all endpoint URLs equal the public origin.
8. Cut public OAuth traffic to the new topology.
9. Smoke test an interactive authorization end-to-end.

## 5. Probe and acceptance evidence

- Probe: `scripts/topology-probe.sh` (discovery endpoints + authorize redirect
  observation; exit 0 iff the `/_interaction` prefix is preserved).
- P3.6 acceptance record: `docs/p36-topology-acceptance.md` (ZITADEL version,
  public origin, interaction base URI, observed login redirect, discovery
  endpoints, prefix-preserved verdict). Re-run at P3.9 final acceptance.
- If the probe shows the prefix dropped or re-encoded, fall back to a
  dedicated interaction host; the gateway design is unaffected (ADR-0005 §1).
