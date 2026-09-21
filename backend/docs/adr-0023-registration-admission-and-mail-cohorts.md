# ADR-0023: Bounded registration admission and mailbox-domain cohorts

- Status: Accepted
- Date: 2026-09-12

## Context

The public registration flow already binds a form intent to a server-issued
device, user agent, Origin, trusted network and email, and requires an
interactive challenge. Those controls remain useful when one dimension is
stable. A caller that rotates device cookies, exit networks, form intents and
addresses can nevertheless allocate concurrent CAPTCHA/DNS/provider work.
Exact-email limits also do not aggregate many local parts under one newly seen
mail domain or many disposable domains behind one MX operator.

The trusted client-IP gateway is a separate boundary. Domain controls must not
make caller-supplied forwarding headers trustworthy, and an unfamiliar domain
must not be permanently rejected merely because it is uncommon.

## Decision

Every browser registration enters a bounded process-local admission controller
before CAPTCHA allocation. It admits at most eight expensive registration
requests, queues at most 32 for three seconds, and reserves most capacity from
an unfamiliar-domain flood. At most two unfamiliar-domain requests run
together, including two from one exact unfamiliar domain. Queue overflow
returns the existing retryable 429 envelope without consuming the form intent
or creation budgets. The controller is process-local overload protection, not
the distributed security authority.

After the exact challenge succeeds, email delivery assessment occurs while the
admission lease is held. DNS cold misses are coalesced per canonical IDNA domain
and use a second bounded gate of eight active and 32 queued lookups. Valid and
evidence-blocked results retain the existing bounded 15-minute cache. Temporary
resolver failures fail closed and are not promoted to positive reputation.

Form-intent issuance has distributed device, network and global budgets. The
network and global budgets are charged before a new device record is created,
so rotating device cookies cannot turn the device store into an allocation
amplifier. CAPTCHA issuance likewise has distributed device, network and global
budgets plus a bounded process-local provider gate of four active and 32 queued
requests. An explicitly configured zero-length provider queue is honored.

The Redis creation transaction now has two non-bypassable global buckets
(20/10 seconds and 200/hour). For an unfamiliar recipient domain it also adds
3/10-minute and 10/day registrable-domain buckets. Each unfamiliar registrable
MX operator independently adds 20/10-minute and 100/day operator buckets; a
domain publishing more than 16 distinct unfamiliar operators fails closed
rather than truncating the list. The RFC A/AAAA delivery fallback also uses the
registrable recipient domain, so rotating arbitrary subdomains cannot create
new cohorts. All dimensions are checked and advanced in one Lua operation; a
denied bucket cannot poison another bucket. Only SHA-256 digests of normalized
registrable domains and MX operators enter Redis keys. The browser-chain marker
moved to the `v4` namespace so a marker created under the earlier combined-MX
binding cannot be interpreted under the independent-operator contract. The
marker subsequently moved to `v5` when a provider-reviewed mailbox-family
bucket was added: Gmail and Googlemail addresses are grouped after removing
dots and plus tags, while Outlook-family addresses remove only plus tags. No
normalization is applied generically to providers whose delivery semantics are
unknown. Each mailbox family receives three creation attempts per 24 hours.

Large consumer domains and reviewed MX operators are classified as established
to avoid treating unrelated users as one suspicious cohort. An established
recipient domain does not inherit an unfamiliar-MX cohort merely because its
provider's current routing hostname is absent from the MX allowlist; blocked MX
checks still apply. Established status removes only unfamiliar-domain/MX buckets; it never bypasses the mandatory
interactive challenge, global budgets, exact email, client, network, pair,
form-intent or admission controls. Operators may extend established and blocked
domain/MX lists with validated comma-separated environment settings. Wildcards,
ICANN or private public-suffix-wide entries (for example `com.cn` or
`github.io`) and more than 4096 additions fail startup. Built-in
evidence-backed blocks remain active and cannot be removed by configuration.

A deterministic existing-account conflict refunds its exact-email,
mailbox-family and any unfamiliar domain/MX charges, bound atomically to the
exact form-intent marker.
Client, network and global pressure charges remain. Verification and resend now
advance stable target, IP and target/IP buckets atomically, so changing the exit
address cannot reset attempts or resend email indefinitely.

Verification also has global 20/10-second and 100/5-minute buckets and enters
the shared bounded provider admission controller. Before invoking the identity
provider, the API requires the target to exist in its local pending-registration
store. Random or already-active user IDs therefore receive the same generic
failure without allocating a provider RPC. All registration, verification,
resend and cleanup provider calls have an eight-second deadline.

Admission configuration is capped at 4,096 active requests and 65,536 total
active-plus-queued slots (globally and for unfamiliar domains), with at most
1,024 requests per unfamiliar domain. Startup validation performs checked
capacity arithmetic before allocating channels, so an oversized or overflowing
environment value fails closed instead of panicking the process.

Honeypot IP strikes are disabled unless
`UP_REGISTRATION_HONEYPOT_IP_BLOCKS_ENABLED=true`. A server-issued device can
still be blocked and the event remains audited. IP blocking must be enabled
only after the gateway's authenticated client-IP overwrite has been verified;
otherwise a CDN node could represent many unrelated people.

## Consequences

- Fully rotated registration attempts still face a global creation ceiling.
- New corporate and school domains remain usable, but sudden concentration is
  slowed and isolated from mainstream mailbox traffic.
- Domain rarity alone is never an AI classifier or permanent block reason.
- An API process cannot create unbounded DNS or identity-provider concurrency.
- Runtime block additions require a reviewed configuration release; an audited
  administrator-managed persistent domain policy remains future work.
- Correct CDN-to-origin client identity is still required before IP/network
  signals can be considered accurate.

## Configuration

- `UP_REGISTRATION_GLOBAL_BURST_LIMIT`, `UP_REGISTRATION_GLOBAL_BURST_WINDOW`
- `UP_REGISTRATION_GLOBAL_LIMIT`, `UP_REGISTRATION_GLOBAL_WINDOW`
- `UP_REGISTRATION_FORM_INTENT_DEVICE_LIMIT`, `UP_REGISTRATION_FORM_INTENT_DEVICE_WINDOW`
- `UP_REGISTRATION_FORM_INTENT_NET_LIMIT`, `UP_REGISTRATION_FORM_INTENT_NET_WINDOW`
- `UP_REGISTRATION_FORM_INTENT_GLOBAL_BURST_LIMIT`, `UP_REGISTRATION_FORM_INTENT_GLOBAL_BURST_WINDOW`
- `UP_REGISTRATION_FORM_INTENT_GLOBAL_LIMIT`, `UP_REGISTRATION_FORM_INTENT_GLOBAL_WINDOW`
- `UP_RISK_REGISTRATION_ISSUE_GLOBAL_BURST_LIMIT`, `UP_RISK_REGISTRATION_ISSUE_GLOBAL_BURST_WINDOW`
- `UP_RISK_REGISTRATION_ISSUE_GLOBAL_LIMIT`, `UP_RISK_REGISTRATION_ISSUE_GLOBAL_WINDOW`
- `UP_RISK_REGISTRATION_ISSUE_MAX_IN_FLIGHT`, `UP_RISK_REGISTRATION_ISSUE_MAX_QUEUED`, `UP_RISK_REGISTRATION_ISSUE_WAIT_TIMEOUT`
- `UP_REGISTRATION_CREATE_MAILBOX_FAMILY_LIMIT`, `UP_REGISTRATION_CREATE_MAILBOX_FAMILY_WINDOW`
- `UP_REGISTRATION_UNFAMILIAR_DOMAIN_BURST_LIMIT`, `UP_REGISTRATION_UNFAMILIAR_DOMAIN_BURST_WINDOW`
- `UP_REGISTRATION_UNFAMILIAR_DOMAIN_LIMIT`, `UP_REGISTRATION_UNFAMILIAR_DOMAIN_WINDOW`
- `UP_REGISTRATION_UNFAMILIAR_MX_BURST_LIMIT`, `UP_REGISTRATION_UNFAMILIAR_MX_BURST_WINDOW`
- `UP_REGISTRATION_UNFAMILIAR_MX_LIMIT`, `UP_REGISTRATION_UNFAMILIAR_MX_WINDOW`
- `UP_REGISTRATION_ADMISSION_MAX_IN_FLIGHT`, `UP_REGISTRATION_ADMISSION_MAX_QUEUED`, `UP_REGISTRATION_ADMISSION_WAIT_TIMEOUT`
- `UP_REGISTRATION_UNFAMILIAR_MAX_IN_FLIGHT`, `UP_REGISTRATION_UNFAMILIAR_MAX_QUEUED`, `UP_REGISTRATION_UNFAMILIAR_PER_DOMAIN`
- `UP_REGISTRATION_BLOCKED_EMAIL_DOMAINS_EXTRA`, `UP_REGISTRATION_BLOCKED_MX_DOMAINS_EXTRA`
- `UP_REGISTRATION_ESTABLISHED_EMAIL_DOMAINS_EXTRA`, `UP_REGISTRATION_ESTABLISHED_MX_DOMAINS_EXTRA`
- `UP_REGISTRATION_VERIFY_GLOBAL_BURST_LIMIT`, `UP_REGISTRATION_VERIFY_GLOBAL_BURST_WINDOW`
- `UP_REGISTRATION_VERIFY_GLOBAL_LIMIT`, `UP_REGISTRATION_VERIFY_GLOBAL_WINDOW`
- `UP_REGISTRATION_HONEYPOT_IP_BLOCKS_ENABLED`

## Verification

`scripts/run-registration-abuse-matrix.sh` runs the race-enabled isolated
device/network/replay, admission, DNS singleflight, domain/MX policy and Redis
cohort tests. The Redis URL must point to a disposable database. The matrix
uses synthetic resolver/provider doubles and never sends email or creates an
account.
