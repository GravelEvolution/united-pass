# Trusted client IP gateway for United Pass

This runbook is a required companion to public registration. Do not reopen
registration until the edge rule, Nginx boundary, application configuration,
and regression probes have all been applied in one reviewed release.

Provider references: Alibaba ESA documents `ali-real-client-ip` as the managed
transform's real client address and explicitly distinguishes it from spoofable
`X-Forwarded-For`; Alibaba CDN documents `Ali-Cdn-Real-Ip` as its origin
request header:

- https://www.alibabacloud.com/help/en/edge-security-acceleration/esa/user-guide/managed-conversion
- https://www.alibabacloud.com/help/en/cdn/user-guide/configure-custom-request-headers

## Trust model

The browser may supply `X-Forwarded-For`, `Ali-Real-Client-IP`,
`Ali-Cdn-Real-Ip`, or `X-Moonstone-Client-IP`. None is trusted merely because
it exists.

Alibaba ESA should enable the managed transform that overwrites
`ali-real-client-ip` with the address that connected to ESA. Alibaba CDN uses
`Ali-Cdn-Real-Ip`. In either product, also overwrite a separate
`X-Moonstone-Edge-Auth` origin-request header with a randomly generated value
kept outside source control. A direct origin request cannot select either Ali
header without that edge proof. Restricting the origin firewall to documented
Alibaba origin-pull ranges or using authenticated origin pull remains
recommended defense in depth.

Nginx then converts the provider-specific boundary into one internal header.
The Go service never reads the Ali headers or `X-Forwarded-For`.

## Nginx HTTP-context maps

Install the following in an Nginx `http` context, for example the panel's
top-level `vhost/nginx/00-moonstone-client-ip.conf`. The secret include must be
root-readable and must not be copied into a release directory.

```nginx
map $http_x_moonstone_edge_auth $moonstone_edge_verified {
    default 0;
    include /etc/moonstone-united-pass/nginx/edge-auth.map;
}

map $moonstone_edge_verified $moonstone_esa_client_ip {
    default "";
    1 $http_ali_real_client_ip;
}

map $moonstone_edge_verified $moonstone_cdn_client_ip {
    default "";
    1 $http_ali_cdn_real_ip;
}

map $moonstone_esa_client_ip $moonstone_edge_client_ip {
    default $moonstone_esa_client_ip;
    "" $moonstone_cdn_client_ip;
}

map $moonstone_edge_client_ip $moonstone_client_ip {
    default $moonstone_edge_client_ip;
    "" $remote_addr;
}
```

The separate secret file contains one quoted value. Generate the value with a
cryptographically secure operator tool; never paste the real value into chat,
logs, shell history, or source control.

```nginx
"REPLACE_WITH_OPERATOR_MANAGED_RANDOM_VALUE" 1;
```

For every Nginx location that proxies United Pass API requests, overwrite the
internal header and discard the caller's forwarding chain:

```nginx
proxy_set_header X-Moonstone-Client-IP $moonstone_client_ip;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
```

When the authenticated edge header is absent, the direct-connect fallback is
the origin TCP address (`$remote_addr`). Caller-provided Ali headers are ignored.
When the edge proof is valid but its selected client value is malformed, the
Go service rejects that internal value and falls back to its Nginx peer; this
fails toward throttling, not bypass.

## Application configuration

The normal local Nginx-to-Go topology uses:

```dotenv
UP_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
UP_REGISTRATION_CREATE_IP_LIMIT=3
UP_REGISTRATION_CREATE_IP_WINDOW=1h
UP_REGISTRATION_CREATE_NET_LIMIT=10
UP_REGISTRATION_CREATE_NET_WINDOW=1h
UP_REGISTRATION_CREATE_EMAIL_LIMIT=3
UP_REGISTRATION_CREATE_EMAIL_WINDOW=24h
UP_REGISTRATION_CREATE_PAIR_LIMIT=2
UP_REGISTRATION_CREATE_PAIR_WINDOW=1h
UP_REGISTRATION_VERIFY_LIMIT=8
UP_REGISTRATION_VERIFY_WINDOW=15m
UP_REGISTRATION_RESEND_LIMIT=3
UP_REGISTRATION_RESEND_WINDOW=30m
UP_REGISTRATION_IPV4_NET_BITS=24
UP_REGISTRATION_IPV6_NET_BITS=56
```

Registration limits intentionally do not reuse `UP_LOGIN_RATE_LIMIT` or
`UP_LOGIN_RATE_WINDOW`; tightening sign-up must not lock existing users out.

## Release gate

1. Keep the emergency Nginx registration closure in place.
2. Configure ESA/CDN to overwrite the real-IP and edge-proof headers.
3. Install the Nginx maps and secret include; run `nginx -t` and hot reload.
4. Add the application environment values through the existing secret/config
   mechanism.
5. Build and stage an immutable API release. Do not edit a `current` directory.
6. Run unit, race, build, and isolated Redis integration tests.
7. Probe direct-origin requests with forged XFF, Ali, and internal headers;
   they must share only the direct TCP address budget.
8. Probe edge requests with several different emails; the fourth request from
   one address must return the stable 429 rate-limit envelope while login is
   still functional.
9. Remove the emergency registration closure only after those probes pass.
