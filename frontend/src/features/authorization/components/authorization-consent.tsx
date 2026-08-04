"use client";

import { useRouter } from "next/navigation";
import { Avatar, Button } from "@douyinfe/semi-ui";
import { IconKey, IconLock } from "@douyinfe/semi-icons";
import type { ConsentRequest } from "@/features/authorization/types";
import type { CurrentUser } from "@/types/identity";
import styles from "./authorization-consent.module.css";

type AuthorizationConsentProps = {
  currentUser: CurrentUser;
  consentRequest: ConsentRequest;
};

export function AuthorizationConsent({ currentUser, consentRequest }: AuthorizationConsentProps) {
  const router = useRouter();

  return (
    <div className={styles.card}>
      <div className={styles.mockBadge}>授权请求 · MOCK</div>
      <div className={styles.application}>
        <div className={styles.applicationIcon}><IconKey size="extra-large" /></div>
        <div>
          <h1>{consentRequest.applicationName}</h1>
          <p>{consentRequest.applicationDescription}</p>
          <span>由 {consentRequest.applicationOwner} 提供</span>
        </div>
      </div>

      <section className={styles.identity} aria-labelledby="current-identity-title">
        <Avatar color="blue">{currentUser.displayName.slice(0, 1)}</Avatar>
        <div>
          <span id="current-identity-title">当前身份</span>
          <strong>{currentUser.displayName}</strong>
          <p>{currentUser.email}</p>
        </div>
      </section>

      <section className={styles.permissions} aria-labelledby="permissions-title">
        <h2 id="permissions-title">此应用希望：</h2>
        <ul>
          {consentRequest.scopes.map((requestedScope) => (
            <li key={requestedScope.scope}>
              <IconLock aria-hidden="true" />
              <div>
                <strong>{requestedScope.label}</strong>
                <p>{requestedScope.description}</p>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <p className={styles.redirectNotice}>
        允许后将返回 <strong>{consentRequest.redirectHost}</strong>。OAuth Scope 仅描述授权数据，不代表业务管理权限。
      </p>

      <div className={styles.actions}>
        <Button size="large" theme="outline" onClick={() => router.push("/account")}>拒绝</Button>
        <Button size="large" type="primary" theme="solid" onClick={() => router.push("/account")}>允许并继续（Mock）</Button>
      </div>
    </div>
  );
}
