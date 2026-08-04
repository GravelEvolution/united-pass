"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Avatar, Button } from "@douyinfe/semi-ui";
import {
  IconAlertTriangle,
  IconKey,
  IconLock,
  IconTick,
  IconClose,
  IconHourglass,
  IconUser,
} from "@douyinfe/semi-icons";
import type { ConsentDecision, ConsentResolution } from "@/features/authorization/types";
import type { CurrentUser } from "@/types/identity";
import styles from "./authorization-consent.module.css";

type AuthorizationConsentProps = {
  currentUser: CurrentUser;
  resolution: ConsentResolution;
};

const consentStateDemos = [
  { requestId: "consent_demo_001", label: "有效请求" },
  { requestId: "consent_demo_002", label: "请求已过期" },
  { requestId: "consent_demo_003", label: "Client 不存在" },
  { requestId: "consent_demo_004", label: "Redirect URI 不匹配" },
  { requestId: "consent_demo_005", label: "用户未登录" },
  { requestId: "consent_demo_006", label: "Scope 不允许" },
  { requestId: "consent_demo_007", label: "已经授权过" },
];

export function AuthorizationConsent({ currentUser, resolution }: AuthorizationConsentProps) {
  const [decision, setDecision] = useState<ConsentDecision | null>(null);
  const router = useRouter();

  function handleDecision(choice: ConsentDecision) {
    setDecision(choice);
  }

  if (resolution.status === "valid") {
    if (decision) {
      return (
        <DecisionResult
          decision={decision}
          applicationName={resolution.request.applicationName}
          redirectHost={resolution.request.redirectHost}
          onContinue={() => router.push(decision === "allow" ? "/account/applications" : "/account")}
        />
      );
    }

    return (
      <>
        <ConsentCard
          currentUser={currentUser}
          resolution={resolution}
          onAllow={() => handleDecision("allow")}
          onDeny={() => handleDecision("deny")}
        />
        <DemoLinks currentRequestId={resolution.request.requestId} />
      </>
    );
  }

  return (
    <>
      <ConsentStateCard resolution={resolution} />
      <DemoLinks currentRequestId={resolution.requestId} />
    </>
  );
}

function ConsentCard({
  currentUser,
  resolution,
  onAllow,
  onDeny,
}: {
  currentUser: CurrentUser;
  resolution: Extract<ConsentResolution, { status: "valid" }>;
  onAllow: () => void;
  onDeny: () => void;
}) {
  const { request } = resolution;

  return (
    <div className={styles.card}>
      <div className={styles.mockBadge}>授权请求 · MOCK</div>
      <div className={styles.application}>
        <div className={styles.applicationIcon}><IconKey size="extra-large" /></div>
        <div>
          <h1>{request.applicationName}</h1>
          <p>{request.applicationDescription}</p>
          <span>由 {request.applicationOwner} 提供</span>
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
          {request.scopes.map((requestedScope) => (
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
        允许后将返回 <strong>{request.redirectHost}</strong>。OAuth Scope 仅描述授权数据，不代表业务管理权限。
      </p>

      <div className={styles.actions}>
        <Button size="large" theme="outline" onClick={onDeny}>拒绝</Button>
        <Button size="large" type="primary" theme="solid" onClick={onAllow}>允许并继续（Mock）</Button>
      </div>
    </div>
  );
}

function ConsentStateCard({ resolution }: { resolution: ConsentResolution }) {
  switch (resolution.status) {
    case "expired":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconWarning}`}>
            <IconHourglass size="extra-large" />
          </div>
          <h1>授权请求已过期</h1>
          <p>请求 <code>{resolution.requestId}</code> 已于 {resolution.expiredAt} 过期。</p>
          <p>请返回发起授权的应用重新开始流程。</p>
          <div className={styles.stateActions}>
            <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
          </div>
        </div>
      );

    case "client_not_found":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconDanger}`}>
            <IconClose size="extra-large" />
          </div>
          <h1>应用不存在</h1>
          <p>请求 <code>{resolution.requestId}</code> 对应的 OAuth 客户端不存在或已被删除。</p>
          <p>页面不接受用户自行拼装的应用名称或任意回跳地址。</p>
          <div className={styles.stateActions}>
            <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
          </div>
        </div>
      );

    case "redirect_mismatch":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconDanger}`}>
            <IconAlertTriangle size="extra-large" />
          </div>
          <h1>Redirect URI 不匹配</h1>
          <p>请求 <code>{resolution.requestId}</code> 携带的重定向地址与已登记的 Redirect URI 不一致。</p>
          <p>页面不会接受 <code>{resolution.attemptedRedirect}</code> 等未校验的地址。</p>
          <div className={styles.stateActions}>
            <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
          </div>
        </div>
      );

    case "unauthenticated":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconWarning}`}>
            <IconUser size="extra-large" />
          </div>
          <h1>需要登录</h1>
          <p>请求 <code>{resolution.requestId}</code> 需要已登录的用户身份才能完成授权。</p>
          <p>请先登录后再返回此页面继续授权流程。</p>
          <div className={styles.stateActions}>
            <Link href="/login"><Button theme="solid" type="primary">前往登录</Button></Link>
          </div>
        </div>
      );

    case "scope_not_allowed":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconDanger}`}>
            <IconAlertTriangle size="extra-large" />
          </div>
          <h1>请求的 Scope 不被允许</h1>
          <p>请求 <code>{resolution.requestId}</code> 包含此应用未登记的 Scope：</p>
          <div className={styles.scopeList}>
            {resolution.disallowedScopes.map((scope) => (
              <code key={scope}>{scope}</code>
            ))}
          </div>
          <p>请联系应用管理员确认允许的 Scope 范围。</p>
          <div className={styles.stateActions}>
            <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
          </div>
        </div>
      );

    case "already_authorized":
      return (
        <div className={styles.stateCard}>
          <div className={`${styles.stateIcon} ${styles.stateIconSuccess}`}>
            <IconTick size="extra-large" />
          </div>
          <h1>已经授权过此应用</h1>
          <p>你此前已授权 <strong>{resolution.applicationName}</strong> 访问相关数据。</p>
          <p>无需再次确认，将自动跳转回 <code>{resolution.redirectHost}</code>。</p>
          <div className={styles.stateActions}>
            <Link href="/account/applications"><Button theme="solid" type="primary">查看授权应用</Button></Link>
            <Link href="/account"><Button theme="outline">返回账户中心</Button></Link>
          </div>
        </div>
      );

    default:
      return null;
  }
}

function DecisionResult({
  decision,
  applicationName,
  redirectHost,
  onContinue,
}: {
  decision: ConsentDecision;
  applicationName: string;
  redirectHost: string;
  onContinue: () => void;
}) {
  const isAllowed = decision === "allow";

  return (
    <div className={styles.stateCard}>
      <div className={`${styles.stateIcon} ${isAllowed ? styles.stateIconSuccess : styles.stateIconDanger}`}>
        {isAllowed ? <IconTick size="extra-large" /> : <IconClose size="extra-large" />}
      </div>
      <div className={styles.decisionResult}>
        <h1>{isAllowed ? "授权成功" : "已拒绝授权"}</h1>
        {isAllowed ? (
          <>
            <p>你已授权 <strong>{applicationName}</strong> 访问请求的数据。</p>
            <p>正在跳转回 <code>{redirectHost}</code>（Mock，不会真实跳转外部地址）。</p>
          </>
        ) : (
          <p>你已拒绝 <strong>{applicationName}</strong> 的授权请求。应用不会获得任何数据访问权限。</p>
        )}
      </div>
      <div className={styles.stateActions}>
        <Button theme="solid" type="primary" onClick={onContinue}>
          {isAllowed ? "查看授权应用" : "返回账户中心"}
        </Button>
      </div>
    </div>
  );
}

function DemoLinks({ currentRequestId }: { currentRequestId: string }) {
  return (
    <div className={styles.demoLinks}>
      <p>Mock 状态演示（点击切换 requestId）</p>
      <ul>
        {consentStateDemos.map((demo) => (
          <li key={demo.requestId}>
            {demo.requestId === currentRequestId ? "→ " : ""}
            <Link href={`/authorize?requestId=${demo.requestId}`}>
              <code>{demo.requestId}</code> — {demo.label}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
