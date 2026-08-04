"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Avatar, Button, Toast } from "@douyinfe/semi-ui";
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
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";
import styles from "./authorization-consent.module.css";

type AuthorizationConsentProps = {
  currentUser?: CurrentUser;
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

type DecisionState =
  | { phase: "idle" }
  | { phase: "submitting"; decision: ConsentDecision }
  | { phase: "done"; decision: ConsentDecision; redirectUrl: string }
  | { phase: "error"; decision: ConsentDecision; message: string };

export function AuthorizationConsent({ currentUser, resolution }: AuthorizationConsentProps) {
  const [decisionState, setDecisionState] = useState<DecisionState>({ phase: "idle" });
  const router = useRouter();

  async function handleDecision(choice: ConsentDecision) {
    if (resolution.status !== "valid") return;

    setDecisionState({ phase: "submitting", decision: choice });
    try {
      const result = await mockUnitedPassDataSource.decideConsent(
        resolution.request.requestId,
        choice,
      );
      setDecisionState({ phase: "done", decision: choice, redirectUrl: result.redirectUrl });
    } catch {
      setDecisionState({
        phase: "error",
        decision: choice,
        message: "提交授权决定失败，请重试。",
      });
      Toast.error({ content: "授权决定提交失败。" });
    }
  }

  if (resolution.status === "valid") {
    if (decisionState.phase === "submitting") {
      return (
        <DecisionPending
          decision={decisionState.decision}
          applicationName={resolution.request.applicationName}
        />
      );
    }

    if (decisionState.phase === "done") {
      const { redirectUrl, decision } = decisionState;
      return (
        <DecisionResult
          decision={decision}
          applicationName={resolution.request.applicationName}
          redirectUrl={redirectUrl}
          onContinue={() => {
            if (redirectUrl.startsWith("/")) {
              router.push(redirectUrl);
            } else {
              window.open(redirectUrl, "_blank", "noopener,noreferrer");
            }
          }}
        />
      );
    }

    if (decisionState.phase === "error") {
      return (
        <DecisionError
          decision={decisionState.decision}
          message={decisionState.message}
          onRetry={() => setDecisionState({ phase: "idle" })}
        />
      );
    }

    if (!currentUser) {
      return null;
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
          <p>登录后请使用原授权链接返回此页面继续流程。</p>
          <div className={styles.stateActions}>
            <Link href={`/login?requestId=${resolution.requestId}`}><Button theme="solid" type="primary">前往登录</Button></Link>
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
          <p>无需再次确认。点击下方按钮返回应用。</p>
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

function DecisionPending({
  decision,
  applicationName,
}: {
  decision: ConsentDecision;
  applicationName: string;
}) {
  return (
    <div className={styles.stateCard}>
      <div className={styles.stateIcon}>
        <IconHourglass size="extra-large" />
      </div>
      <h1>{decision === "allow" ? "正在授权…" : "正在拒绝…"}</h1>
      <p>正在向 <strong>{applicationName}</strong> 提交你的授权决定。</p>
    </div>
  );
}

function DecisionResult({
  decision,
  applicationName,
  redirectUrl,
  onContinue,
}: {
  decision: ConsentDecision;
  applicationName: string;
  redirectUrl: string;
  onContinue: () => void;
}) {
  const isAllowed = decision === "allow";
  const isExternalRedirect = isAllowed && !redirectUrl.startsWith("/");

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
            <p>
              {isExternalRedirect
                ? <>授权完成后将跳转至 <code>{redirectUrl}</code>（Mock，不会真实跳转至外部地址）。</>
                : <>点击下方按钮继续。</>}
            </p>
          </>
        ) : (
          <p>你已拒绝 <strong>{applicationName}</strong> 的授权请求。应用不会获得任何数据访问权限。</p>
        )}
      </div>
      <div className={styles.stateActions}>
        <Button theme="solid" type="primary" onClick={onContinue}>
          {isAllowed ? "完成并跳转" : "返回账户中心"}
        </Button>
      </div>
    </div>
  );
}

function DecisionError({
  decision,
  message,
  onRetry,
}: {
  decision: ConsentDecision;
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className={styles.stateCard}>
      <div className={`${styles.stateIcon} ${styles.stateIconDanger}`}>
        <IconAlertTriangle size="extra-large" />
      </div>
      <h1>提交失败</h1>
      <p>{message}</p>
      <p>你的{decision === "allow" ? "授权" : "拒绝"}决定尚未提交。</p>
      <div className={styles.stateActions}>
        <Button theme="solid" type="primary" onClick={onRetry}>返回重试</Button>
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
