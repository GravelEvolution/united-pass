//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: OAuth consent screen UI (scope listing and allow/deny)
//

"use client";

import { useEffect, useState } from "react";
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
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { isApiError } from "@/lib/api/api-error";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
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
  // "done" is the frozen mock demo result card. Real mode never renders it:
  // it navigates immediately and keeps the callback URL out of the DOM.
  | { phase: "done"; decision: ConsentDecision; redirectUrl: string }
  | { phase: "navigating"; decision: ConsentDecision }
  // "error" is the mock retry demo. Real one-shot completions use "failed".
  | { phase: "error"; decision: ConsentDecision; message: string }
  | { phase: "failed"; decision: ConsentDecision; failure: CompletionFailure };

// Outcome of a failed one-shot completion. The backend's global single-winner
// completion makes same-request retries unsafe: after any ambiguous failure
// the browser cannot prove the decision was not applied.
type CompletionFailure =
  | { outcome: "relogin" }
  | { outcome: "terminal"; message: string };

function classifyCompletionFailure(error: unknown): CompletionFailure {
  // 401 (session credential required) is the only recoverable failure: the
  // login continuation keeps the same opaque request ID. The session gate
  // rejects before the decision is applied, so nothing was submitted.
  if (isApiError(error) && error.kind === "unauthorized") {
    return { outcome: "relogin" };
  }
  // 409/410 and ambiguous network/provider errors terminate the transaction;
  // the user must restart authorization from the client application.
  return {
    outcome: "terminal",
    message: "此授权请求无法继续，请从发起授权的应用重新开始。",
  };
}

// Auto-completion of an already-authorized consent silently submits "allow"
// exactly once per requestId. The module-level flight map survives React
// StrictMode's unmount/remount: the second effect run attaches to the same
// in-flight Promise instead of issuing a second POST that would collide with
// the backend's single-winner completion. Finished (resolved or rejected)
// flights are kept for the session so revisits never re-POST a completed
// transaction.
const autoCompletionFlights = new Map<string, Promise<{ redirectUrl: string }>>();

function acquireAutoCompletionFlight(requestId: string): Promise<{ redirectUrl: string }> {
  let flight = autoCompletionFlights.get(requestId);
  if (!flight) {
    flight = browserCommands.decideConsent(requestId, "allow");
    autoCompletionFlights.set(requestId, flight);
  }
  return flight;
}

type AutoCompletionState =
  | { phase: "in_flight" }
  | { phase: "failed"; failure: CompletionFailure };

export function AuthorizationConsent({ currentUser, resolution }: AuthorizationConsentProps) {
  const [decisionState, setDecisionState] = useState<DecisionState>({ phase: "idle" });
  const [autoCompletion, setAutoCompletion] = useState<AutoCompletionState>({
    phase: "in_flight",
  });
  const router = useRouter();
  const alreadyRequestedId =
    resolution.status === "already_authorized" ? resolution.requestId : null;

  useEffect(() => {
    // Side effects stay out of render: the POST starts after commit, and
    // StrictMode's double effect run attaches to the same single-flight
    // Promise instead of double-submitting.
    if (alreadyRequestedId === null) return;
    let disposed = false;
    acquireAutoCompletionFlight(alreadyRequestedId).then(
      (result) => {
        if (disposed) return;
        // Credential-grade callback URL: consumed by an immediate same-window
        // navigation — never rendered, parsed, or kept in visible state.
        window.location.assign(result.redirectUrl);
      },
      (error: unknown) => {
        if (disposed) return;
        setAutoCompletion({
          phase: "failed",
          failure: classifyCompletionFailure(error),
        });
      },
    );
    return () => {
      disposed = true;
    };
  }, [alreadyRequestedId]);

  async function handleDecision(choice: ConsentDecision) {
    if (resolution.status !== "valid") return;

    setDecisionState({ phase: "submitting", decision: choice });
    try {
      const result = await browserCommands.decideConsent(
        resolution.request.requestId,
        choice,
      );
      if (!USE_MOCK_DATA_SOURCE) {
        // Real mode: the callback URL may carry the authorization code or
        // the OAuth error response. It is consumed by an immediate
        // same-window navigation and never enters the visible DOM.
        setDecisionState({ phase: "navigating", decision: choice });
        window.location.assign(result.redirectUrl);
        return;
      }
      // Mock mode keeps the frozen interactive result card.
      setDecisionState({ phase: "done", decision: choice, redirectUrl: result.redirectUrl });
    } catch (error) {
      if (!USE_MOCK_DATA_SOURCE) {
        // One-shot completion: the browser cannot prove the decision was not
        // applied, so real mode never offers a same-request retry.
        setDecisionState({
          phase: "failed",
          decision: choice,
          failure: classifyCompletionFailure(error),
        });
        return;
      }
      setDecisionState({
        phase: "error",
        decision: choice,
        message: "提交授权决定失败，请重试。",
      });
      Toast.error({ content: "授权决定提交失败。" });
    }
  }

  if (resolution.status === "valid") {
    if (decisionState.phase === "submitting" || decisionState.phase === "navigating") {
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
              // Same-window redirect to the client's validated Redirect URI.
              // This matches standard OAuth completion behavior.
              window.location.assign(redirectUrl);
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

    if (decisionState.phase === "failed") {
      return (
        <CompletionFailedCard
          decision={decisionState.decision}
          failure={decisionState.failure}
          requestId={resolution.request.requestId}
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
          showMockIndicators={USE_MOCK_DATA_SOURCE}
          onAllow={() => handleDecision("allow")}
          onDeny={() => handleDecision("deny")}
        />
        {USE_MOCK_DATA_SOURCE && <DemoLinks currentRequestId={resolution.request.requestId} />}
      </>
    );
  }

  if (resolution.status === "already_authorized") {
    return <AlreadyAuthorizedCard resolution={resolution} autoCompletion={autoCompletion} />;
  }

  return (
    <>
      <ConsentStateCard resolution={resolution} />
      {USE_MOCK_DATA_SOURCE && <DemoLinks currentRequestId={resolution.requestId} />}
    </>
  );
}

function ConsentCard({
  currentUser,
  resolution,
  showMockIndicators,
  onAllow,
  onDeny,
}: {
  currentUser: CurrentUser;
  resolution: Extract<ConsentResolution, { status: "valid" }>;
  showMockIndicators: boolean;
  onAllow: () => void;
  onDeny: () => void;
}) {
  const { request } = resolution;

  return (
    <div className={styles.card}>
      {showMockIndicators && <div className={styles.mockBadge}>授权请求 · MOCK</div>}
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
        <Button size="large" type="primary" theme="solid" onClick={onAllow}>
          {showMockIndicators ? "允许并继续（Mock）" : "允许并继续"}
        </Button>
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
            <Link href={{ pathname: "/login", query: { requestId: resolution.requestId } }}>
              <Button theme="solid" type="primary">前往登录</Button>
            </Link>
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
      // Handled by AlreadyAuthorizedCard with automatic completion; the union
      // case is exhaustive only because TypeScript still sees it here.
      return null;

    default:
      return null;
  }
}

function AlreadyAuthorizedCard({
  resolution,
  autoCompletion,
}: {
  resolution: Extract<ConsentResolution, { status: "already_authorized" }>;
  autoCompletion: AutoCompletionState;
}) {
  if (autoCompletion.phase === "failed") {
    // One-shot semantics: a failed silent completion is classified like a
    // failed manual decision and never retried against the same request.
    return (
      <CompletionFailedCard
        decision="allow"
        failure={autoCompletion.failure}
        requestId={resolution.requestId}
      />
    );
  }

  // In-flight view: the silent allow is being submitted and the browser will
  // follow the validated Redirect URI via window.location.assign(). The
  // callback URL itself never enters the DOM.
  return (
    <div className={styles.stateCard}>
      <div className={`${styles.stateIcon} ${styles.stateIconSuccess}`}>
        <IconTick size="extra-large" />
      </div>
      <h1>已经授权过此应用</h1>
      <p>你此前已授权 <strong>{resolution.applicationName}</strong> 访问相关数据。</p>
      <p>无需再次确认，正在返回 <strong>{resolution.redirectHost}</strong>…</p>
    </div>
  );
}

function CompletionFailedCard({
  decision,
  failure,
  requestId,
}: {
  decision: ConsentDecision;
  failure: CompletionFailure;
  requestId: string;
}) {
  if (failure.outcome === "relogin") {
    // 401 continuation: the session gate rejected the request before any
    // decision was applied, so logging in with the same request ID resumes
    // the flow safely.
    return (
      <div className={styles.stateCard}>
        <div className={`${styles.stateIcon} ${styles.stateIconWarning}`}>
          <IconUser size="extra-large" />
        </div>
        <h1>需要重新登录</h1>
        <p>登录状态未能验证，你的{decision === "allow" ? "授权" : "拒绝"}决定未被提交。</p>
        <p>请重新登录后继续此授权请求。</p>
        <div className={styles.stateActions}>
          <Link href={{ pathname: "/login", query: { requestId } }}>
            <Button theme="solid" type="primary">前往登录</Button>
          </Link>
        </div>
      </div>
    );
  }

  // Terminal failures (409/410, ambiguous network/provider errors): the
  // completion is one-shot and the browser cannot prove the decision was not
  // applied, so no same-request retry is offered.
  return (
    <div className={styles.stateCard}>
      <div className={`${styles.stateIcon} ${styles.stateIconDanger}`}>
        <IconAlertTriangle size="extra-large" />
      </div>
      <h1>无法继续此授权请求</h1>
      <p>{failure.message}</p>
      <p>授权请求只能完成一次，United Pass 无法确认决定是否已提交，因此不会对同一请求再次提交。</p>
      <div className={styles.stateActions}>
        <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
      </div>
    </div>
  );
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
                ? <>点击下方按钮后将跳转至 <code>{redirectUrl}</code>。</>
                : <>点击下方按钮继续。</>}
            </p>
          </>
        ) : (
          <>
            <p>你已拒绝 <strong>{applicationName}</strong> 的授权请求。应用不会获得任何数据访问权限。</p>
            <p>拒绝结果将返回已验证的 Redirect URI 并携带 OAuth 错误。</p>
          </>
        )}
      </div>
      <div className={styles.stateActions}>
        <Button theme="solid" type="primary" onClick={onContinue}>
          {isAllowed ? "完成并跳转" : "完成并返回"}
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

export function MissingRequestIdCard() {
  return (
    <div className={styles.stateCard}>
      <div className={`${styles.stateIcon} ${styles.stateIconWarning}`}>
        <IconAlertTriangle size="extra-large" />
      </div>
      <h1>缺少授权请求</h1>
      <p>此页面需要由应用发起的授权请求才能继续。</p>
      <p>请从发起授权的应用重新进入，页面不接受自行拼装的请求参数。</p>
      <div className={styles.stateActions}>
        <Link href="/account"><Button theme="solid" type="primary">返回账户中心</Button></Link>
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
