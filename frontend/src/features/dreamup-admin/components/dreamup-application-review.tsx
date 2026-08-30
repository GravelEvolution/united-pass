"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Banner, Button, Modal, Select, Tag, TextArea, Toast } from "@douyinfe/semi-ui";
import { dreamUPAdminCommands } from "../api/browser-commands";
import { classifyDreamUPAdminError } from "../error-state";
import type {
  AdmissionConsensus,
  DreamUPApplicationDetail,
  DreamUPApplicationStatus,
  ReviewRecommendation,
} from "../types";
import styles from "./dreamup-admin.module.css";

const answerLabels: Readonly<Record<string, string>> = {
  city: "所在城市",
  affiliation_type: "当前身份",
  affiliation_name: "学校或组织",
  primary_role: "主要方向",
  experience_level: "实践经验",
  skill_tags: "技能标签",
  problem_to_solve: "想解决的真实问题",
  first_build_step: "44 小时内的第一步",
  what_you_bring: "能为团队带来什么",
  collaboration_goal: "希望怎样协作",
  portfolio_urls: "作品链接",
  team_preference: "组队偏好",
  existing_team_details: "已有团队情况",
};

const statusLabels: Record<DreamUPApplicationStatus, string> = {
  submitted: "待审核",
  under_review: "审核中",
  accepted: "已录取",
  waitlisted: "候补",
  rejected: "已拒绝",
  withdrawn: "已撤回",
};

const recommendationLabels: Record<ReviewRecommendation, string> = {
  accept: "建议录取",
  waitlist: "建议候补",
  reject: "建议拒绝",
  needs_discussion: "需要讨论",
};

function mutationMessage(error: unknown): string {
  return classifyDreamUPAdminError(error).message;
}

export function DreamUPApplicationReview({
  eventId,
  initialDetail,
  initialConsensus,
}: {
  eventId: string;
  initialDetail: DreamUPApplicationDetail;
  initialConsensus: AdmissionConsensus;
}) {
  const router = useRouter();
  const [detail, setDetail] = useState(initialDetail);
  const [consensus, setConsensus] = useState(initialConsensus);
  const [recommendation, setRecommendation] = useState<ReviewRecommendation>(initialDetail.ownReview?.recommendation ?? "needs_discussion");
  const [note, setNote] = useState(initialDetail.ownReview?.note ?? "");
  const [reviewPending, setReviewPending] = useState(false);
  const [decisionPending, setDecisionPending] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const application = detail.application;
  const effectiveStatus = consensus.applicationStatus;
  const consensusClosed = consensus.status === "finalized" || effectiveStatus === "accepted" || effectiveStatus === "rejected" || effectiveStatus === "withdrawn";

  async function saveReview(): Promise<void> {
    setReviewPending(true);
    try {
      const ownReview = await dreamUPAdminCommands.saveOwnReview(
        eventId,
        application.id,
        detail.ownReview?.version ?? 0,
        { recommendation, note },
      );
      setDetail((current) => ({ ...current, ownReview }));
      Toast.success({ content: "本人审核意见已保存。" });
    } catch (error) {
      Toast.error({ content: mutationMessage(error) });
    } finally {
      setReviewPending(false);
    }
  }

  async function toggleApproval(): Promise<void> {
    setDecisionPending(true);
    try {
      const next = consensus.ownApproval
        ? await dreamUPAdminCommands.withdrawAdmissionApproval(eventId, application.id, consensus.version)
        : await dreamUPAdminCommands.approveAdmission(eventId, application.id, consensus.version);
      setConsensus(next);
      Toast.success({ content: next.applicationStatus === "accepted" ? "第三份独立同意已形成，报名已录取。" : next.ownApproval ? "你的录取同意已提交。" : "你的录取同意已撤回。" });
    } catch (error) {
      Toast.error({ content: mutationMessage(error) });
      router.refresh();
    } finally {
      setDecisionPending(false);
    }
  }

  async function reject(): Promise<void> {
    if (rejectReason.trim().length < 10) {
      Toast.warning({ content: "请填写至少 10 个字的拒绝原因。" });
      return;
    }
    setDecisionPending(true);
    try {
      const next = await dreamUPAdminCommands.rejectApplication(eventId, application.id, application.version, rejectReason.trim());
      setDetail(next);
      setConsensus((current) => ({ ...current, status: "cancelled", applicationStatus: "rejected" }));
      setRejectOpen(false);
      Toast.success({ content: "报名已拒绝，原因已记录。" });
    } catch (error) {
      Toast.error({ content: mutationMessage(error) });
    } finally {
      setDecisionPending(false);
    }
  }

  return (
    <>
      <header className={styles.reviewHeader}>
        <div>
          <Link href={`/admin/dreamup/${encodeURIComponent(eventId)}`}>← 返回报名列表</Link>
          <h1>{application.displayHandle}</h1>
          <p>报名身份由不可逆展示代号代替；本页面只处理评审所需内容。</p>
        </div>
        <Tag color={effectiveStatus === "accepted" ? "green" : effectiveStatus === "rejected" ? "red" : "blue"} size="large">
          {statusLabels[effectiveStatus]}
        </Tag>
      </header>

      <div className={styles.reviewGrid}>
        <main className={styles.answerCard}>
          <div className={styles.sectionHeading}><span>报名内容</span><h2>这个年轻人想做什么</h2></div>
          <dl className={styles.answerList}>
            {Object.entries(application.reviewAnswers).map(([key, value]) => (
              <div key={key}>
                <dt>{answerLabels[key] ?? key}</dt>
                <dd>{Array.isArray(value) ? value.join(" · ") : value || "—"}</dd>
              </div>
            ))}
          </dl>
        </main>

        <aside className={styles.reviewAside}>
          <section className={styles.actionCard}>
            <div className={styles.sectionHeading}><span>本人审核</span><h2>留下独立判断</h2></div>
            <label className={styles.formField}>
              <span>建议</span>
              <Select value={recommendation} onChange={(value) => setRecommendation(value as ReviewRecommendation)}>
                {Object.entries(recommendationLabels).map(([value, label]) => <Select.Option key={value} value={value}>{label}</Select.Option>)}
              </Select>
            </label>
            <label className={styles.formField}>
              <span>审核备注</span>
              <TextArea value={note} onChange={setNote} maxCount={2000} autosize={{ minRows: 4, maxRows: 8 }} placeholder="说明你的判断依据；仅你本人和获授权流程可使用。" />
            </label>
            <Button block theme="solid" type="primary" loading={reviewPending} onClick={() => void saveReview()}>保存本人审核</Button>
          </section>

          <section className={styles.actionCard}>
            <div className={styles.sectionHeading}><span>录取共识</span><h2>录取同意 {consensus.approvalCount}/{consensus.requiredApprovals}</h2></div>
            <div className={styles.consensusTrack} aria-label={`已有 ${consensus.approvalCount} 份录取同意，需要 ${consensus.requiredApprovals} 份`}>
              {Array.from({ length: consensus.requiredApprovals }, (_, index) => <span key={index} data-filled={index < consensus.approvalCount} />)}
            </div>
            <p className={styles.muted}>三名不同管理员分别同意后，系统才会自动录取；本页没有单人录取按钮。</p>
            <Button
              block
              theme={consensus.ownApproval ? "outline" : "solid"}
              type={consensus.ownApproval ? "tertiary" : "primary"}
              disabled={consensusClosed}
              loading={decisionPending}
              onClick={() => void toggleApproval()}
            >
              {consensus.ownApproval ? "撤回我的录取同意" : "同意录取"}
            </Button>
            <Button block theme="borderless" type="danger" disabled={consensusClosed} onClick={() => setRejectOpen(true)}>拒绝报名</Button>
          </section>

          <Banner
            type="info"
            title="敏感资料不会自动加载"
            description="受限身份与法律材料由独立的高级授权流程控制。本基础审核页不请求、缓存或展示这些内容。"
          />
        </aside>
      </div>

      <Modal
        title="拒绝这份报名"
        visible={rejectOpen}
        onCancel={() => setRejectOpen(false)}
        onOk={() => void reject()}
        confirmLoading={decisionPending}
        okText="确认拒绝"
        cancelText="取消"
      >
        <p className={styles.modalCopy}>拒绝会结束当前录取共识。请写清原因，便于审计与后续沟通。</p>
        <TextArea value={rejectReason} onChange={setRejectReason} maxCount={500} autosize={{ minRows: 4, maxRows: 7 }} placeholder="至少 10 个字" />
      </Modal>
    </>
  );
}
