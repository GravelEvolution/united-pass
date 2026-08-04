"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Modal, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type {
  PolicyDetail,
  PolicyDraftInput,
  PolicyEffect,
  PolicyPrincipal,
  PolicyCondition,
} from "@/features/policies/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./policy-editor.module.css";

type PolicyEditorProps = {
  detail?: PolicyDetail;
};

const EFFECT_OPTIONS: Array<{ value: PolicyEffect; label: string }> = [
  { value: "allow", label: "允许" },
  { value: "deny", label: "拒绝" },
];

const OPERATOR_OPTIONS = ["eq", "neq", "in", "not_in", "gt", "lt", "contains"] as const;

export function PolicyEditor({ detail }: PolicyEditorProps) {
  const router = useRouter();
  const isEditing = Boolean(detail);

  const [name, setName] = useState(detail?.name ?? "");
  const [description, setDescription] = useState(detail?.description ?? "");
  const [resource, setResource] = useState(detail?.resource ?? "");
  const [action, setAction] = useState(detail?.action ?? "");
  const [effect, setEffect] = useState<PolicyEffect>(detail?.effect ?? "allow");
  const [principals, setPrincipals] = useState<PolicyPrincipal[]>(detail?.principals ?? []);
  const [conditions, setConditions] = useState<PolicyCondition[]>(detail?.conditions ?? []);
  const [saving, setSaving] = useState(false);
  const [publishing, setPublishing] = useState(false);

  function addPrincipal(): void {
    setPrincipals([...principals, { attribute: "", operator: "eq", value: "" }]);
  }

  function updatePrincipal(index: number, patch: Partial<PolicyPrincipal>): void {
    setPrincipals(principals.map((p, i) => (i === index ? { ...p, ...patch } : p)));
  }

  function removePrincipal(index: number): void {
    setPrincipals(principals.filter((_, i) => i !== index));
  }

  function addCondition(): void {
    setConditions([...conditions, { attribute: "", operator: "eq", value: "" }]);
  }

  function updateCondition(index: number, patch: Partial<PolicyCondition>): void {
    setConditions(conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)));
  }

  function removeCondition(index: number): void {
    setConditions(conditions.filter((_, i) => i !== index));
  }

  function buildInput(): PolicyDraftInput | null {
    if (!name.trim()) {
      Toast.warning({ content: "请填写策略名称。" });
      return null;
    }
    if (!resource.trim()) {
      Toast.warning({ content: "请填写资源标识。" });
      return null;
    }
    if (!action.trim()) {
      Toast.warning({ content: "请填写操作标识。" });
      return null;
    }

    return {
      policyId: detail?.policyId,
      name: name.trim(),
      description: description.trim(),
      resource: resource.trim(),
      action: action.trim(),
      effect,
      principals: principals.filter((p) => p.attribute && p.value),
      conditions: conditions.filter((c) => c.attribute && c.value),
    };
  }

  async function handleSaveDraft(): Promise<void> {
    const input = buildInput();
    if (!input) return;

    setSaving(true);
    try {
      const result = await browserCommands.savePolicyDraft(input);
      Toast.success({ content: `草稿已保存（v${result.version}）。` });
      if (!isEditing) {
        router.push(`/admin/policies/${result.policyId}`);
      } else {
        router.refresh();
      }
    } catch {
      Toast.error({ content: "保存失败，请重试。" });
    } finally {
      setSaving(false);
    }
  }

  async function handlePublish(): Promise<void> {
    const input = buildInput();
    if (!input) return;

    const onOk = async () => {
      setPublishing(true);
      try {
        const draftResult = await browserCommands.savePolicyDraft(input);
        await browserCommands.publishPolicy(draftResult.policyId);
        Toast.success({ content: `策略已发布（v${draftResult.version}）。` });
        router.push(`/admin/policies/${draftResult.policyId}`);
        router.refresh();
      } catch {
        Toast.error({ content: "发布失败，请重试。" });
        throw new Error("publish failed");
      } finally {
        setPublishing(false);
      }
    };

    Modal.warning({
      title: "发布此策略？",
      content: (
        <div>
          <p>发布后策略将立即生效。后端 ABAC 引擎将按此策略评估所有匹配请求。</p>
          <p>已发布的版本不可修改，但可以创建新版本。</p>
          <p>此操作需要重认证。当前为 Mock 实现。</p>
        </div>
      ),
      okText: "确认发布",
      cancelText: "取消",
      okType: "danger",
      onOk,
    });
  }

  return (
    <>
      <Link href="/admin/policies" className={styles.backLink}>
        ← 返回策略列表
      </Link>

      <PageHeader
        eyebrow="ABAC Policy"
        title={isEditing ? detail!.name : "新建策略"}
        description={isEditing ? `策略 ID：${detail!.policyId} · v${detail!.version}` : "定义基于属性的访问控制策略"}
      />

      {detail && (
        <div className={styles.headerCard}>
          <div className={styles.headerInfo}>
            <h1>{detail.name}</h1>
            <p>{detail.description}</p>
          </div>
          <div className={styles.headerMeta}>
            <span>版本：v{detail.version}</span>
            <StatusBadge
              label={detail.status === "published" ? "已发布" : "草稿"}
              tone={detail.status === "published" ? "success" : "warning"}
            />
          </div>
        </div>
      )}

      <div className={styles.editorCard}>
        <form className={styles.form} onSubmit={(e) => { e.preventDefault(); void handleSaveDraft(); }}>
          <label className={styles.field}>
            <span>策略名称 *</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如：应用管理员维护 OAuth 应用"
              className={styles.textInput}
            />
          </label>

          <label className={styles.field}>
            <span>说明</span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="描述策略的用途和影响范围"
              className={styles.textArea}
              rows={2}
            />
          </label>

          <div className={styles.fieldRow}>
            <label className={styles.field}>
              <span>资源 *</span>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                placeholder="例如：application:*"
                className={styles.textInput}
              />
              <small>支持通配符。例如 <code>application:*</code> 匹配所有应用操作。</small>
            </label>

            <label className={styles.field}>
              <span>操作 *</span>
              <input
                type="text"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                placeholder="例如：application.manage"
                className={styles.textInput}
              />
              <small>与 OAuth Scope 独立。例如 <code>application.manage</code>。</small>
            </label>

            <label className={styles.field}>
              <span>效果 *</span>
              <select
                value={effect}
                onChange={(e) => setEffect(e.target.value as PolicyEffect)}
                className={styles.selectInput}
              >
                {EFFECT_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </label>
          </div>

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <h3>Principal 属性</h3>
              <Button theme="borderless" size="small" onClick={addPrincipal}>+ 添加</Button>
            </div>
            {principals.length === 0 ? (
              <p className={styles.emptyText}>尚未添加 Principal 属性。</p>
            ) : (
              principals.map((principal, index) => (
                <div key={index} className={styles.conditionRow}>
                  <input
                    type="text"
                    value={principal.attribute}
                    onChange={(e) => updatePrincipal(index, { attribute: e.target.value })}
                    placeholder="属性名（如 role）"
                    className={styles.textInput}
                  />
                  <select
                    value={principal.operator}
                    onChange={(e) => updatePrincipal(index, { operator: e.target.value as PolicyPrincipal["operator"] })}
                    className={styles.selectInput}
                  >
                    {OPERATOR_OPTIONS.map((op) => (
                      <option key={op} value={op}>{op}</option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={principal.value}
                    onChange={(e) => updatePrincipal(index, { value: e.target.value })}
                    placeholder="值（如 admin）"
                    className={styles.textInput}
                  />
                  <Button theme="borderless" type="danger" size="small" onClick={() => removePrincipal(index)}>×</Button>
                </div>
              ))
            )}
          </div>

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <h3>条件</h3>
              <Button theme="borderless" size="small" onClick={addCondition}>+ 添加</Button>
            </div>
            {conditions.length === 0 ? (
              <p className={styles.emptyText}>尚未添加条件。无条件时仅按 Principal 匹配。</p>
            ) : (
              conditions.map((condition, index) => (
                <div key={index} className={styles.conditionRow}>
                  <input
                    type="text"
                    value={condition.attribute}
                    onChange={(e) => updateCondition(index, { attribute: e.target.value })}
                    placeholder="属性名（如 department）"
                    className={styles.textInput}
                  />
                  <select
                    value={condition.operator}
                    onChange={(e) => updateCondition(index, { operator: e.target.value as PolicyCondition["operator"] })}
                    className={styles.selectInput}
                  >
                    {OPERATOR_OPTIONS.map((op) => (
                      <option key={op} value={op}>{op}</option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={condition.value}
                    onChange={(e) => updateCondition(index, { value: e.target.value })}
                    placeholder="值（如 identity_platform）"
                    className={styles.textInput}
                  />
                  <Button theme="borderless" type="danger" size="small" onClick={() => removeCondition(index)}>×</Button>
                </div>
              ))
            )}
          </div>

          <div className={styles.formActions}>
            <Button theme="borderless" htmlType="button" onClick={() => router.push("/admin/policies")}>
              取消
            </Button>
            <Button
              theme="borderless"
              type="primary"
              htmlType="submit"
              loading={saving}
              disabled={saving || publishing}
            >
              保存草稿
            </Button>
            <Button
              theme="solid"
              type="primary"
              htmlType="button"
              loading={publishing}
              disabled={saving || publishing}
              onClick={handlePublish}
            >
              发布策略
            </Button>
          </div>
        </form>
      </div>

      {detail && detail.versionHistory.length > 0 && (
        <div className={styles.editorCard}>
          <div className={styles.section}>
            <h3>版本历史</h3>
            {detail.versionHistory.map((entry) => (
              <div key={`${entry.version}-${entry.updatedAt}`} className={styles.versionRow}>
                <div>
                  <strong>v{entry.version}</strong>
                  <StatusBadge
                    label={entry.status === "published" ? "已发布" : "草稿"}
                    tone={entry.status === "published" ? "success" : "warning"}
                  />
                </div>
                <div>
                  <p>{entry.changeSummary}</p>
                  <span>{entry.updatedBy} · {formatSecurityDateTime(entry.updatedAt)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
