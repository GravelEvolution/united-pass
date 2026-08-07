//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Policy simulation panel
//

"use client";

import { useState } from "react";
import { Button, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { PolicySimulationResult } from "@/features/policies/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./policy-editor.module.css";

export function PolicySimulationPanel() {
  const [action, setAction] = useState("application.manage");
  const [role, setRole] = useState("application_admin");
  const [department, setDepartment] = useState("identity_platform");
  const [simulating, setSimulating] = useState(false);
  const [result, setResult] = useState<PolicySimulationResult | null>(null);

  async function handleSimulate(): Promise<void> {
    setSimulating(true);
    try {
      const simulationResult = await browserCommands.simulatePolicy({
        principalAttributes: { role, department },
        resourceAttributes: {},
        action,
      });
      setResult(simulationResult);
    } catch {
      Toast.error({ content: "模拟失败，请重试。" });
    } finally {
      setSimulating(false);
    }
  }

  return (
    <div className={styles.simulateCard}>
      <h3 style={{ margin: "0 0 16px", fontSize: 14, color: "var(--up-ink-secondary)" }}>策略模拟</h3>
      <div className={styles.simulateForm}>
        <label className={styles.field}>
          <span>操作</span>
          <input
            type="text"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className={styles.textInput}
            placeholder="例如：application.manage"
          />
        </label>
        <label className={styles.field}>
          <span>Principal · role</span>
          <input
            type="text"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className={styles.textInput}
            placeholder="例如：application_admin"
          />
        </label>
        <label className={styles.field}>
          <span>Principal · department</span>
          <input
            type="text"
            value={department}
            onChange={(e) => setDepartment(e.target.value)}
            className={styles.textInput}
            placeholder="例如：identity_platform"
          />
        </label>
        <div>
          <Button
            theme="solid"
            type="primary"
            loading={simulating}
            disabled={simulating}
            onClick={handleSimulate}
          >
            模拟评估
          </Button>
        </div>
      </div>

      {result && (
        <div className={styles.simulateResult} style={{ marginTop: 16 }}>
          <h4>
            决策：
            <StatusBadge
              label={result.decision === "allow" ? "允许" : result.decision === "deny" ? "拒绝" : "无匹配"}
              tone={result.decision === "allow" ? "success" : "danger"}
            />
          </h4>
          {result.matchedPolicyName && (
            <p style={{ margin: "4px 0 8px", fontSize: 13, color: "var(--up-ink-secondary)" }}>
              匹配策略：{result.matchedPolicyName}
            </p>
          )}
          <ul>
            {result.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
          <p style={{ margin: "8px 0 0", fontSize: 12, color: "var(--up-muted-soft)" }}>
            评估时间：{formatSecurityDateTime(result.evaluatedAt)}
          </p>
        </div>
      )}
    </div>
  );
}
