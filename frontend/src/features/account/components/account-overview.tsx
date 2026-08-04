"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { Button, Input, Modal, Toast } from "@douyinfe/semi-ui";
import { IconEdit } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { CurrentUser } from "@/types/identity";
import styles from "./account-panels.module.css";

type AccountOverviewProps = {
  currentUser: CurrentUser;
};

type EditableProfile = Pick<CurrentUser, "displayName" | "nickname" | "avatarUrl">;

type ProfileErrors = {
  displayName?: string;
  avatarUrl?: string;
};

function createProfileDraft(currentProfile: EditableProfile): EditableProfile {
  return {
    displayName: currentProfile.displayName,
    nickname: currentProfile.nickname ?? "",
    avatarUrl: currentProfile.avatarUrl ?? "",
  };
}

function normalizeAvatarUrl(avatarUrl: string): { normalizedUrl?: string; error?: string } {
  const trimmedAvatarUrl = avatarUrl.trim();
  if (!trimmedAvatarUrl) return {};

  try {
    const parsedAvatarUrl = new URL(trimmedAvatarUrl);
    if (parsedAvatarUrl.protocol !== "https:") {
      return { error: "头像 URL 必须使用 HTTPS。" };
    }
    return { normalizedUrl: parsedAvatarUrl.toString() };
  } catch {
    return { error: "请输入有效的头像 URL。" };
  }
}

export function AccountOverview({ currentUser }: AccountOverviewProps) {
  const [profile, setProfile] = useState<EditableProfile>(createProfileDraft(currentUser));
  const [profileDraft, setProfileDraft] = useState<EditableProfile>(createProfileDraft(currentUser));
  const [profileErrors, setProfileErrors] = useState<ProfileErrors>({});
  const [isEditorVisible, setIsEditorVisible] = useState(false);
  const preferredName = profile.nickname?.trim() || profile.displayName;
  const draftPreviewAvatarUrl = normalizeAvatarUrl(profileDraft.avatarUrl ?? "").normalizedUrl;

  function openProfileEditor() {
    setProfileDraft(createProfileDraft(profile));
    setProfileErrors({});
    setIsEditorVisible(true);
  }

  function closeProfileEditor() {
    setIsEditorVisible(false);
    setProfileErrors({});
  }

  function handleProfileSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedDisplayName = profileDraft.displayName.trim();
    const normalizedNickname = profileDraft.nickname?.trim();
    const avatarUrlResult = normalizeAvatarUrl(profileDraft.avatarUrl ?? "");
    const nextErrors: ProfileErrors = {};

    if (!normalizedDisplayName) {
      nextErrors.displayName = "显示名称不能为空。";
    }
    if (avatarUrlResult.error) {
      nextErrors.avatarUrl = avatarUrlResult.error;
    }
    if (Object.keys(nextErrors).length > 0) {
      setProfileErrors(nextErrors);
      return;
    }

    setProfile({
      displayName: normalizedDisplayName,
      nickname: normalizedNickname,
      avatarUrl: avatarUrlResult.normalizedUrl,
    });
    setProfileErrors({});
    setIsEditorVisible(false);
    Toast.success({ content: "资料已在当前 Mock 页面更新，刷新后会恢复。" });
  }

  return (
    <>
      <PageHeader
        eyebrow="My identity"
        title={`你好，${preferredName}`}
        description="查看统一账户资料，以及与该账户关联的用户和员工身份。"
        action={
          <Button type="primary" theme="solid" icon={<IconEdit />} onClick={openProfileEditor}>
            编辑资料
          </Button>
        }
      />

      <div className={styles.overviewGrid}>
        <section className={styles.heroCard}>
          <div
            className={`${styles.avatar} ${profile.avatarUrl ? styles.avatarWithImage : ""}`}
            style={profile.avatarUrl ? { backgroundImage: `url(${profile.avatarUrl})` } : undefined}
            role="img"
            aria-label={`${profile.displayName}的头像`}
          >
            {!profile.avatarUrl && profile.displayName.slice(0, 1)}
          </div>
          <div className={styles.heroCopy}>
            <span className={styles.label}>统一账户</span>
            <h2>{profile.displayName}</h2>
            <p>{profile.nickname ? `${profile.nickname} · ${currentUser.email}` : currentUser.email}</p>
            <div className={styles.badges}>
              <StatusBadge label="外部用户能力" tone="info" />
              {currentUser.employeeProfile && <StatusBadge label="员工档案已关联" tone="success" />}
            </div>
          </div>
          <div className={styles.stableId}>
            <span>稳定用户 ID</span>
            <code>{currentUser.userId}</code>
          </div>
        </section>

        <section className={styles.card}>
          <div className={styles.cardHeading}>
            <div>
              <span className={styles.label}>ACCOUNT DETAILS</span>
              <h2>基本资料</h2>
            </div>
            <StatusBadge label="已验证" tone="success" />
          </div>
          <dl className={styles.detailList}>
            <div><dt>显示名称</dt><dd>{profile.displayName}</dd></div>
            <div><dt>昵称</dt><dd>{profile.nickname || "未设置"}</dd></div>
            <div><dt>头像 URL</dt><dd className={styles.urlValue}>{profile.avatarUrl || "未设置"}</dd></div>
            <div><dt>邮箱地址</dt><dd>{currentUser.email}</dd></div>
            <div><dt>手机号码</dt><dd>{currentUser.phoneMasked}</dd></div>
          </dl>
        </section>

        <section className={styles.card}>
          <div className={styles.cardHeading}>
            <div>
              <span className={styles.label}>EMPLOYEE PERSONA</span>
              <h2>员工档案</h2>
            </div>
            <StatusBadge label={currentUser.employeeProfile ? "在职" : "未关联"} tone={currentUser.employeeProfile ? "success" : "neutral"} />
          </div>
          {currentUser.employeeProfile ? (
            <dl className={styles.detailList}>
              <div><dt>员工编号</dt><dd>{currentUser.employeeProfile.employeeId}</dd></div>
              <div><dt>所属部门</dt><dd>{currentUser.employeeProfile.departmentName}</dd></div>
              <div><dt>职位</dt><dd>{currentUser.employeeProfile.title}</dd></div>
            </dl>
          ) : (
            <p className={styles.emptyText}>此账户目前没有员工档案，但仍可使用普通用户能力。</p>
          )}
        </section>
      </div>

      <Modal
        title="编辑基本资料"
        visible={isEditorVisible}
        footer={null}
        width={520}
        maskClosable={false}
        onCancel={closeProfileEditor}
      >
        <form className={styles.profileForm} onSubmit={handleProfileSubmit}>
          <div className={styles.profilePreview}>
            <div
              className={`${styles.avatar} ${draftPreviewAvatarUrl ? styles.avatarWithImage : ""}`}
              style={draftPreviewAvatarUrl ? { backgroundImage: `url(${draftPreviewAvatarUrl})` } : undefined}
              aria-hidden="true"
            >
              {!draftPreviewAvatarUrl && (profileDraft.displayName.trim().slice(0, 1) || "?")}
            </div>
            <div>
              <strong>{profileDraft.displayName.trim() || "显示名称"}</strong>
              <span>{profileDraft.nickname?.trim() || "尚未设置昵称"}</span>
            </div>
          </div>

          <label className={styles.profileField} htmlFor="profile-display-name">
            <span>显示名称</span>
            <Input
              id="profile-display-name"
              value={profileDraft.displayName}
              onChange={(displayName) => {
                setProfileDraft((currentDraft) => ({ ...currentDraft, displayName }));
                setProfileErrors((currentErrors) => ({ ...currentErrors, displayName: undefined }));
              }}
              maxLength={80}
              validateStatus={profileErrors.displayName ? "error" : "default"}
              aria-invalid={Boolean(profileErrors.displayName)}
              aria-errormessage={profileErrors.displayName ? "profile-display-name-error" : undefined}
              required
            />
            {profileErrors.displayName && <small id="profile-display-name-error" className={styles.profileError} role="alert">{profileErrors.displayName}</small>}
          </label>

          <label className={styles.profileField} htmlFor="profile-nickname">
            <span>昵称（可选）</span>
            <Input
              id="profile-nickname"
              value={profileDraft.nickname}
              onChange={(nickname) => setProfileDraft((currentDraft) => ({ ...currentDraft, nickname }))}
              placeholder="希望其他用户看到的称呼"
              maxLength={40}
            />
          </label>

          <label className={styles.profileField} htmlFor="profile-avatar-url">
            <span>头像 URL（可选）</span>
            <Input
              id="profile-avatar-url"
              type="url"
              value={profileDraft.avatarUrl}
              onChange={(avatarUrl) => {
                setProfileDraft((currentDraft) => ({ ...currentDraft, avatarUrl }));
                setProfileErrors((currentErrors) => ({ ...currentErrors, avatarUrl: undefined }));
              }}
              placeholder="https://example.com/avatar.png"
              validateStatus={profileErrors.avatarUrl ? "error" : "default"}
              aria-invalid={Boolean(profileErrors.avatarUrl)}
              aria-errormessage={profileErrors.avatarUrl ? "profile-avatar-url-error" : undefined}
            />
            <small className={profileErrors.avatarUrl ? styles.profileError : undefined} id={profileErrors.avatarUrl ? "profile-avatar-url-error" : undefined}>
              {profileErrors.avatarUrl ?? "仅接受 HTTPS 图片地址；加载远程头像可能向图片服务暴露网络信息。"}
            </small>
          </label>

          <p className={styles.profileNotice}>邮箱和手机号码属于安全联系方式，接入后端后需要通过独立验证流程修改。</p>

          <div className={styles.profileActions}>
            <Button theme="outline" onClick={closeProfileEditor}>取消</Button>
            <Button htmlType="submit" type="primary" theme="solid">保存 Mock 修改</Button>
          </div>
        </form>
      </Modal>
    </>
  );
}
