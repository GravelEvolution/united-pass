"use client";

import type { ChangeEvent, FormEvent } from "react";
import { useRef, useState } from "react";
import { Button, Input, Modal, Toast } from "@douyinfe/semi-ui";
import { IconDelete, IconEdit, IconUpload } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { CurrentUser } from "@/types/identity";
import { ContactVerificationModal } from "./contact-verification-modal";
import type { ContactKind } from "../utils/contact-validation";
import { AvatarValidationError, sanitizeAvatarFile } from "../utils/avatar-file";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./account-panels.module.css";

type AccountOverviewProps = {
  currentUser: CurrentUser;
};

type EditableProfile = Pick<CurrentUser, "displayName" | "nickname"> & {
  avatarFileName?: string;
  avatarPreviewUrl?: string;
};

type ProfileErrors = {
  displayName?: string;
  avatarFile?: string;
};

type ContactDetails = Pick<CurrentUser, "email" | "phoneMasked">;

function getControlledAvatarUrl(avatarUrl: string | undefined): string | undefined {
  return avatarUrl?.startsWith("/api/v1/media/avatars/") ? avatarUrl : undefined;
}

function createInitialProfile(currentUser: CurrentUser): EditableProfile {
  return {
    displayName: currentUser.displayName,
    nickname: currentUser.nickname ?? "",
    avatarPreviewUrl: getControlledAvatarUrl(currentUser.avatarUrl),
  };
}

function copyProfile(currentProfile: EditableProfile): EditableProfile {
  return { ...currentProfile };
}

function maskPhoneNumber(phoneNumber: string): string {
  if (phoneNumber.startsWith("+86") && phoneNumber.length === 14) {
    return `+86 ${phoneNumber.slice(3, 6)} **** ${phoneNumber.slice(-4)}`;
  }

  return `${phoneNumber.slice(0, Math.max(3, phoneNumber.length - 8))} **** ${phoneNumber.slice(-4)}`;
}

export function AccountOverview({ currentUser }: AccountOverviewProps) {
  const initialProfile = createInitialProfile(currentUser);
  const [profile, setProfile] = useState<EditableProfile>(initialProfile);
  const [profileDraft, setProfileDraft] = useState<EditableProfile>(copyProfile(initialProfile));
  const [profileErrors, setProfileErrors] = useState<ProfileErrors>({});
  const [contactDetails, setContactDetails] = useState<ContactDetails>({
    email: currentUser.email,
    phoneMasked: currentUser.phoneMasked,
  });
  const [verificationKind, setVerificationKind] = useState<ContactKind>();
  const [isEditorVisible, setIsEditorVisible] = useState(false);
  const [isAvatarProcessing, setIsAvatarProcessing] = useState(false);
  const [isSubmittingProfile, setIsSubmittingProfile] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const avatarRequestIdRef = useRef(0);
  const selectedFileRef = useRef<File | null>(null);
  const preferredName = profile.nickname?.trim() || profile.displayName;

  function openProfileEditor() {
    setProfileDraft(copyProfile(profile));
    setProfileErrors({});
    setIsEditorVisible(true);
  }

  function closeProfileEditor() {
    avatarRequestIdRef.current += 1;
    setIsAvatarProcessing(false);
    setIsEditorVisible(false);
    setProfileErrors({});
    selectedFileRef.current = null;
  }

  async function handleAvatarSelection(event: ChangeEvent<HTMLInputElement>) {
    const selectedFile = event.target.files?.[0];
    event.target.value = "";
    if (!selectedFile) return;

    const requestId = avatarRequestIdRef.current + 1;
    avatarRequestIdRef.current = requestId;
    setIsAvatarProcessing(true);
    selectedFileRef.current = selectedFile;
    setProfileErrors((currentErrors) => ({ ...currentErrors, avatarFile: undefined }));

    try {
      const sanitizedAvatar = await sanitizeAvatarFile(selectedFile);
      if (avatarRequestIdRef.current !== requestId) return;
      setProfileDraft((currentDraft) => ({
        ...currentDraft,
        avatarFileName: sanitizedAvatar.fileName,
        avatarPreviewUrl: sanitizedAvatar.previewDataUrl,
      }));
    } catch (error) {
      if (avatarRequestIdRef.current !== requestId) return;
      setProfileErrors((currentErrors) => ({
        ...currentErrors,
        avatarFile: error instanceof AvatarValidationError ? error.message : "头像处理失败，请选择其他图片。",
      }));
    } finally {
      if (avatarRequestIdRef.current === requestId) setIsAvatarProcessing(false);
    }
  }

  async function handleProfileSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedDisplayName = profileDraft.displayName.trim();
    const normalizedNickname = profileDraft.nickname?.trim();
    const nextErrors: ProfileErrors = {};

    if (!normalizedDisplayName) {
      nextErrors.displayName = "显示名称不能为空。";
    }
    if (isAvatarProcessing) nextErrors.avatarFile = "头像仍在处理中，请稍候。";
    if (Object.keys(nextErrors).length > 0) {
      setProfileErrors(nextErrors);
      return;
    }

    setIsSubmittingProfile(true);
    try {
      await browserCommands.updateProfile({
        displayName: normalizedDisplayName,
        nickname: normalizedNickname,
      });
      let avatarUrl = profileDraft.avatarPreviewUrl;
      if (selectedFileRef.current && profileDraft.avatarPreviewUrl?.startsWith("data:")) {
        try {
          const uploadResult = await browserCommands.uploadAvatar(selectedFileRef.current);
          avatarUrl = uploadResult.avatarUrl;
        } catch {
          Toast.warning({ content: "头像上传失败，资料已更新但头像未变更。" });
        }
      }
      setProfile({
        displayName: normalizedDisplayName,
        nickname: normalizedNickname,
        avatarFileName: profileDraft.avatarFileName,
        avatarPreviewUrl: avatarUrl,
      });
      selectedFileRef.current = null;
      setProfileErrors({});
      setIsEditorVisible(false);
      Toast.success({ content: "资料已更新。" });
    } catch {
      Toast.error({ content: "资料更新失败，请稍后重试。" });
    } finally {
      setIsSubmittingProfile(false);
    }
  }

  function handleContactVerified(nextValue: string) {
    if (verificationKind === "email") {
      setContactDetails((currentDetails) => ({ ...currentDetails, email: nextValue }));
      Toast.success({ content: "邮箱已更新。" });
    } else if (verificationKind === "phone") {
      setContactDetails((currentDetails) => ({ ...currentDetails, phoneMasked: maskPhoneNumber(nextValue) }));
      Toast.success({ content: "手机号已更新。" });
    }

    setVerificationKind(undefined);
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
            className={`${styles.avatar} ${profile.avatarPreviewUrl ? styles.avatarWithImage : ""}`}
            style={profile.avatarPreviewUrl ? { backgroundImage: `url(${profile.avatarPreviewUrl})` } : undefined}
            role="img"
            aria-label={`${profile.displayName}的头像`}
          >
            {!profile.avatarPreviewUrl && profile.displayName.slice(0, 1)}
          </div>
          <div className={styles.heroCopy}>
            <span className={styles.label}>统一账户</span>
            <h2>{profile.displayName}</h2>
            <p>{profile.nickname ? `${profile.nickname} · ${contactDetails.email}` : contactDetails.email}</p>
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
            <div><dt>头像文件</dt><dd>{profile.avatarFileName || (profile.avatarPreviewUrl ? "已设置" : "未上传")}</dd></div>
            <div>
              <dt>邮箱地址</dt>
              <dd className={styles.contactValue}>
                <span>{contactDetails.email}</span>
                <Button size="small" type="primary" theme="borderless" onClick={() => setVerificationKind("email")}>修改邮箱</Button>
              </dd>
            </div>
            <div>
              <dt>手机号码</dt>
              <dd className={styles.contactValue}>
                <span>{contactDetails.phoneMasked}</span>
                <Button size="small" type="primary" theme="borderless" onClick={() => setVerificationKind("phone")}>修改手机号</Button>
              </dd>
            </div>
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
              className={`${styles.avatar} ${profileDraft.avatarPreviewUrl ? styles.avatarWithImage : ""}`}
              style={profileDraft.avatarPreviewUrl ? { backgroundImage: `url(${profileDraft.avatarPreviewUrl})` } : undefined}
              aria-hidden="true"
            >
              {!profileDraft.avatarPreviewUrl && (profileDraft.displayName.trim().slice(0, 1) || "?")}
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

          <div className={styles.profileField}>
            <span>头像图片（可选）</span>
            <input
              ref={avatarInputRef}
              className={styles.visuallyHidden}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              aria-hidden="true"
              tabIndex={-1}
              onChange={handleAvatarSelection}
            />
            <div className={styles.avatarUploadActions}>
              <Button
                htmlType="button"
                icon={<IconUpload />}
                loading={isAvatarProcessing}
                onClick={() => avatarInputRef.current?.click()}
              >
                {profileDraft.avatarPreviewUrl ? "更换头像" : "选择头像"}
              </Button>
              {profileDraft.avatarPreviewUrl && (
                <Button
                  htmlType="button"
                  type="danger"
                  theme="borderless"
                  icon={<IconDelete />}
                  onClick={() => {
                    avatarRequestIdRef.current += 1;
                    setIsAvatarProcessing(false);
                    setProfileDraft((currentDraft) => ({
                      ...currentDraft,
                      avatarFileName: undefined,
                      avatarPreviewUrl: undefined,
                    }));
                    setProfileErrors((currentErrors) => ({ ...currentErrors, avatarFile: undefined }));
                  }}
                >
                  移除
                </Button>
              )}
            </div>
            <small className={profileErrors.avatarFile ? styles.profileError : undefined} role={profileErrors.avatarFile ? "alert" : undefined}>
              {profileErrors.avatarFile ?? (profileDraft.avatarFileName
                ? `已安全处理：${profileDraft.avatarFileName}`
                : "仅限 PNG、JPEG、WebP；最大 2 MiB。文件通过校验后会重新编码，不会加载外部链接或上传原文件。")}
            </small>
          </div>

          <p className={styles.profileNotice}>邮箱和手机号码属于安全联系方式，请返回基本资料卡片通过独立验证流程修改。</p>

          <div className={styles.profileActions}>
            <Button theme="outline" onClick={closeProfileEditor} disabled={isSubmittingProfile}>取消</Button>
            <Button htmlType="submit" type="primary" theme="solid" disabled={isAvatarProcessing || isSubmittingProfile} loading={isSubmittingProfile}>保存修改</Button>
          </div>
        </form>
      </Modal>

      {verificationKind && (
        <ContactVerificationModal
          key={verificationKind}
          kind={verificationKind}
          currentValue={verificationKind === "email" ? contactDetails.email : contactDetails.phoneMasked}
          onCancel={() => setVerificationKind(undefined)}
          onVerified={handleContactVerified}
        />
      )}
    </>
  );
}
