import styles from "./user-avatar.module.css";

type UserAvatarProps = {
  displayName: string;
  imageUrl?: string;
  className?: string;
  ariaHidden?: boolean;
};

export function UserAvatar({
  displayName,
  imageUrl,
  className,
  ariaHidden = false,
}: UserAvatarProps) {
  const classes = [styles.avatar, imageUrl ? styles.avatarWithImage : "", className]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      className={classes}
      style={imageUrl ? { backgroundImage: `url(${imageUrl})` } : undefined}
      role={ariaHidden ? undefined : "img"}
      aria-label={ariaHidden ? undefined : `${displayName}的头像`}
      aria-hidden={ariaHidden || undefined}
    >
      {!imageUrl && (displayName.trim().slice(0, 1) || "?")}
    </div>
  );
}
