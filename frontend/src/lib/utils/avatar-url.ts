const CONTROLLED_AVATAR_PREFIX = "/api/v1/media/avatars/";

export function getControlledAvatarUrl(avatarUrl: string | undefined): string | undefined {
  return avatarUrl?.startsWith(CONTROLLED_AVATAR_PREFIX) ? avatarUrl : undefined;
}
