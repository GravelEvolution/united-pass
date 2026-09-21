export function formatRetryAfter(seconds: number): string | undefined {
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;

  const totalSeconds = Math.ceil(seconds);
  if (totalSeconds < 60) return `${totalSeconds} 秒`;

  const totalMinutes = Math.ceil(totalSeconds / 60);
  if (totalMinutes < 60) return `${totalMinutes} 分钟`;

  const totalHours = Math.floor(totalMinutes / 60);
  const remainingMinutes = totalMinutes % 60;
  if (totalHours < 24) {
    return remainingMinutes === 0
      ? `${totalHours} 小时`
      : `${totalHours} 小时 ${remainingMinutes} 分钟`;
  }

  // Do not understate long server-enforced waits: round any remaining minutes
  // up to the next hour once the duration reaches a day.
  const roundedHours = Math.ceil(totalMinutes / 60);
  const days = Math.floor(roundedHours / 24);
  const remainingHours = roundedHours % 24;
  return remainingHours === 0
    ? `${days} 天`
    : `${days} 天 ${remainingHours} 小时`;
}
