const fullDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  dateStyle: "medium",
  timeStyle: "medium",
  timeZone: "Asia/Shanghai",
});

export function formatSecurityDateTime(timestamp: string): string {
  return `${fullDateTimeFormatter.format(new Date(timestamp))}（北京时间）`;
}
