//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Date and time formatting utilities
//

const fullDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  dateStyle: "medium",
  timeStyle: "medium",
  timeZone: "Asia/Shanghai",
});

export function formatSecurityDateTime(timestamp: string): string {
  return `${fullDateTimeFormatter.format(new Date(timestamp))}（北京时间）`;
}
