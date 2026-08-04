import type { UserPersona } from "@/types/identity";

export function formatPersonaLabel(personas: ReadonlyArray<UserPersona>): string {
  const hasConsumer = personas.includes("consumer");
  const hasEmployee = personas.includes("employee");

  if (hasConsumer && hasEmployee) return "外部用户 · 员工";
  if (hasEmployee) return "员工";
  return "外部用户";
}
