import type { DreamUPEventSummary } from "./types";

export function hasDreamUPAdministrationAccess(events: readonly DreamUPEventSummary[]): boolean {
  return events.length > 0;
}
