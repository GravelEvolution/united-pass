//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Centralized mock/real data source switch flag
//

/**
 * Data source switch for the per-seam mock → real HTTP migration
 * (frontend-freeze-v1.md §5, ADR-0004).
 *
 * `NEXT_PUBLIC_USE_MOCK=true` keeps every seam on the mock data source.
 * Any other value routes the already-migrated seams through the real HTTP
 * clients; seams without a backend implementation stay on the mock source.
 *
 * The flag must use the `NEXT_PUBLIC_` prefix because browser-side command
 * code reads it too: Next.js only inlines `NEXT_PUBLIC_*` variables into
 * Client Component bundles. Server code may read it as well, so a single
 * flag drives both layers. This is the ONLY sanctioned place to read the
 * environment for data source selection (AGENTS.md §18).
 */
export const USE_MOCK_DATA_SOURCE = process.env.NEXT_PUBLIC_USE_MOCK === "true";
