//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Pagination contract types
//

/**
 * Cursor-based pagination types shared across all list queries.
 *
 * See docs/api-contracts.md for the full contract.
 * See docs/adr-0006.md for the deployment topology.
 */

/** Query parameters for paginated list endpoints. */
export type PageQuery = {
  /** Opaque cursor returned by the previous page; omit for the first page. */
  cursor?: string;
  /** Page size; the backend may cap or adjust this value. */
  limit?: number;
  /** Free-text search term. */
  query?: string;
  /** Sort specifier, e.g. `-updatedAt` for descending. */
  sort?: string;
  /** Status filter, e.g. `active`, `disabled`. */
  status?: string;
};

/** Cursor-paginated response envelope. */
export type CursorPage<T> = {
  items: T[];
  page: {
    /** Cursor to fetch the next page; `null` when there are no more items. */
    nextCursor: string | null;
    /** Whether more items exist beyond the current page. */
    hasMore: boolean;
  };
};
