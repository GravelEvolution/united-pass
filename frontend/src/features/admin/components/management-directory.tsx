//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Management directory navigation UI
//

"use client";

import type { FormEvent, ReactNode } from "react";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Empty, Input, Table } from "@douyinfe/semi-ui";
import type { ColumnProps, Data } from "@douyinfe/semi-ui/lib/es/table";
import { IconSearch } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import type { CursorPage } from "@/types/pagination";
import styles from "./admin.module.css";

export type DirectoryCopy = {
  eyebrow: string;
  title: string;
  description: string;
  searchPlaceholder: string;
  actionLabel: string;
};

type ManagementDirectoryProps<RecordType extends Data> = {
  columns: ColumnProps<RecordType>[];
  copy: DirectoryCopy;
  getSearchText?: (record: RecordType) => string;
  records: RecordType[];
  rowKey: string;
  action?: ReactNode;
  basePath?: string;
  initialQuery?: string;
  page?: CursorPage<unknown>["page"];
  hasPrevious?: boolean;
};

type PrimaryCellProps = {
  primary: ReactNode;
  secondary?: ReactNode;
};

export function createScopedColumn<RecordType extends Data>(
  column: ColumnProps<RecordType>,
): ColumnProps<RecordType> {
  return {
    ...column,
    onHeaderCell: () => ({ scope: "col" }),
  };
}

export function PrimaryCell({ primary, secondary }: PrimaryCellProps) {
  return (
    <span className={styles.primaryCell}>
      <strong>{primary}</strong>
      {secondary && <span>{secondary}</span>}
    </span>
  );
}

export function SecondaryCell({ children }: { children: ReactNode }) {
  return <span className={styles.secondaryCell}>{children}</span>;
}

export function ManagementDirectory<RecordType extends Data>({
  columns,
  copy,
  getSearchText,
  records,
  rowKey,
  action,
  basePath,
  initialQuery = "",
  page,
  hasPrevious = false,
}: ManagementDirectoryProps<RecordType>) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState(initialQuery);
  const normalizedQuery = searchQuery.trim().toLocaleLowerCase("zh-CN");
  const displayedRecords = basePath || !getSearchText || !normalizedQuery
    ? records
    : records.filter((record) =>
        getSearchText(record).toLocaleLowerCase("zh-CN").includes(normalizedQuery),
      );

  function navigate(query: string, cursor?: string): void {
    if (!basePath) return;
    const parameters = new URLSearchParams(window.location.search);
    const normalized = query.trim();
    if (normalized) parameters.set("q", normalized);
    else parameters.delete("q");
    if (cursor) parameters.set("cursor", cursor);
    else parameters.delete("cursor");
    const encoded = parameters.toString();
    router.push(`${basePath}${encoded ? `?${encoded}` : ""}`);
  }

  function handleSearch(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (basePath) navigate(searchQuery);
  }

  return (
    <>
      <PageHeader
        eyebrow={copy.eyebrow}
        title={copy.title}
        description={copy.description}
        action={action}
      />

      <section className={styles.directoryCard} aria-label={`${copy.title}目录`}>
        <div className={styles.toolbar}>
          <form onSubmit={handleSearch} style={{ display: "flex", gap: 8, flex: 1 }}>
            <Input
              value={searchQuery}
              onChange={setSearchQuery}
              prefix={<IconSearch />}
              placeholder={copy.searchPlaceholder}
              showClear
              aria-label={copy.searchPlaceholder}
            />
            <Button htmlType="submit" theme="solid" type="primary">搜索</Button>
          </form>
          <span aria-live="polite">
            {basePath ? "本页" : "共"} {displayedRecords.length} 条记录
          </span>
        </div>
        <div className={styles.tableScroll}>
          <Table<RecordType>
            className={styles.directoryTable}
            columns={columns}
            dataSource={displayedRecords}
            empty={<Empty title="没有匹配记录" description="请调整搜索关键词后重试。" />}
            pagination={false}
            rowKey={rowKey}
            scroll={{ x: 920 }}
            size="middle"
          />
        </div>
        {page && (page.hasMore || hasPrevious) && (
          <div className={styles.toolbar} style={{ justifyContent: "flex-end" }}>
            <Button
              theme="outline"
              onClick={() => router.back()}
              disabled={!hasPrevious}
            >
              上一页
            </Button>
            <Button
              theme="solid"
              type="primary"
              onClick={() => page.nextCursor && navigate(initialQuery, page.nextCursor)}
              disabled={!page.hasMore || !page.nextCursor}
            >
              下一页
            </Button>
          </div>
        )}
      </section>
    </>
  );
}
