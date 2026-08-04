"use client";

import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import { Empty, Input, Table } from "@douyinfe/semi-ui";
import type { ColumnProps, Data } from "@douyinfe/semi-ui/lib/es/table";
import { IconSearch } from "@douyinfe/semi-icons";
import { MockActionButton } from "@/components/common/mock-action-button";
import { PageHeader } from "@/components/common/page-header";
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
  getSearchText: (record: RecordType) => string;
  records: RecordType[];
  rowKey: string;
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
}: ManagementDirectoryProps<RecordType>) {
  const [searchQuery, setSearchQuery] = useState("");
  const normalizedQuery = searchQuery.trim().toLocaleLowerCase("zh-CN");
  const filteredRecords = normalizedQuery
    ? records.filter((record) => getSearchText(record).toLocaleLowerCase("zh-CN").includes(normalizedQuery))
    : records;
  const pagination = useMemo(
    () => ({ pageSize: 20, hideOnSinglePage: true, showTotal: true }),
    [],
  );

  return (
    <>
      <PageHeader
        eyebrow={copy.eyebrow}
        title={copy.title}
        description={copy.description}
        action={<MockActionButton primary message={copy.actionLabel}>{copy.actionLabel}</MockActionButton>}
      />

      <section className={styles.directoryCard} aria-label={`${copy.title}目录`}>
        <div className={styles.toolbar}>
          <Input
            value={searchQuery}
            onChange={setSearchQuery}
            prefix={<IconSearch />}
            placeholder={copy.searchPlaceholder}
            showClear
            aria-label={copy.searchPlaceholder}
          />
          <span aria-live="polite">共 {filteredRecords.length} 条 mock 记录</span>
        </div>
        <div className={styles.tableScroll}>
          <Table<RecordType>
            className={styles.directoryTable}
            columns={columns}
            dataSource={filteredRecords}
            empty={<Empty title="没有匹配记录" description="请调整搜索关键词后重试。" />}
            pagination={pagination}
            rowKey={rowKey}
            scroll={{ x: 920 }}
            size="middle"
            title={`${copy.title}列表`}
          />
        </div>
      </section>
    </>
  );
}
