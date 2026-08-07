//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Legal document renderer component
//

import Link from "next/link";
import { BrandMark } from "@/components/common/brand-mark";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { COMPANY_LEGAL_NAME, SYSTEM_NAME } from "@/lib/branding";
import styles from "./legal-document.module.css";

export type LegalTable = {
  headers: string[];
  rows: string[][];
};

export type LegalNote = {
  tone: "info" | "warning";
  text: string;
};

export type LegalSubsection = {
  id?: string;
  title?: string;
  paragraphs?: string[];
  items?: string[];
  tables?: LegalTable[];
  notes?: LegalNote[];
  subsections?: LegalSubsection[];
};

export type LegalSection = LegalSubsection & {
  id: string;
  title: string;
};

type LegalDocumentProps = {
  eyebrow: string;
  title: string;
  summary: string;
  version: string;
  effectiveDate: string;
  sections: LegalSection[];
  relatedHref: "/privacy" | "/terms";
  relatedLabel: string;
};

function LegalTable({ table }: { table: LegalTable }) {
  return (
    <div className={styles.tableWrapper}>
      <table className={styles.table}>
        <thead>
          <tr>
            {table.headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LegalNoteBox({ note }: { note: LegalNote }) {
  return (
    <div className={`${styles.note} ${note.tone === "warning" ? styles.noteWarning : styles.noteInfo}`}>
      {note.text}
    </div>
  );
}

function LegalSubsectionView({ subsection }: { subsection: LegalSubsection }) {
  return (
    <div className={styles.subsection}>
      {subsection.title && <h3>{subsection.title}</h3>}
      {subsection.paragraphs?.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
      {subsection.items && (
        <ul>
          {subsection.items.map((item) => <li key={item}>{item}</li>)}
        </ul>
      )}
      {subsection.tables?.map((table, index) => <LegalTable key={index} table={table} />)}
      {subsection.notes?.map((note, index) => <LegalNoteBox key={index} note={note} />)}
      {subsection.subsections?.map((sub, index) => (
        <LegalSubsectionView key={index} subsection={sub} />
      ))}
    </div>
  );
}

export function LegalDocument({
  eyebrow,
  title,
  summary,
  version,
  effectiveDate,
  sections,
  relatedHref,
  relatedLabel,
}: LegalDocumentProps) {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <Link href="/login" aria-label={`返回${SYSTEM_NAME}登录页`}>
          <BrandMark />
        </Link>
        <ThemeToggle />
      </header>

      <main className={styles.main}>
        <section className={styles.hero}>
          <p className={styles.eyebrow}>{eyebrow}</p>
          <h1>{title}</h1>
          <p className={styles.summary}>{summary}</p>
          <dl className={styles.metadata}>
            <div><dt>版本</dt><dd>{version}</dd></div>
            <div><dt>生效日期</dt><dd>{effectiveDate}</dd></div>
            <div><dt>适用系统</dt><dd>{SYSTEM_NAME}</dd></div>
          </dl>
        </section>

        <article className={styles.document}>
          <nav className={styles.contents} aria-label={`${title}目录`}>
            <strong>内容目录</strong>
            <ol>
              {sections.map((section) => (
                <li key={section.id}><a href={`#${section.id}`}>{section.title}</a></li>
              ))}
            </ol>
          </nav>

          <div className={styles.sections}>
            {sections.map((section, index) => (
              <section key={section.id} id={section.id} aria-labelledby={`${section.id}-title`}>
                <span className={styles.sectionNumber}>{String(index + 1).padStart(2, "0")}</span>
                <h2 id={`${section.id}-title`}>{section.title}</h2>
                {section.paragraphs?.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
                {section.items && (
                  <ul>
                    {section.items.map((item) => <li key={item}>{item}</li>)}
                  </ul>
                )}
                {section.tables?.map((table, tableIndex) => <LegalTable key={tableIndex} table={table} />)}
                {section.notes?.map((note, noteIndex) => <LegalNoteBox key={noteIndex} note={note} />)}
                {section.subsections?.map((subsection, subIndex) => (
                  <LegalSubsectionView key={subIndex} subsection={subsection} />
                ))}
              </section>
            ))}
          </div>
        </article>

        <nav className={styles.actions} aria-label="法律文件导航">
          <Link href="/login">返回登录</Link>
          <Link href={relatedHref}>{relatedLabel}</Link>
        </nav>
      </main>

      <footer className={styles.footer}>© 2026 {COMPANY_LEGAL_NAME}</footer>
    </div>
  );
}
