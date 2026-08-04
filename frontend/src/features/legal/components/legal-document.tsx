import Link from "next/link";
import { BrandMark } from "@/components/common/brand-mark";
import { ThemeToggle } from "@/components/common/theme-toggle";
import { COMPANY_LEGAL_NAME, SYSTEM_NAME } from "@/lib/branding";
import styles from "./legal-document.module.css";

export type LegalSection = {
  id: string;
  title: string;
  paragraphs?: string[];
  items?: string[];
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
