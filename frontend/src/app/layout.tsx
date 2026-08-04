import type { Metadata } from "next";
import { Noto_Sans_SC } from "next/font/google";
import "@douyinfe/semi-ui/lib/es/_base/base.css";
import "./globals.css";

const notoSansSc = Noto_Sans_SC({
  variable: "--font-sans",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "United Pass",
    template: "%s | United Pass",
  },
  description: "统一、安全、清晰的身份与访问管理平台",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="zh-CN" className={notoSansSc.variable}>
      <body>{children}</body>
    </html>
  );
}
