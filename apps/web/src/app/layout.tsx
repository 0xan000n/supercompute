import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "Supercompute",
  description:
    "A compute trust network where resource owners contribute AI capacity while cryptographically constraining how it is used.",
  openGraph: {
    title: "Supercompute",
    description:
      "Contribute AI compute and cryptographically constrain how it is used — without seeing the workloads that use it.",
    type: "website",
  },
  twitter: { card: "summary_large_image" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    /**
     * `suppressHydrationWarning` on <html> and <body> only.
     *
     * Browser extensions routinely stamp attributes onto these two elements
     * before React hydrates — a translation extension adding
     * `data-gt-extension-loaded`, a theme extension setting `class`, and so on.
     * React reads the already-modified DOM as "the server HTML", reports a
     * mismatch it cannot fix, and the dev overlay shows an error for something no
     * application change can prevent.
     *
     * The suppression is scoped to each element's OWN attributes and does not
     * extend into the tree, so genuine mismatches in the app still surface. It is
     * applied here precisely because these are the two nodes the app does not
     * exclusively own.
     */
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body className="antialiased" suppressHydrationWarning>
        {/* Keyboard users must be able to reach the content past the nav. */}
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:border focus:border-private/40 focus:bg-surface-2 focus:px-3 focus:py-2 focus:text-[13px] focus:text-private"
        >
          Skip to content
        </a>
        {children}
        {/*
          Fixed grain overlay. Flat dark surfaces read as sterile; a little noise
          gives the panels something to sit on. Pointer-events-none so it never
          intercepts a click on the canvas beneath it.
        */}
        <div aria-hidden className="grain" />
      </body>
    </html>
  );
}
