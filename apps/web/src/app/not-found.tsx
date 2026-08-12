import Link from "next/link";

/**
 * A dead end should still tell you where you are and how to leave. The routes are
 * listed because this app's URLs are not guessable — a receipt path carries a
 * request id, and landing here usually means an id that has been reset away.
 */
export default function NotFound() {
  const routes = [
    { href: "/", label: "Network", detail: "live compute provenance graph" },
    { href: "/playground", label: "Playground", detail: "send a private request" },
    { href: "/contribute", label: "Contribute", detail: "add capacity under constraints" },
    { href: "/dashboard", label: "Contributors", detail: "per-contributor accounting" },
    { href: "/policy", label: "Policy Lab", detail: "test a prompt without revealing it" },
    { href: "/trust", label: "Trust Model", detail: "what is and is not established" },
  ];

  return (
    <main className="mx-auto flex min-h-dvh max-w-[720px] flex-col justify-center px-6 py-16">
      <p className="mono text-[12px] tracking-[0.14em] text-private">404</p>
      <h1 className="mt-3 text-[30px] font-semibold leading-tight tracking-[-0.03em]">
        There is nothing at this address.
      </h1>
      <p className="mt-3 text-[14px] leading-relaxed text-ink-3">
        If you followed a receipt link, the request it names may have been reset — local state is
        wiped by <span className="mono text-ink-2">pnpm reset</span>, and request ids do not survive
        it. Everything else is one of these.
      </p>

      <nav className="mt-7 grid gap-1.5">
        {routes.map((route) => (
          <Link
            key={route.href}
            href={route.href}
            className="group flex items-baseline justify-between gap-4 rounded-[10px] border border-hairline px-3.5 py-3 outline-none transition duration-200 hover:border-private/40 hover:bg-surface-2 focus-visible:ring-2 focus-visible:ring-private/50"
          >
            <span className="text-[13.5px] font-medium text-ink-2 group-hover:text-ink">
              {route.label}
            </span>
            <span className="text-[11.5px] text-ink-4">{route.detail}</span>
          </Link>
        ))}
      </nav>
    </main>
  );
}
