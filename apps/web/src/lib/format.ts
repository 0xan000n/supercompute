export function shortHash(value: string | null | undefined, head = 6, tail = 4): string {
  if (!value) return "—";
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  if (clean.length <= head + tail) return value;
  return `${value.startsWith("0x") ? "0x" : ""}${clean.slice(0, head)}…${clean.slice(-tail)}`;
}

export function ms(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(value < 10_000 ? 2 : 1)} s`;
}

export function usd(microUsd: number | null | undefined): string {
  if (microUsd === null || microUsd === undefined) return "—";
  const dollars = microUsd / 1_000_000;
  if (dollars === 0) return "$0.00";
  if (dollars < 0.01) return `$${dollars.toFixed(6).replace(/0+$/, "").replace(/\.$/, ".0")}`;
  return `$${dollars.toFixed(2)}`;
}

export function usdFromDollars(dollars: number | null | undefined): string {
  if (dollars === null || dollars === undefined) return "—";
  if (dollars === 0) return "$0.00";
  if (dollars < 0.01) return `$${dollars.toFixed(6).replace(/0+$/, "")}`;
  return `$${dollars.toFixed(2)}`;
}

export function num(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString();
}

export function relTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const delta = Date.now() - Date.parse(iso);
  if (Number.isNaN(delta)) return "—";
  const s = Math.max(0, Math.round(delta / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
