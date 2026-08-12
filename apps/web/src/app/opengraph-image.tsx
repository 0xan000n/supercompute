import { ImageResponse } from "next/og";

/**
 * The card people see when the link is pasted anywhere. Generated rather than
 * hand-designed so it cannot drift from the product's own vocabulary, and it
 * carries the honest label — a shared link should not imply more than the build
 * delivers.
 */
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt =
  "Supercompute — a compute trust network where contributors constrain how their AI capacity is used";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#05060a",
          backgroundImage:
            "radial-gradient(ellipse 100% 60% at 50% -10%, rgba(34,211,238,0.16), transparent 65%)",
          padding: 72,
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              border: "2px solid rgba(34,211,238,0.55)",
              background: "rgba(34,211,238,0.1)",
            }}
          />
          <div
            style={{
              fontSize: 26,
              color: "#a7adc0",
              letterSpacing: 6,
              textTransform: "uppercase",
            }}
          >
            Supercompute
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
          <div
            style={{
              fontSize: 68,
              lineHeight: 1.05,
              color: "#eef0f6",
              letterSpacing: -2.5,
              maxWidth: 960,
            }}
          >
            Contribute AI compute. Constrain how it is used. Never see the work.
          </div>
          <div style={{ fontSize: 27, color: "#6b7288", maxWidth: 900, lineHeight: 1.4 }}>
            Requests encrypted in the browser, executed under an exact policy version, and
            returned with a signed receipt anyone can verify.
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {[
            { label: "PROMPT PRIVATE", color: "#22d3ee" },
            { label: "POLICY VERIFIED", color: "#34d399" },
            { label: "SIMULATED TEE", color: "#fbbf24" },
          ].map((chip) => (
            <div
              key={chip.label}
              style={{
                display: "flex",
                fontSize: 20,
                color: chip.color,
                border: `1px solid ${chip.color}55`,
                background: `${chip.color}14`,
                borderRadius: 999,
                padding: "9px 20px",
                letterSpacing: 1.2,
              }}
            >
              {chip.label}
            </div>
          ))}
        </div>
      </div>
    ),
    size
  );
}
