"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GraphLink, GraphNode } from "@ctn/protocol";
import { NODE_STYLE, statusColor } from "@/lib/theme";
import { LANES, laneCentre, laneWidth, layout, settle, type PositionedNode } from "./layout";

/**
 * Custom canvas renderer.
 *
 * Written rather than pulled in because the demo needs three things a
 * general-purpose graph library does not give at once: the spec's fixed lane
 * layout (§48), particles that travel along the exact path a request took, and
 * a visually dominant selected path. It is ~1 file, has no dependencies, and
 * renders 500+ nodes at 60fps on integrated graphics.
 */

export interface NetworkGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  recent: Set<string>;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  /** Node ids on the highlighted request path; everything else dims. */
  focusPath?: Set<string>;
  className?: string;
  compact?: boolean;
}

interface Particle {
  linkId: string;
  t: number;
  speed: number;
  color: string;
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

/** Trims a label to fit `maxWidth` world units under the context's current font. */
function ellipsize(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (ctx.measureText(text).width <= maxWidth) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(`${text.slice(0, mid)}…`).width <= maxWidth) lo = mid;
    else hi = mid - 1;
  }
  return lo <= 1 ? "…" : `${text.slice(0, lo)}…`;
}

export function NetworkGraph({
  nodes,
  links,
  recent,
  selectedId,
  onSelect,
  focusPath,
  className = "",
  compact = false,
}: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);

  // Mutable render state lives in refs: the animation loop must not re-subscribe
  // on every React render.
  const positioned = useRef<Map<string, PositionedNode> | null>(null);
  const layoutInfo = useRef<{ width: number; height: number }>({ width: 1, height: 1 });
  const particles = useRef<Particle[]>([]);
  const view = useRef({ scale: 1, tx: 0, ty: 0, targetScale: 1, initialized: false });
  const pointer = useRef<{ x: number; y: number; down: boolean; dragged: boolean; lastX: number; lastY: number }>({
    x: -1e9,
    y: -1e9,
    down: false,
    dragged: false,
    lastX: 0,
    lastY: 0,
  });
  const dataRef = useRef({ nodes, links, recent, selectedId, focusPath, hoverId });

  dataRef.current = { nodes, links, recent, selectedId, focusPath, hoverId };

  /**
   * The renderer stops touching the canvas once the graph has settled.
   *
   * Beyond not burning a core to redraw an identical frame, this matters because
   * a canvas that commits a new frame every tick never presents a stable surface —
   * screenshot tooling and some compositors wait indefinitely for one. `nudge` is
   * bumped by anything that needs a redraw without changing node positions
   * (hover, selection, pan, zoom, resize).
   */
  const nudge = useRef(0);
  const bump = useCallback(() => {
    nudge.current += 1;
  }, []);

  /**
   * The hook hands back fresh array identities on every render, so the layout is
   * keyed on actual topology instead. Without this, moving the mouse recomputed
   * the whole layout on every frame.
   */
  const topology = useMemo(
    () => `${nodes.map((n) => n.id).join(",")}|${links.map((l) => l.id).join(",")}`,
    [nodes, links]
  );

  useEffect(() => {
    const result = layout(dataRef.current.nodes, dataRef.current.links, positioned.current);
    positioned.current = result.nodes;
    layoutInfo.current = { width: result.width, height: result.height };
    bump();
  }, [topology, bump]);

  // Newly created links emit a travelling particle, so the eye follows the
  // request through the network in the order things actually happened.
  const seenLinks = useRef<Set<string>>(new Set());
  useEffect(() => {
    for (const link of dataRef.current.links) {
      if (seenLinks.current.has(link.id)) continue;
      seenLinks.current.add(link.id);
      // Skip the initial snapshot burst; only animate genuinely live arrivals.
      if (Date.now() - Date.parse(link.createdAt) > 8000) continue;
      const target = positioned.current?.get(link.target);
      const color = target ? statusColor(target.type, target.status) : "#22d3ee";
      for (let i = 0; i < 3; i++) {
        particles.current.push({
          linkId: link.id,
          t: -i * 0.18,
          speed: 0.6 + Math.random() * 0.25,
          color,
        });
      }
    }
  }, [topology]);

  // Selection, hover and focus change the picture without moving any node.
  useEffect(bump, [bump, selectedId, hoverId, focusPath]);

  const fit = useCallback(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const { width: lw, height: lh } = layoutInfo.current;
    const pad = compact ? 34 : 54;
    const scale = clamp(
      Math.min((wrap.clientWidth - pad * 2) / lw, (wrap.clientHeight - pad * 2) / Math.max(lh, 200)),
      0.28,
      compact ? 1.15 : 1.5
    );
    view.current.targetScale = scale;
    view.current.scale = scale;
    view.current.tx = (wrap.clientWidth - lw * scale) / 2;
    view.current.ty = (wrap.clientHeight - lh * scale) / 2;
    view.current.initialized = true;
    bump();
  }, [compact, bump]);

  // Fit once the first real layout exists, and on resize.
  useEffect(() => {
    if (!view.current.initialized && nodes.length > 0) fit();
    const observer = new ResizeObserver(() => fit());
    if (wrapRef.current) observer.observe(wrapRef.current);
    return () => observer.disconnect();
  }, [fit, nodes.length]);

  /**
   * When a path is focused, bring it into view. Without this the newest request
   * can be highlighted somewhere off-screen, which is exactly the moment the
   * viewer most wants to see it.
   */
  const focusKey = focusPath ? [...focusPath].sort().join(",") : "";
  useEffect(() => {
    const map = positioned.current;
    const wrap = wrapRef.current;
    if (!map || !wrap || !focusPath || focusPath.size === 0) return;

    let sum = 0;
    let count = 0;
    for (const id of focusPath) {
      const node = map.get(id);
      if (!node) continue;
      sum += node.ty;
      count += 1;
    }
    if (count === 0) return;
    const v = view.current;
    v.ty = wrap.clientHeight / 2 - (sum / count) * v.scale;
    bump();
  }, [focusKey, focusPath, bump]);

  const toWorld = useCallback((cx: number, cy: number) => {
    const v = view.current;
    return { x: (cx - v.tx) / v.scale, y: (cy - v.ty) / v.scale };
  }, []);

  const hitTest = useCallback(
    (cx: number, cy: number): PositionedNode | null => {
      const map = positioned.current;
      if (!map) return null;
      const { x, y } = toWorld(cx, cy);
      let best: PositionedNode | null = null;
      let bestDist = Infinity;
      for (const node of map.values()) {
        const r = NODE_STYLE[node.type].radius + 9;
        const d = (node.x - x) ** 2 + (node.y - y) ** 2;
        if (d < r * r && d < bestDist) {
          best = node;
          bestDist = d;
        }
      }
      return best;
    },
    [toWorld]
  );

  // ---- the render loop ----
  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    let raf = 0;
    let last = performance.now();
    let dpr = 1;
    let lastNudge = -1;

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(wrap.clientWidth * dpr);
      canvas.height = Math.floor(wrap.clientHeight * dpr);
      canvas.style.width = `${wrap.clientWidth}px`;
      canvas.style.height = `${wrap.clientHeight}px`;
      bump();
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(wrap);

    const PULSING = new Set(["PROVING", "PROVIDER_RUNNING", "ROUTING", "RECEIVED"]);

    /** True while any visible thing is still changing. */
    const isAnimating = (map: Map<string, PositionedNode>): boolean => {
      if (particles.current.length > 0) return true;
      if (dataRef.current.recent.size > 0) return true;
      if (Math.abs(view.current.targetScale - view.current.scale) > 0.001) return true;
      for (const node of map.values()) {
        if (node.appear < 1) return true;
        if (Math.abs(node.tx - node.x) > 0.05 || Math.abs(node.ty - node.y) > 0.05) return true;
        if (node.status && PULSING.has(node.status)) return true;
      }
      return false;
    };

    const drawShape = (
      shape: string,
      x: number,
      y: number,
      r: number
    ) => {
      ctx.beginPath();
      if (shape === "square") {
        const s = r * 0.92;
        // rounded square
        const rad = s * 0.3;
        ctx.moveTo(x - s + rad, y - s);
        ctx.arcTo(x + s, y - s, x + s, y + s, rad);
        ctx.arcTo(x + s, y + s, x - s, y + s, rad);
        ctx.arcTo(x - s, y + s, x - s, y - s, rad);
        ctx.arcTo(x - s, y - s, x + s, y - s, rad);
        ctx.closePath();
      } else if (shape === "diamond") {
        const s = r * 1.18;
        ctx.moveTo(x, y - s);
        ctx.lineTo(x + s, y);
        ctx.lineTo(x, y + s);
        ctx.lineTo(x - s, y);
        ctx.closePath();
      } else if (shape === "hex") {
        const s = r * 1.08;
        for (let i = 0; i < 6; i++) {
          const a = (Math.PI / 3) * i - Math.PI / 6;
          const px = x + Math.cos(a) * s;
          const py = y + Math.sin(a) * s;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
      } else {
        ctx.arc(x, y, r, 0, Math.PI * 2);
      }
    };

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const map = positioned.current;
      const { selectedId: sel, focusPath, hoverId: hov, recent } = dataRef.current;

      if (!map || map.size === 0) {
        raf = requestAnimationFrame(frame);
        return;
      }

      // Skip the frame entirely when the picture cannot have changed.
      if (nudge.current === lastNudge && !isAnimating(map)) {
        raf = requestAnimationFrame(frame);
        return;
      }
      lastNudge = nudge.current;

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr);

      for (const node of map.values()) settle(node, dt);

      const v = view.current;
      v.scale += (v.targetScale - v.scale) * Math.min(1, dt * 10);
      ctx.translate(v.tx, v.ty);
      ctx.scale(v.scale, v.scale);

      const focused = focusPath && focusPath.size > 0;
      const isLit = (id: string) => !focused || focusPath!.has(id);

      // ---- lane guides ----
      if (!compact) {
        const { height } = layoutInfo.current;
        ctx.save();
        for (let lane = 0; lane < LANES.length; lane++) {
          const x = laneCentre(lane);
          ctx.strokeStyle = "rgba(255,255,255,0.03)";
          ctx.lineWidth = 1 / v.scale;
          ctx.beginPath();
          ctx.moveTo(x, -30);
          ctx.lineTo(x, height + 26);
          ctx.stroke();

          ctx.fillStyle = "rgba(255,255,255,0.22)";
          ctx.font = `600 ${10 / Math.max(v.scale, 0.6)}px ui-sans-serif, system-ui`;
          ctx.textAlign = "center";
          ctx.textBaseline = "alphabetic";
          ctx.fillText(LANES[lane].label.toUpperCase(), x, -42 / Math.max(v.scale, 0.6));
        }
        ctx.restore();
      }

      // ---- edges ----
      for (const link of dataRef.current.links) {
        const a = map.get(link.source);
        const b = map.get(link.target);
        if (!a || !b) continue;
        const lit = isLit(link.source) && isLit(link.target);
        const touchesSelection = sel === link.source || sel === link.target;

        const alpha = lit ? (touchesSelection ? 0.55 : 0.2) : 0.045;
        ctx.strokeStyle = touchesSelection
          ? `rgba(34,211,238,${alpha})`
          : `rgba(160,175,205,${alpha})`;
        ctx.lineWidth = (touchesSelection ? 1.7 : 1.05) / v.scale + (lit ? 0.35 : 0);

        // Curved edges: a slight bow makes parallel edges legible.
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const bow = clamp(Math.hypot(dx, dy) * 0.12, 0, 34);
        const nx = -dy / (Math.hypot(dx, dy) || 1);
        const ny = dx / (Math.hypot(dx, dy) || 1);

        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.quadraticCurveTo(mx + nx * bow, my + ny * bow, b.x, b.y);
        ctx.stroke();
      }

      // ---- particles along live edges ----
      const linkById = new Map(dataRef.current.links.map((l) => [l.id, l]));
      particles.current = particles.current.filter((p) => p.t < 1.15);
      for (const p of particles.current) {
        p.t += dt * p.speed;
        if (p.t < 0) continue;
        const link = linkById.get(p.linkId);
        if (!link) continue;
        const a = map.get(link.source);
        const b = map.get(link.target);
        if (!a || !b) continue;

        const t = clamp(p.t, 0, 1);
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const bow = clamp(len * 0.12, 0, 34);
        const nx = -dy / len;
        const ny = dx / len;
        const cx = (a.x + b.x) / 2 + nx * bow;
        const cy = (a.y + b.y) / 2 + ny * bow;
        // quadratic bezier point
        const px = (1 - t) ** 2 * a.x + 2 * (1 - t) * t * cx + t ** 2 * b.x;
        const py = (1 - t) ** 2 * a.y + 2 * (1 - t) * t * cy + t ** 2 * b.y;

        const fade = t > 0.85 ? 1 - (t - 0.85) / 0.15 : 1;
        ctx.save();
        ctx.globalCompositeOperation = "lighter";
        const grad = ctx.createRadialGradient(px, py, 0, px, py, 9);
        grad.addColorStop(0, p.color);
        grad.addColorStop(1, "rgba(0,0,0,0)");
        ctx.globalAlpha = 0.85 * fade;
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(px, py, 9, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      }

      // ---- nodes ----
      for (const node of map.values()) {
        const style = NODE_STYLE[node.type];
        const color = statusColor(node.type, node.status);
        const lit = isLit(node.id);
        const isSel = sel === node.id;
        const isHov = hov === node.id;
        const isNew = recent.has(node.id);
        const ease = 1 - (1 - node.appear) ** 3;
        const r = style.radius * (0.55 + 0.45 * ease);

        ctx.globalAlpha = lit ? 1 : 0.18;

        // Halo for selection, hover, arrival, and in-flight states.
        const pulsing =
          node.status === "PROVING" || node.status === "PROVIDER_RUNNING" || node.status === "ROUTING";
        if (isSel || isHov || isNew || pulsing) {
          const beat = pulsing || isNew ? 0.5 + 0.5 * Math.sin(now / 320) : 1;
          const haloR = r + (isSel ? 15 : 11) + beat * 5;
          ctx.save();
          ctx.globalCompositeOperation = "lighter";
          const halo = ctx.createRadialGradient(node.x, node.y, r * 0.5, node.x, node.y, haloR);
          halo.addColorStop(0, style.glow);
          halo.addColorStop(1, "rgba(0,0,0,0)");
          ctx.globalAlpha = (lit ? 1 : 0.2) * (isSel ? 0.85 : 0.6) * (0.5 + beat * 0.5);
          ctx.fillStyle = halo;
          ctx.beginPath();
          ctx.arc(node.x, node.y, haloR, 0, Math.PI * 2);
          ctx.fill();
          ctx.restore();
        }

        // Body: dark fill with a coloured rim reads crisply at small sizes. A flat
        // fill rather than a gradient — a per-node gradient allocation on every
        // frame costs thousands of objects a second and looks the same at this size.
        drawShape(style.shape, node.x, node.y, r);
        ctx.fillStyle = "#10131c";
        ctx.fill();

        ctx.strokeStyle = color;
        ctx.lineWidth = (isSel ? 2.6 : 1.7) / Math.max(v.scale, 0.6);
        ctx.stroke();

        // Inner dot: colour at full saturation, so type is readable when zoomed out.
        drawShape(style.shape, node.x, node.y, r * 0.4);
        ctx.fillStyle = color;
        ctx.globalAlpha = (lit ? 1 : 0.18) * 0.9;
        ctx.fill();
        ctx.globalAlpha = lit ? 1 : 0.18;

        /**
         * Labels are deliberately sparse.
         *
         * Hubs are the landmarks a viewer navigates by, so they keep their names.
         * Per-request nodes do not: every row would otherwise read "Policy Proof
         * / Attempt 1 · ok / Response / Compute Receipt", which is the lane header
         * repeated once per row and nothing else. Those get labelled on hover or
         * selection, where the label actually answers a question.
         */
        const wantsLabel = node.hub || isSel || isHov;
        if (wantsLabel && (lit || isSel)) {
          const size = 11.5 / Math.max(v.scale, 0.62);
          ctx.font = `${isSel || node.hub ? 600 : 500} ${size}px ui-sans-serif, system-ui`;
          ctx.textAlign = "center";
          ctx.textBaseline = "top";

          // Labels are drawn at a constant on-screen size, so zooming out makes
          // them wider *relative to the lane*. Ellipsize to the lane width in
          // world units and they can never bleed into the neighbouring column.
          const label = ellipsize(ctx, node.label, laneWidth(node.lane) - 14);
          const ly = node.y + r + 5 / Math.max(v.scale, 0.62);

          // A dark backing keeps labels readable where edges pass behind them.
          const w = ctx.measureText(label).width;
          ctx.fillStyle = "rgba(5,6,10,0.78)";
          ctx.fillRect(node.x - w / 2 - 3, ly - 1, w + 6, size * 1.12);

          ctx.fillStyle = isSel || isHov ? "#eef0f6" : "rgba(235,240,250,0.82)";
          ctx.fillText(label, node.x, ly);
        }
      }
      ctx.globalAlpha = 1;

      raf = requestAnimationFrame(frame);
    };

    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
    };
  }, [compact]);

  // ---- interaction ----
  const onPointerDown = (e: React.PointerEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    pointer.current.down = true;
    pointer.current.dragged = false;
    pointer.current.lastX = e.clientX - rect.left;
    pointer.current.lastY = e.clientY - rect.top;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const cx = e.clientX - rect.left;
    const cy = e.clientY - rect.top;

    if (pointer.current.down) {
      const dx = cx - pointer.current.lastX;
      const dy = cy - pointer.current.lastY;
      if (Math.abs(dx) + Math.abs(dy) > 2) pointer.current.dragged = true;
      view.current.tx += dx;
      view.current.ty += dy;
      pointer.current.lastX = cx;
      pointer.current.lastY = cy;
      bump();
      return;
    }
    const hit = hitTest(cx, cy);
    setHoverId(hit?.id ?? null);
  };

  const onPointerUp = (e: React.PointerEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const wasDrag = pointer.current.dragged;
    pointer.current.down = false;
    if (wasDrag) return;
    const hit = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    onSelect(hit?.id ?? null);
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const rect = e.currentTarget.getBoundingClientRect();
    const cx = e.clientX - rect.left;
    const cy = e.clientY - rect.top;
    const v = view.current;
    const prev = v.scale;
    const next = clamp(prev * Math.exp(-e.deltaY * 0.0016), 0.22, 3);
    // Zoom about the cursor.
    v.tx = cx - ((cx - v.tx) * next) / prev;
    v.ty = cy - ((cy - v.ty) * next) / prev;
    v.scale = next;
    v.targetScale = next;
    bump();
  };

  const hovered = hoverId ? nodes.find((n) => n.id === hoverId) : null;

  return (
    <div ref={wrapRef} className={`relative overflow-hidden ${className}`}>
      <canvas
        ref={canvasRef}
        className={`absolute inset-0 ${hoverId ? "cursor-pointer" : "cursor-grab active:cursor-grabbing"}`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={() => {
          setHoverId(null);
          pointer.current.down = false;
        }}
        onWheel={onWheel}
      />

      {hovered && (
        <div className="pointer-events-none absolute left-3 bottom-3 panel px-3 py-2 max-w-[280px] animate-rise">
          <div className="flex items-center gap-2">
            <span
              className="size-2 rounded-full"
              style={{ background: statusColor(hovered.type, hovered.status) }}
            />
            <span className="label-xs">{NODE_STYLE[hovered.type].short}</span>
          </div>
          <div className="mt-1 text-[13px] font-medium text-ink truncate">{hovered.label}</div>
          {hovered.status && (
            <div className="mono mt-0.5 text-[11px] text-ink-3">{hovered.status}</div>
          )}
        </div>
      )}

      <button
        onClick={fit}
        className="absolute right-3 bottom-3 panel px-2.5 py-1.5 text-[11px] font-medium text-ink-2 hover:text-ink transition"
        title="Fit graph to view"
      >
        Fit
      </button>
    </div>
  );
}
