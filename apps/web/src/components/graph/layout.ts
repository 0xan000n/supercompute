import type { GraphLink, GraphNode, GraphNodeType } from "@ctn/protocol";

/**
 * §48 — a deterministic layered layout, not a force simulation.
 *
 * The spec asks for a specific reading order (contributors left, TEE and policy
 * in the centre, providers and models right, requests crossing the middle). A
 * force layout would scramble that on every update, so nodes are placed by type
 * into fixed lanes instead.
 *
 * The layout's one real idea: a request and everything that belongs only to it
 * (its proof, its attempts, its response, its receipt) share a single row. That
 * turns each request into one clean horizontal line and leaves the only crossing
 * edges as the meaningful ones — requests reaching back to whichever
 * contributor's credential served them, which is the story the demo is telling.
 *
 * Positions are stable across updates: an arriving node animates in on its own
 * row instead of rearranging the picture.
 */

export interface PositionedNode extends GraphNode {
  lane: number;
  tx: number;
  ty: number;
  /** rendered position, eased toward the target each frame */
  x: number;
  y: number;
  /** 0 → 1 entry animation */
  appear: number;
  /** hubs are shared landmarks; flow nodes belong to exactly one request */
  hub: boolean;
}

export interface LayoutResult {
  nodes: Map<string, PositionedNode>;
  height: number;
  width: number;
  rowHeight: number;
}

/**
 * Lanes are individually sized: columns whose nodes carry real names need room
 * for a label, columns that repeat the same word every row do not. Uniform lane
 * widths meant either truncating "Alice's OpenAI credits" to eight characters or
 * wasting the same space on ten identical "Receipt" columns.
 */
export const LANES: Array<{ label: string; width: number }> = [
  { label: "Contributors", width: 116 },
  { label: "Credentials", width: 176 },
  { label: "Requests", width: 132 },
  { label: "TEE · Policy", width: 140 },
  { label: "Proof", width: 84 },
  { label: "Attempts", width: 84 },
  { label: "Providers", width: 108 },
  { label: "Models", width: 156 },
  { label: "Response", width: 84 },
  { label: "Receipt", width: 84 },
];

/** Left edge of each lane, and the centre x used for node placement. */
const LANE_X: number[] = (() => {
  const centres: number[] = [];
  let x = 0;
  for (const lane of LANES) {
    centres.push(x + lane.width / 2);
    x += lane.width;
  }
  return centres;
})();

export const LAYOUT_WIDTH = LANES.reduce((sum, l) => sum + l.width, 0);

export function laneCentre(lane: number): number {
  return LANE_X[lane] ?? 0;
}

export function laneWidth(lane: number): number {
  return LANES[lane]?.width ?? 100;
}
const MAX_ROW_HEIGHT = 58;
const MIN_ROW_HEIGHT = 26;
const TARGET_HEIGHT = 780;

const LANE_OF: Record<GraphNodeType, number> = {
  Contributor: 0,
  Credential: 1,
  Request: 2,
  TEEWorker: 3,
  Policy: 3,
  Proof: 4,
  ProviderAttempt: 5,
  Provider: 6,
  Model: 7,
  Response: 8,
  ComputeReceipt: 9,
};

/** Types that exist once per request, and therefore inherit its row. */
const FLOW_TYPES = new Set<GraphNodeType>(["Proof", "ProviderAttempt", "Response", "ComputeReceipt"]);

export function layout(
  nodes: GraphNode[],
  links: GraphLink[],
  previous: Map<string, PositionedNode> | null
): LayoutResult {
  const byId = new Map<string, PositionedNode>();

  for (const node of nodes) {
    const prior = previous?.get(node.id);
    byId.set(node.id, {
      ...node,
      lane: LANE_OF[node.type] ?? 3,
      hub: !FLOW_TYPES.has(node.type) && node.type !== "Request",
      tx: prior?.tx ?? 0,
      ty: prior?.ty ?? 0,
      x: prior?.x ?? Number.NaN,
      y: prior?.y ?? Number.NaN,
      appear: prior?.appear ?? 0,
    });
  }

  // Requests define the rows, oldest at top so existing rows never shift when a
  // new request arrives.
  const requests = [...byId.values()]
    .filter((n) => n.type === "Request")
    .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id));

  const rowHeight = Math.max(
    MIN_ROW_HEIGHT,
    Math.min(MAX_ROW_HEIGHT, requests.length > 0 ? TARGET_HEIGHT / requests.length : MAX_ROW_HEIGHT)
  );
  const height = Math.max(280, requests.length * rowHeight);

  const rowOf = new Map<string, number>();
  requests.forEach((request, i) => {
    const y = (height - requests.length * rowHeight) / 2 + i * rowHeight + rowHeight / 2;
    rowOf.set(request.id, y);
    request.tx = laneCentre(2);
    request.ty = y;
  });

  // Map each flow node to the request that owns it, via the request's own edges.
  const ownerOf = new Map<string, string>();
  for (const link of links) {
    const source = byId.get(link.source);
    const target = byId.get(link.target);
    if (!source || !target) continue;
    if (source.type === "Request" && FLOW_TYPES.has(target.type)) {
      ownerOf.set(target.id, source.id);
    }
  }

  // Several attempts can share a request; fan them out slightly so they read as
  // separate events rather than one node.
  const attemptSeen = new Map<string, number>();

  for (const node of byId.values()) {
    if (node.type === "Request") continue;
    node.tx = laneCentre(node.lane);

    if (!node.hub) {
      const owner = ownerOf.get(node.id);
      const y = owner ? rowOf.get(owner) : undefined;
      if (y !== undefined) {
        if (node.type === "ProviderAttempt") {
          const index = attemptSeen.get(owner!) ?? 0;
          attemptSeen.set(owner!, index + 1);
          node.ty = y + index * Math.min(15, rowHeight * 0.42);
        } else {
          node.ty = y;
        }
        continue;
      }
      // Orphan (its request has not projected yet): park it centrally.
      node.ty = height / 2;
    }
  }

  // Hubs: evenly distributed down their lane, ordered so that a credential sits
  // near the contributor that owns it.
  const hubLanes = new Map<number, PositionedNode[]>();
  for (const node of byId.values()) {
    if (!node.hub) continue;
    (hubLanes.get(node.lane) ?? hubLanes.set(node.lane, []).get(node.lane)!).push(node);
  }

  const orderIndex = new Map<string, number>();
  const contributorLane = (hubLanes.get(0) ?? []).sort(
    (a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id)
  );
  contributorLane.forEach((n, i) => orderIndex.set(n.id, i));

  // A credential inherits its contributor's ordinal, keeping the pairs aligned.
  const ownerContributor = new Map<string, string>();
  for (const link of links) {
    if (link.type !== "CONTRIBUTED") continue;
    ownerContributor.set(link.target, link.source);
  }

  for (const [lane, group] of hubLanes) {
    group.sort((a, b) => {
      if (lane === 1) {
        const ao = orderIndex.get(ownerContributor.get(a.id) ?? "") ?? 1e6;
        const bo = orderIndex.get(ownerContributor.get(b.id) ?? "") ?? 1e6;
        if (ao !== bo) return ao - bo;
      }
      return Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id);
    });

    const gap = height / (group.length + 1);
    group.forEach((node, i) => {
      node.ty = gap * (i + 1);
    });
  }

  // Seed render positions for genuinely new nodes: entering from the left of
  // their lane makes arrival read as flowing into the network.
  for (const node of byId.values()) {
    if (Number.isNaN(node.x)) {
      node.x = node.tx - 40;
      node.y = node.ty;
    }
  }

  return { nodes: byId, height, width: LAYOUT_WIDTH, rowHeight };
}

/**
 * Exponential smoothing toward the target — frame-rate independent, cannot
 * oscillate, and settles in roughly a third of a second. A spring was tried
 * first and needed careful tuning to avoid either overshoot or a multi-second
 * crawl; this has no such failure mode.
 */
export function settle(node: PositionedNode, dt: number): void {
  const alpha = 1 - Math.exp(-11 * dt);
  node.x += (node.tx - node.x) * alpha;
  node.y += (node.ty - node.y) * alpha;
  if (Math.abs(node.tx - node.x) < 0.08) node.x = node.tx;
  if (Math.abs(node.ty - node.y) < 0.08) node.y = node.ty;
  node.appear = Math.min(1, node.appear + dt * 2.8);
}
