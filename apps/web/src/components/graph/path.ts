import type { GraphLink, GraphNode } from "@ctn/protocol";

/**
 * §48 — "make the currently selected request path visually dominant."
 *
 * The obvious implementation, an undirected BFS a few hops deep, does not work
 * here: the TEE, the policy, each provider and each model are *shared* by every
 * request. Hop one reaches those hubs, hop two walks back out of them into every
 * other request in the view, and the "isolated" set ends up being the whole
 * graph — so nothing dims and the control appears to do nothing.
 *
 * The fix is to treat hubs as terminals. They are included in the path, because a
 * request genuinely did execute in that TEE under that policy against that
 * provider, but traversal stops there instead of continuing into their other
 * neighbours.
 */
const HUB_TYPES = new Set<GraphNode["type"]>([
  "TEEWorker",
  "Policy",
  "Provider",
  "Model",
]);

export function requestPath(
  rootId: string,
  nodes: GraphNode[],
  links: GraphLink[]
): Set<string> | undefined {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  if (!byId.has(rootId)) return undefined;

  const adjacency = new Map<string, string[]>();
  const connect = (a: string, b: string) => {
    const list = adjacency.get(a);
    if (list) list.push(b);
    else adjacency.set(a, [b]);
  };
  for (const link of links) {
    connect(link.source, link.target);
    connect(link.target, link.source);
  }

  const path = new Set<string>([rootId]);
  let frontier = [rootId];

  for (let depth = 0; depth < 4 && frontier.length > 0; depth++) {
    const next: string[] = [];
    for (const id of frontier) {
      // A hub is a leaf of the path: include it, do not expand through it.
      if (id !== rootId && HUB_TYPES.has(byId.get(id)?.type ?? "Request")) continue;
      for (const neighbour of adjacency.get(id) ?? []) {
        if (path.has(neighbour)) continue;
        path.add(neighbour);
        next.push(neighbour);
      }
    }
    frontier = next;
  }

  return path;
}
