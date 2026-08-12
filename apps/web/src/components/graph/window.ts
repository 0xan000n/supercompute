import type { GraphLink, GraphNode } from "@ctn/protocol";

/**
 * Keeps the graph legible as traffic accumulates.
 *
 * The network's landmarks — contributors, credentials, the TEE, the policy,
 * providers, models — are always kept, because they are what the picture is
 * about. Only request flows are windowed: the most recent N requests and the
 * proof, attempt, response and receipt nodes that belong to them.
 *
 * Windowing happens in the client rather than the API so nothing is lost: the
 * projection still holds every request, and raising the window reveals them
 * without a refetch.
 */
export interface WindowedGraph {
  nodes: GraphNode[];
  links: GraphLink[];
  totalRequests: number;
  hiddenRequests: number;
}

const HUB_TYPES = new Set(["Contributor", "Credential", "TEEWorker", "Policy", "Provider", "Model"]);

export function windowGraph(
  nodes: GraphNode[],
  links: GraphLink[],
  limit: number | null
): WindowedGraph {
  const requests = nodes
    .filter((n) => n.type === "Request")
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));

  if (limit === null || requests.length <= limit) {
    return { nodes, links, totalRequests: requests.length, hiddenRequests: 0 };
  }

  const keptRequests = new Set(requests.slice(0, limit).map((r) => r.id));

  // A flow node is kept when the request that owns it is kept.
  const requestIds = new Set(requests.map((r) => r.id));
  const ownerOf = new Map<string, string>();
  for (const link of links) {
    if (requestIds.has(link.source) && !requestIds.has(link.target)) {
      ownerOf.set(link.target, link.source);
    }
  }

  const keep = new Set<string>();
  for (const node of nodes) {
    if (HUB_TYPES.has(node.type)) {
      keep.add(node.id);
      continue;
    }
    if (node.type === "Request") {
      if (keptRequests.has(node.id)) keep.add(node.id);
      continue;
    }
    const owner = ownerOf.get(node.id);
    // An orphan flow node (owner not yet projected) is kept: dropping it would
    // make a live request look incomplete mid-flight.
    if (owner === undefined || keptRequests.has(owner)) keep.add(node.id);
  }

  return {
    nodes: nodes.filter((n) => keep.has(n.id)),
    links: links.filter((l) => keep.has(l.source) && keep.has(l.target)),
    totalRequests: requests.length,
    hiddenRequests: requests.length - keptRequests.size,
  };
}
