"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { GraphLink, GraphNode, GraphSnapshot } from "@ctn/protocol";

/**
 * Where the coordinator lives.
 *
 * Locally it is a separate process on its own port. In the hosted build it is
 * routed at a same-origin sub-path, which avoids CORS entirely and keeps an HTTPS
 * page from having to call plain-HTTP localhost.
 */
export const COORDINATOR =
  process.env.NEXT_PUBLIC_COORDINATOR_URL ?? "http://127.0.0.1:4200";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${COORDINATOR}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  const json = (await res.json()) as T & { error?: { code: string; message: string } };
  if (!res.ok) {
    throw Object.assign(new Error(json.error?.message ?? `request failed (${res.status})`), {
      code: json.error?.code ?? "CTN_INTERNAL",
      payload: json,
    });
  }
  return json;
}

export function usePolled<T>(path: string, intervalMs = 3000): { data: T | null; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [path]);

  useEffect(() => {
    void load();
    if (intervalMs <= 0) return;
    const timer = setInterval(() => void load(), intervalMs);
    return () => clearInterval(timer);
  }, [load, intervalMs]);

  return { data, error, refresh: load };
}

export interface LiveGraph {
  nodes: GraphNode[];
  links: GraphLink[];
  connected: boolean;
  /** Node ids that arrived within the last moment — used to animate entry. */
  recent: Set<string>;
}

/**
 * §47 — snapshot first, then subscribe. The SSE stream carries node.created /
 * node.updated / link.created, so the graph converges without polling.
 */
export function useLiveGraph(): LiveGraph {
  const [nodes, setNodes] = useState<Map<string, GraphNode>>(new Map());
  const [links, setLinks] = useState<Map<string, GraphLink>>(new Map());
  const [connected, setConnected] = useState(false);
  const [recent, setRecent] = useState<Set<string>>(new Set());
  const recentTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const markRecent = useCallback((id: string) => {
    setRecent((prev) => new Set(prev).add(id));
    const timers = recentTimers.current;
    clearTimeout(timers.get(id));
    timers.set(
      id,
      setTimeout(() => {
        setRecent((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
        timers.delete(id);
      }, 2600)
    );
  }, []);

  useEffect(() => {
    let cancelled = false;
    let source: EventSource | null = null;

    const start = async () => {
      try {
        const snapshot = await api<GraphSnapshot>("/v1/graph");
        if (cancelled) return;
        setNodes(new Map(snapshot.nodes.map((n) => [n.id, n])));
        setLinks(new Map(snapshot.links.map((l) => [l.id, l])));
      } catch {
        // The stream may still connect; a failed snapshot is not fatal.
      }
      if (cancelled) return;

      source = new EventSource(`${COORDINATOR}/v1/graph/events`);
      source.onopen = () => setConnected(true);
      source.onerror = () => setConnected(false);

      const onNode = (event: MessageEvent) => {
        const payload = JSON.parse(event.data) as { kind: string; node: GraphNode };
        setNodes((prev) => new Map(prev).set(payload.node.id, payload.node));
        if (payload.kind === "node.created") markRecent(payload.node.id);
      };
      source.addEventListener("node.created", onNode as EventListener);
      source.addEventListener("node.updated", onNode as EventListener);
      source.addEventListener("link.created", ((event: MessageEvent) => {
        const payload = JSON.parse(event.data) as { link: GraphLink };
        setLinks((prev) => new Map(prev).set(payload.link.id, payload.link));
        markRecent(payload.link.id);
      }) as EventListener);
    };

    void start();
    return () => {
      cancelled = true;
      source?.close();
      for (const timer of recentTimers.current.values()) clearTimeout(timer);
      recentTimers.current.clear();
    };
  }, [markRecent]);

  return {
    nodes: Array.from(nodes.values()),
    links: Array.from(links.values()),
    connected,
    recent,
  };
}
