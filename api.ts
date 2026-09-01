import { storage } from "@/src/utils/storage";

const BASE = process.env.EXPO_PUBLIC_BACKEND_URL;
export const TOKEN_KEY = "bookverse.token";

async function req<T>(path: string, opts: RequestInit = {}, auth = true): Promise<T> {
  const token = auth ? await storage.secureGet<string>(TOKEN_KEY, "") : null;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((opts.headers as Record<string, string>) ?? {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${BASE}/api${path}`, { ...opts, headers });
  const text = await res.text();
  const data = text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : null;
  if (!res.ok) {
    const msg = (data && typeof data === "object" && "detail" in data) ? (data as any).detail : `HTTP ${res.status}`;
    throw new Error(String(msg));
  }
  return data as T;
}

export const api = {
  get: <T,>(p: string, auth = true) => req<T>(p, { method: "GET" }, auth),
  post: <T,>(p: string, body?: any, auth = true) => req<T>(p, { method: "POST", body: JSON.stringify(body ?? {}) }, auth),
  put: <T,>(p: string, body?: any, auth = true) => req<T>(p, { method: "PUT", body: JSON.stringify(body ?? {}) }, auth),
  del: <T,>(p: string, auth = true) => req<T>(p, { method: "DELETE" }, auth),
};
