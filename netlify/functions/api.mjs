import { getStore } from "@netlify/blobs";
import { handle } from "../lib/core.mjs";

function adapter() {
  const s = getStore({ name: "phils-shops", consistency: "strong" });
  return {
    get: (k) => s.get(k, { type: "json" }),
    set: (k, v) => s.setJSON(k, v),
    del: (k) => s.delete(k),
    list: async (prefix) => {
      const out = [];
      const { blobs } = await s.list({ prefix });
      for (const b of blobs) out.push(b.key);
      return out;
    },
  };
}

export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const body = req.method === "GET" || req.method === "DELETE" ? "" : await req.text();
  const auth = req.headers.get("authorization") || "";
  const out = await handle(
    {
      method: req.method,
      route,
      path: url.searchParams.get("path") || "",
      body,
      uid: req.headers.get("x-uid") || "",
      token: auth.startsWith("Bearer ") ? auth.slice(7) : "",
    },
    adapter(),
    { ADMIN_PASSWORD: process.env.ADMIN_PASSWORD, TOKEN_SECRET: process.env.TOKEN_SECRET },
  );
  if (route === "login" && out.status === 401) await new Promise((r) => setTimeout(r, 800));
  return new Response(JSON.stringify(out.json), {
    status: out.status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
};

export const config = { path: "/api/*" };
