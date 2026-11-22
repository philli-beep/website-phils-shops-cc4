// Kern des Backends: reine Logik ohne Netlify-Abhängigkeit (testbar).
import { createHmac, timingSafeEqual } from "node:crypto";

const PUBLIC_READ = new Set(["done", "shop", "mapedit", "ostatus", "chat"]);
const OWN_READ = new Set(["routes", "ratings", "orders", "notify", "dm", "dmr", "tix"]);
const PLAYER_WRITE = new Set(["routes", "ratings", "orders", "chat", "dm", "tix"]);
const ALL = new Set([...PUBLIC_READ, ...OWN_READ]);
const TOKEN_TTL = 12 * 3600 * 1000;
const MAX_BODY = 400 * 1024;
const NAME = /^[A-Za-z0-9_]{3,16}$/;

const res = (status, json) => ({ status, json });

function secretOf(env) {
  return (env.TOKEN_SECRET || "") + "|" + (env.ADMIN_PASSWORD || "") + "|phils-shops";
}
export function makeToken(env, now = Date.now()) {
  const exp = String(now + TOKEN_TTL);
  const sig = createHmac("sha256", secretOf(env)).update(exp).digest("hex");
  return exp + "." + sig;
}
export function checkToken(env, token, now = Date.now()) {
  if (!token || typeof token !== "string") return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig || Number(exp) < now) return false;
  const want = createHmac("sha256", secretOf(env)).update(exp).digest("hex");
  const a = Buffer.from(sig), b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
}
function samePw(a, b) {
  const x = createHmac("sha256", "k").update(String(a)).digest();
  const y = createHmac("sha256", "k").update(String(b)).digest();
  return timingSafeEqual(x, y);
}
function parsePath(p) {
  const m = /^([a-z]+)(?:\/([A-Za-z0-9_-]{1,80}))?$/.exec(p || "");
  if (!m || !ALL.has(m[1])) return null;
  return { col: m[1], id: m[2] || null };
}
const str = (v, n) => typeof v === "string" && v.length <= n;

// Prüft/bereinigt, was ein Spieler in sein eigenes Dokument schreiben darf.
function cleanPlayerDoc(col, d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return null;
  if (col === "ratings") {
    if (!Number.isInteger(d.stars) || d.stars < 1 || d.stars > 5) return null;
    return { stars: d.stars, at: str(d.at, 40) ? d.at : "", ign: str(d.ign, 32) ? d.ign : "" };
  }
  if (col === "orders") {
    if (!Array.isArray(d.list) || d.list.length > 20) return null;
    const list = [];
    for (const o of d.list) {
      if (!o || !NAME.test(o.ign || "") || !["f1", "f4"].includes(o.farm) || !str(o.id, 40) || !str(o.at, 40)) return null;
      list.push({ id: o.id, ign: o.ign, farm: o.farm, at: o.at, meet: !!o.meet, where: str(o.where, 120) ? o.where : "" });
    }
    return { list };
  }
  if (col === "chat") {
    if (!Array.isArray(d.msgs) || d.msgs.length > 30) return null;
    const msgs = [];
    for (const m of d.msgs) {
      if (!m || !str(m.id, 40) || !str(m.t, 200) || !m.t.trim() || !NAME.test(m.n || "") || !Number.isFinite(m.at)) return null;
      msgs.push({ id: m.id, n: m.n, t: m.t, at: m.at });
    }
    return { msgs };
  }
  if (col === "tix") {
    if (!Array.isArray(d.items) || d.items.length > 4 || !NAME.test(d.ign || "")) return null;
    const items = [];
    for (const x of d.items) {
      if (!x || (x.d !== "ne" && x.d !== "ow") || !Number.isFinite(x.at)) return null;
      items.push({ d: x.d, at: x.at, h: x.h === true });
    }
    return { ign: d.ign, items };
  }
  if (col === "dm") {
    if (!Array.isArray(d.msgs) || d.msgs.length > 40 || !NAME.test(d.n || "")) return null;
    const msgs = [];
    for (const m of d.msgs) {
      if (!m || !str(m.id, 40) || !str(m.t, 200) || !m.t.trim() || !Number.isFinite(m.at)) return null;
      msgs.push({ id: m.id, t: m.t, at: m.at });
    }
    return { n: d.n, msgs };
  }
  if (col === "routes") {
    if (!Array.isArray(d.subs) || d.subs.length > 40) return null;
    for (const s of d.subs) {
      if (!s || !str(s.ign, 32) || !str(s.at, 40) || !Array.isArray(s.s) || s.s.length > 200) return null;
    }
    return { subs: d.subs };
  }
  return null;
}

/**
 * req: { method, route, path, body (string), uid, token }
 * store: { get(key), set(key, obj), del(key), list(prefix) -> [key] }
 */
export async function handle(req, store, env) {
  if (!env.ADMIN_PASSWORD) return res(500, { error: "ADMIN_PASSWORD ist nicht gesetzt" });
  const admin = checkToken(env, req.token);
  const uid = /^[a-f0-9]{16,64}$/.test(req.uid || "") ? req.uid : "";

  if (req.route === "login") {
    if (req.method !== "POST") return res(405, { error: "method" });
    let b; try { b = JSON.parse(req.body || "{}"); } catch { return res(400, { error: "json" }); }
    if (typeof b.password === "string" && samePw(b.password, env.ADMIN_PASSWORD)) return res(200, { token: makeToken(env) });
    return res(401, { error: "Falsches Passwort" });
  }
  if (req.route === "ping") return res(200, { ok: true, admin });

  if (req.route === "col") {
    if (req.method !== "GET") return res(405, { error: "method" });
    const p = parsePath(req.path);
    if (!p || p.id) return res(400, { error: "path" });
    if (!PUBLIC_READ.has(p.col) && !admin) return res(403, { error: "keine Rechte" });
    const keys = (await store.list(p.col + "/")).slice(0, 500);
    const docs = [];
    for (const k of keys) { const data = await store.get(k); if (data != null) docs.push({ id: k.slice(p.col.length + 1), data }); }
    return res(200, { docs });
  }

  if (req.route === "doc") {
    const p = parsePath(req.path);
    if (!p || !p.id) return res(400, { error: "path" });
    const key = p.col + "/" + p.id;
    if (req.method === "GET") {
      const ok = admin || PUBLIC_READ.has(p.col) || (OWN_READ.has(p.col) && uid && p.id === uid);
      if (!ok) return res(403, { error: "keine Rechte" });
      return res(200, { data: (await store.get(key)) ?? null });
    }
    if (req.method === "PUT" || req.method === "DELETE") {
      const own = uid && p.id === uid && PLAYER_WRITE.has(p.col);
      if (!admin && !own) return res(403, { error: "keine Rechte" });
      if (req.method === "DELETE") { await store.del(key); return res(200, { ok: true }); }
      if ((req.body || "").length > MAX_BODY) return res(413, { error: "zu groß" });
      let d; try { d = JSON.parse(req.body || "null"); } catch { return res(400, { error: "json" }); }
      if (!admin) {
        const sh = (await store.get("shop/status")) || {};
        if (p.col === "orders" && !sh.open) return res(403, { error: "XP Shop geschlossen" });
        if (p.col === "tix") {
          const prev = (await store.get(key)) || { items: [] };
          for (const x of (Array.isArray(d && d.items) ? d.items : [])) if (!(prev.items || []).some((y) => y.d === x.d) && sh.tix && sh.tix[x.d] === false) return res(403, { error: "Ticket nicht verfügbar" });
        }
        if (p.col === "chat" && sh.chat === false) return res(403, { error: "Chat ist aus" });
        if (p.col === "routes" && !sh.cb) return res(403, { error: "Cushion Weg bauen geschlossen" });
        d = cleanPlayerDoc(p.col, d); if (!d) return res(400, { error: "ungültig" });
        const nk = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9_]/g, "");
        const blocked = (ign, kind) => { const b = sh.blocks && sh.blocks[nk(ign)]; const u = b && b[kind]; return !!u && (u === -1 || u > Date.now()); };
        if (p.col === "orders" && d.list.length) {
          const last = d.list[d.list.length - 1];
          const prev = (await store.get(key)) || { list: [] };
          const isNew = !(prev.list || []).some((o) => o.id === last.id);
          if (isNew) {
            if (blocked(last.ign, "o")) return res(403, { error: "gesperrt" });
            const os = (await store.get("ostatus/" + nk(last.ign))) || { orders: [] };
            const active = d.list.filter((o) => nk(o.ign) === nk(last.ign)).filter((o) => { const s = (os.orders || []).find((x) => x.id === o.id); const st = s ? s.state : "bearb"; return st !== "fertig" && st !== "no"; });
            const mx = Number.isInteger(sh.maxord) && sh.maxord >= 1 ? sh.maxord : 2;
            if (active.length > mx) return res(403, { error: "zu viele offene Bestellungen" });
          }
        }
        if (p.col === "tix") {
          const prev = (await store.get(key)) || { items: [] };
          d.items = d.items.map((x) => { const o = (prev.items || []).find((y) => y.d === x.d); return { d: x.d, at: o ? o.at : x.at, h: !!(o && o.h) }; });
        }
        if (p.col === "chat" && d.msgs.length) {
          const prev = (await store.get(key)) || { msgs: [] };
          const last = d.msgs[d.msgs.length - 1];
          if (!(prev.msgs || []).some((x) => x.id === last.id) && blocked(last.n, "c")) return res(403, { error: "stumm" });
        }
        if (p.col === "routes" && d.subs.length) {
          const prev = (await store.get(key)) || { subs: [] };
          if (d.subs.length > (prev.subs || []).length && blocked(d.subs[d.subs.length - 1].ign, "r")) return res(403, { error: "gesperrt" });
        }
      }
      else if (!d || typeof d !== "object" || Array.isArray(d)) return res(400, { error: "ungültig" });
      await store.set(key, d);
      return res(200, { ok: true });
    }
    return res(405, { error: "method" });
  }
  return res(404, { error: "unbekannt" });
}
