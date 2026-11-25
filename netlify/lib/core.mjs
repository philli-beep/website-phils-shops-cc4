// Kern des Backends: reine Logik ohne Netlify-Abhängigkeit (testbar).
import { createHmac, timingSafeEqual } from "node:crypto";

const PUBLIC_READ = new Set(["done", "shop", "mapedit", "ostatus", "chat", "tixpub"]);
const OWN_READ = new Set(["routes", "ratings", "orders", "notify", "dm", "dmr", "tix", "pro", "biz", "korb"]);
const PLAYER_WRITE = new Set(["routes", "ratings", "orders", "chat", "dm", "tix", "pro", "biz", "korb"]);
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
export function makePgToken(env, now = Date.now()) {
  const exp = String(now + TOKEN_TTL);
  const sig = createHmac("sha256", (env.TOKEN_SECRET || "") + "|" + (env.PIGLIN_PASSWORD || "") + "|phils-shops-pg").update("pg" + exp).digest("hex");
  return exp + ".pg." + sig;
}
export function checkPgToken(env, token, now = Date.now()) {
  if (!env.PIGLIN_PASSWORD || !token || typeof token !== "string") return false;
  const [exp, tag, sig] = token.split(".");
  if (!exp || tag !== "pg" || !sig || Number(exp) < now) return false;
  const want = createHmac("sha256", (env.TOKEN_SECRET || "") + "|" + env.PIGLIN_PASSWORD + "|phils-shops-pg").update("pg" + exp).digest("hex");
  const a = Buffer.from(sig), b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
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
// Öffentliche Liste: wer hat ein bestätigtes Ticket (nur Name und Art, nichts sonst).
async function rebuildTixPub(store) {
  try {
    const list = [];
    for (const k of await store.list("tix/")) {
      const t = await store.get(k); if (!t) continue;
      const ok = (t.items || []).filter((x) => (x.st || (x.h ? "ok" : "p")) === "ok").map((x) => x.d);
      if (ok.length && NAME.test(t.ign || "")) list.push({ n: t.ign, ne: ok.includes("ne"), ow: ok.includes("ow") });
    }
    const man = await store.get("tixpub/manual");
    for (const m of (man && Array.isArray(man.list) ? man.list : [])) {
      if (!m || !NAME.test(m.n || "")) continue;
      const e = list.find((x) => x.n.toLowerCase() === m.n.toLowerCase());
      if (e) { e.ne = e.ne || !!m.ne; e.ow = e.ow || !!m.ow; } else list.push({ n: m.n, ne: !!m.ne, ow: !!m.ow });
    }
    list.sort((a, b) => a.n.toLowerCase().localeCompare(b.n.toLowerCase()));
    await store.set("tixpub/main", { list, at: Date.now() });
  } catch {}
}

const PIG_KEYS = ["eb","ib","fr","sf","wb","in","qz","gl","mc","ep","st","fc","gr","le","nb","ob","co","ss"];
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
      if (!x || !["ne", "ow", "pn", "po"].includes(x.d) || !Number.isFinite(x.at)) return null;
      items.push({ d: x.d, at: x.at, st: "p" });
    }
    return { ign: d.ign, items };
  }
  if (col === "korb") {
    if (!Array.isArray(d.list) || d.list.length > 10 || !NAME.test(d.ign || "")) return null;
    const list = [];
    for (const o of d.list) {
      if (!o || !str(o.id, 40) || !Number.isFinite(o.at) || !Number.isInteger(o.offer) || o.offer < 1 || o.offer > 100000 || !Array.isArray(o.items) || !o.items.length || o.items.length > 18) return null;
      const items = [];
      for (const x of o.items) { if (!x || !PIG_KEYS.includes(x.k) || !Number.isInteger(x.n) || x.n < 1 || x.n > 576) return null; items.push({ k: x.k, n: x.n }); }
      const msgs = [];
      for (const m of (Array.isArray(o.msgs) ? o.msgs : []).slice(-40)) { if (m && m.f === "p" && str(m.id, 40) && str(m.t, 200) && m.t.trim() && Number.isFinite(m.at)) msgs.push({ id: m.id, t: m.t, at: m.at, f: "p" }); }
      list.push({ id: o.id, at: o.at, items, offer: o.offer, st: "p", msgs, acc: o.acc === true });
    }
    return { ign: d.ign, list };
  }
  if (col === "pro" || col === "biz") {
    if (!NAME.test(d.ign || "") || !Number.isFinite(d.at)) return null;
    return { ign: d.ign, at: d.at, st: "p" };
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
  const pg = !admin && checkPgToken(env, req.token);
  const uid = /^[a-f0-9]{16,64}$/.test(req.uid || "") ? req.uid : "";

  if (req.route === "login") {
    if (req.method !== "POST") return res(405, { error: "method" });
    let b; try { b = JSON.parse(req.body || "{}"); } catch { return res(400, { error: "json" }); }
    if (typeof b.password === "string" && samePw(b.password, env.ADMIN_PASSWORD)) return res(200, { token: makeToken(env), scope: "admin" });
    if (typeof b.password === "string" && env.PIGLIN_PASSWORD && samePw(b.password, env.PIGLIN_PASSWORD)) return res(200, { token: makePgToken(env), scope: "pg" });
    return res(401, { error: "Falsches Passwort" });
  }
  if (req.route === "ping") return res(200, { ok: true, admin, pg });

  if (req.route === "col") {
    if (req.method !== "GET") return res(405, { error: "method" });
    const p = parsePath(req.path);
    if (!p || p.id) return res(400, { error: "path" });
    if (!PUBLIC_READ.has(p.col) && !admin && !(pg && p.col === "korb")) return res(403, { error: "keine Rechte" });
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
      const ok = admin || (pg && p.col === "korb") || PUBLIC_READ.has(p.col) || (OWN_READ.has(p.col) && uid && p.id === uid);
      if (!ok) return res(403, { error: "keine Rechte" });
      return res(200, { data: (await store.get(key)) ?? null });
    }
    if (req.method === "PUT" || req.method === "DELETE") {
      const own = uid && p.id === uid && PLAYER_WRITE.has(p.col);
      if (pg && key === "shop/status" && req.method === "PUT") {
        let nd; try { nd = JSON.parse(req.body || "null"); } catch { return res(400, { error: "json" }); }
        if (!nd || typeof nd.pig !== "boolean") return res(400, { error: "ungültig" });
        const cur = (await store.get(key)) || {}; cur.pig = nd.pig; await store.set(key, cur); return res(200, { ok: true });
      }
      const priv = admin || (pg && p.col === "korb");
      if (!priv && !own) return res(403, { error: "keine Rechte" });
      if (req.method === "DELETE") { await store.del(key); if (p.col === "tix") await rebuildTixPub(store); return res(200, { ok: true }); }
      if ((req.body || "").length > MAX_BODY) return res(413, { error: "zu groß" });
      let d; try { d = JSON.parse(req.body || "null"); } catch { return res(400, { error: "json" }); }
      if (!priv) {
        const sh = (await store.get("shop/status")) || {};
        const prevD = (await store.get(key)) || {}; const shrink = (Array.isArray(d && d.list) ? d.list.length < (prevD.list || []).length : false) || (Array.isArray(d && d.subs) ? d.subs.length < (prevD.subs || []).length : false);
        if (p.col === "orders" && !sh.open && !shrink) return res(403, { error: "XP Shop geschlossen" });
        if (p.col === "tix") {
          const prev = (await store.get(key)) || { items: [] };
          for (const x of (Array.isArray(d && d.items) ? d.items : [])) if (!(prev.items || []).some((y) => y.d === x.d) && sh.tix && sh.tix[x.d] === false) return res(403, { error: "Ticket nicht verfügbar" });
        }
        if (p.col === "chat" && sh.chat === false) return res(403, { error: "Chat ist aus" });
        if (p.col === "routes" && !sh.cb && !shrink) return res(403, { error: "Cushion Weg bauen geschlossen" });
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
            const mx = (Number.isInteger(sh.maxord) && sh.maxord >= 1 ? sh.maxord : 2) + ((Array.isArray(sh.biz) && sh.biz.some((q) => nk(q) === nk(last.ign))) ? 2 : (Array.isArray(sh.pros) && sh.pros.some((q) => nk(q) === nk(last.ign))) ? 1 : 0);
            if (active.length > mx) return res(403, { error: "zu viele offene Bestellungen" });
          }
        }
        if (p.col === "tix") {
          const prev = (await store.get(key)) || { items: [] };
          d.items = d.items.map((x) => { const o = (prev.items || []).find((y) => y.d === x.d && y.at === x.at); return { d: x.d, at: x.at, st: o ? (o.st || (o.h ? "ok" : "p")) : "p" }; });
        }
        if (p.col === "korb") {
          const prev = (await store.get(key)) || { list: [] };
          if (sh.pig === false && d.list.some((o) => !(prev.list || []).some((y) => y.id === o.id))) return res(403, { error: "Piglin Shop geschlossen" });
          d.list = d.list.map((o) => { const y = (prev.list || []).find((q) => q.id === o.id); if (!y) { delete o.acc; return o; } let st = y.st || "p", offer = y.offer, ctr = y.ctr; if (o.acc === true && st === "c" && y.ctr) { st = "ok"; offer = y.ctr; ctr = undefined; } const am = (y.msgs || []).filter((m) => m.f === "a"); const msgs = am.concat(o.msgs).sort((a, b) => a.at - b.at).slice(-60); return { id: o.id, at: o.at, items: o.items, offer, st, ...(ctr ? { ctr } : {}), msgs }; });
        }
        if (p.col === "pro" || p.col === "biz") {
          const prev = (await store.get(key)) || {};
          d.st = prev.at === d.at && prev.st ? prev.st : "p";
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
      if (p.col === "tix" || (p.col === "tixpub" && p.id === "manual")) await rebuildTixPub(store);
      return res(200, { ok: true });
    }
    return res(405, { error: "method" });
  }
  return res(404, { error: "unbekannt" });
}
