// Config Wall — one tiny API for the shared takeaway wall.
// GET  /api/takeaways              → public list (hidden entries removed, unlisted names stripped)
// GET  /api/takeaways?admin=KEY    → everything, for moderation + CSV export
// POST /api/takeaways              → add a takeaway
// POST /api/takeaways {action, id, key} → admin: hide | unhide | delete
// POST /api/takeaways {action:"remove", id, token} → author deletes their own takeaway
import { getStore } from "@netlify/blobs";

const THEMES = ["ai", "systems", "craft", "code", "career", "community", "other"];
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX = 30; // generous: conference wifi puts many people behind one IP

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });

const clean = (v, max) =>
  String(v ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);

const cleanLink = (v) => {
  let s = clean(v, 200);
  if (!s) return "";
  if (!/^https?:\/\//i.test(s)) s = "https://" + s.replace(/^\/+/, "");
  try {
    const u = new URL(s);
    if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".")) return "";
    return u.toString();
  } catch {
    return "";
  }
};

const sha256 = async (s) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const strip = ({ tokenHash, ...e }) => e;
const publicView = (e) =>
  e.listed ? strip(e) : strip({ ...e, name: "", role: "", company: "", link: "" });

export default async (req, context) => {
  const store = getStore({ name: "config-wall", consistency: "strong" });
  const url = new URL(req.url);
  const adminKey = Netlify.env.get("ADMIN_KEY");
  const isAdmin = (k) => Boolean(adminKey && k && k === adminKey);

  if (req.method === "GET") {
    const admin = isAdmin(url.searchParams.get("admin"));
    const { blobs } = await store.list({ prefix: "entry/" });
    const all = (
      await Promise.all(blobs.map((b) => store.get(b.key, { type: "json" })))
    ).filter(Boolean);
    const entries = (admin ? all.map(strip) : all.filter((e) => !e.hidden).map(publicView)).sort(
      (a, b) => b.ts - a.ts
    );
    return json(
      { entries },
      200,
      admin
        ? { "cache-control": "no-store" }
        : {
            "cache-control": "public, max-age=0, must-revalidate",
            "netlify-cdn-cache-control": "public, durable, s-maxage=6, stale-while-revalidate=30",
          }
    );
  }

  if (req.method === "POST") {
    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: "Bad request" }, 400);
    }

    // Author removes their own takeaway (token was handed out once, at creation)
    if (body.action === "remove") {
      const key = "entry/" + clean(body.id, 80);
      const entry = await store.get(key, { type: "json" });
      if (!entry) return json({ ok: true }); // already gone
      const token = String(body.token || "");
      if (!token || !entry.tokenHash || (await sha256(token)) !== entry.tokenHash)
        return json({ error: "You can only delete your own takeaway." }, 403);
      await store.delete(key);
      return json({ ok: true });
    }

    // Admin moderation
    if (body.action) {
      if (!isAdmin(body.key)) return json({ error: "Unauthorized" }, 401);
      const key = "entry/" + clean(body.id, 80);
      const entry = await store.get(key, { type: "json" });
      if (!entry) return json({ error: "Not found" }, 404);
      if (body.action === "delete") {
        await store.delete(key);
        return json({ ok: true });
      }
      entry.hidden = body.action === "hide";
      await store.setJSON(key, entry);
      return json({ ok: true, entry: strip(entry) });
    }

    // Honeypot: bots fill every field. Pretend it worked.
    if (body.website) return json({ ok: true, entry: null }, 201);

    const entry = {
      text: clean(body.text, 240),
      theme: THEMES.includes(body.theme) ? body.theme : "other",
      name: clean(body.name, 60),
      role: clean(body.role, 60),
      company: clean(body.company, 60),
      link: cleanLink(body.link),
      listed: body.listed !== false,
      ts: Date.now(),
    };
    if (entry.text.length < 3) return json({ error: "Add your takeaway first." }, 400);
    if (!entry.name) return json({ error: "Add your name." }, 400);

    // Soft rate limit per IP
    const ip = (context.ip || "unknown").replace(/[^a-zA-Z0-9:.]/g, "_");
    const rlKey = "rl/" + ip;
    const now = Date.now();
    const rl = (await store.get(rlKey, { type: "json" })) || { hits: [] };
    rl.hits = rl.hits.filter((t) => now - t < RATE_WINDOW_MS);
    if (rl.hits.length >= RATE_MAX)
      return json({ error: "Lots of posts from this network — try again in a few minutes." }, 429);
    rl.hits.push(now);
    await store.setJSON(rlKey, rl);

    entry.id = now.toString(36) + "-" + crypto.randomUUID().slice(0, 8);
    const deleteToken = crypto.randomUUID() + crypto.randomUUID();
    entry.tokenHash = await sha256(deleteToken);
    await store.setJSON("entry/" + entry.id, entry);
    return json({ entry: strip(entry), deleteToken }, 201, { "cache-control": "no-store" });
  }

  return json({ error: "Method not allowed" }, 405);
};

export const config = { path: "/api/takeaways" };
