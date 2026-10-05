// Jetty Ambassador Store: static site + order relay into ApparelMagic.
// No dependencies; needs Node 18+.
//
// Railway Variables:
//   AM_TOKEN           ApparelMagic API token (Settings > API > Tokens). Required to send orders.
//   AM_SUBDOMAIN       defaults to "jetty"  ->  https://jetty.app.apparelmagic.com/api/json/
//   AM_WAREHOUSE_NAME  defaults to "Distribution Center"
//   AM_WAREHOUSE_ID    optional; skips the warehouse lookup
//   AM_DRY_RUN         "1" = do every lookup but do NOT create the order; returns what would be sent
//   ADMIN_KEY          optional; required as ?key= for /api/health?check=1

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const AM_TOKEN = process.env.AM_TOKEN || "";
const AM_BASE = process.env.AM_BASE_URL || `https://${process.env.AM_SUBDOMAIN || "jetty"}.app.apparelmagic.com/api/json/`;
const WAREHOUSE_NAME = process.env.AM_WAREHOUSE_NAME || "Distribution Center";
const DRY_RUN = process.env.AM_DRY_RUN === "1";
const DIVISION_NAME = process.env.AM_DIVISION_NAME || "MARKETING / PROMO";
const SOURCE_FIELD = process.env.AM_SOURCE_FIELD || "source";   // order header field that holds Source
const SOURCE_VALUE = process.env.AM_SOURCE_VALUE || "B2B";
const DEFAULT_STATE = "NJ";
const STATES = {AL:"ALABAMA",AK:"ALASKA",AZ:"ARIZONA",AR:"ARKANSAS",CA:"CALIFORNIA",CO:"COLORADO",CT:"CONNECTICUT",DE:"DELAWARE",DC:"DISTRICT OF COLUMBIA",FL:"FLORIDA",GA:"GEORGIA",HI:"HAWAII",ID:"IDAHO",IL:"ILLINOIS",IN:"INDIANA",IA:"IOWA",KS:"KANSAS",KY:"KENTUCKY",LA:"LOUISIANA",ME:"MAINE",MD:"MARYLAND",MA:"MASSACHUSETTS",MI:"MICHIGAN",MN:"MINNESOTA",MS:"MISSISSIPPI",MO:"MISSOURI",MT:"MONTANA",NE:"NEBRASKA",NV:"NEVADA",NH:"NEW HAMPSHIRE",NJ:"NEW JERSEY",NM:"NEW MEXICO",NY:"NEW YORK",NC:"NORTH CAROLINA",ND:"NORTH DAKOTA",OH:"OHIO",OK:"OKLAHOMA",OR:"OREGON",PA:"PENNSYLVANIA",RI:"RHODE ISLAND",SC:"SOUTH CAROLINA",SD:"SOUTH DAKOTA",TN:"TENNESSEE",TX:"TEXAS",UT:"UTAH",VT:"VERMONT",VA:"VIRGINIA",WA:"WASHINGTON",WV:"WEST VIRGINIA",WI:"WISCONSIN",WY:"WYOMING",PR:"PUERTO RICO"};
function stateCode(v) {
  const t = String(v || "").trim().toUpperCase().replace(/\./g, "");
  if (STATES[t]) return t;
  const hit = Object.entries(STATES).find(([, n]) => n === t);
  return hit ? hit[0] : DEFAULT_STATE;
}
const UA = "JettyAmbassadorStore/1.0 (+https://jettyambassador.up.railway.app)";

// Per-season order settings. Update season.json each new season.
const SEASON = JSON.parse(fs.readFileSync(path.join(ROOT, "season.json"), "utf8")); // {season, startDate: "MM/DD/YYYY"}
const CATALOG = JSON.parse(fs.readFileSync(path.join(ROOT, "catalog.json"), "utf8")); // upc -> {s,size,p,d,c,a}

const PICKUP = {
  "pickup-dc":   { label: "Pickup - Jetty Distribution",   addr: "700 S Main St, West Creek, NJ 08092" },
  "pickup-flag": { label: "Pickup - Jetty Flagship Store", addr: "176 E Bay Ave 1st Floor, Manahawkin, NJ 08050" },
};

/* ---------- ambassador file: same scheme as the page (PBKDF2 -> AES-256-GCM) ---------- */
function fileIdFor(code) {
  return crypto.createHash("sha256").update("jetty-amb:" + code).digest("hex").slice(0, 20);
}
function unlock(code) {
  if (!/^[A-Z0-9]{8,32}$/.test(code)) throw new Error("bad_code");
  const blob = JSON.parse(fs.readFileSync(path.join(ROOT, "a", fileIdFor(code) + ".json"), "utf8"));
  const key = crypto.pbkdf2Sync(code, Buffer.from(blob.s, "base64"), blob.k, 32, "sha256");
  const raw = Buffer.from(blob.c, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(blob.i, "base64"));
  d.setAuthTag(raw.subarray(raw.length - 16));
  return JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString("utf8"));
}

/* ---------- ApparelMagic API ---------- */
const auth = () => ({ time: String(Math.floor(Date.now() / 1000)), token: AM_TOKEN });
function qs(obj, prefix) {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v !== null && typeof v === "object") out.push(qs(v, key));
    else out.push(encodeURIComponent(key) + "=" + encodeURIComponent(v));
  }
  return out.filter(Boolean).join("&");
}
async function amGet(endpoint, params = [], extra = {}) {
  const body = { ...auth(), ...extra };
  if (params.length) body.parameters = params;
  const r = await fetch(AM_BASE + endpoint + "?" + qs(body), { headers: { "User-Agent": UA, Accept: "application/json" } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || (j.meta && j.meta.errors && j.meta.errors.length)) throw new Error(`AM GET ${endpoint} failed (${r.status}): ${JSON.stringify(j.meta?.errors || j).slice(0, 300)}`);
  return j.response || [];
}
async function amPost(endpoint, payload) {
  const r = await fetch(AM_BASE + endpoint, {
    method: "POST",
    headers: { "User-Agent": UA, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ ...auth(), ...payload }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || (j.meta && j.meta.errors && j.meta.errors.length)) throw new Error(`AM POST ${endpoint} failed (${r.status}): ${JSON.stringify(j.meta?.errors || j).slice(0, 500)}`);
  return j.response || [];
}

const cache = { divisionId: process.env.AM_DIVISION_ID || "", warehouseId: process.env.AM_WAREHOUSE_ID || "", customers: new Map(), skus: new Map() };
async function warehouseId() {
  if (cache.warehouseId) return cache.warehouseId;
  const rows = await amGet("warehouses/");
  const w = rows.find(r => String(r.name || r.warehouse_name || "").trim().toLowerCase() === WAREHOUSE_NAME.toLowerCase());
  if (!w) throw new Error(`Warehouse "${WAREHOUSE_NAME}" not found in AM`);
  return (cache.warehouseId = String(w.warehouse_id || w.id));
}
async function divisionId() {
  if (cache.divisionId) return cache.divisionId;
  const norm = x => String(x || "").replace(/\s+/g, " ").trim().toLowerCase();
  const rows = await amGet("divisions/");
  const d = rows.find(r => [r.name, r.division_name, r.description, r.code].some(v => norm(v) === norm(DIVISION_NAME)));
  if (!d) throw new Error(`Division "${DIVISION_NAME}" not found in AM`);
  return (cache.divisionId = String(d.division_id || d.id));
}
async function customerId(name) {
  if (cache.customers.has(name)) return cache.customers.get(name);
  const rows = await amGet("customers/", [{ field: "customer_name", operator: "=", value: name }]);
  const exact = rows.filter(r => String(r.customer_name || "").trim() === name.trim());
  if (exact.length !== 1) throw new Error(`AM customer "${name}": ${exact.length ? "more than one match" : "not found"}`);
  const id = String(exact[0].customer_id);
  cache.customers.set(name, id);
  return id;
}
async function skuIds(upcs) {
  const need = upcs.filter(u => !cache.skus.has(u));
  for (let i = 0; i < need.length; i += 50) {
    const chunk = need.slice(i, i + 50);
    const rows = await amGet("inventory/", chunk.map(u => ({ field: "upc_display", operator: "=", value: u, include_type: "OR" })));
    for (const r of rows) if (r.upc_display) cache.skus.set(String(r.upc_display), String(r.sku_id));
  }
  const missing = upcs.filter(u => !cache.skus.has(u));
  if (missing.length) throw new Error(`UPC not found in AM: ${missing.join(", ")}`);
  return Object.fromEntries(upcs.map(u => [u, cache.skus.get(u)]));
}

/* ---------- season-to-date spend (read back from AM, so edits/cancels in AM count) ---------- */
// An ambassador's season orders = their AM customer + their season PO (e.g. "Werner AMB, SUM27").
// A new season gets a new PO code, so the total starts at $0 automatically.
const recent = new Map();     // po -> [{amOrderId, retail, units, at}] created since this server started (covers AM lag)
const spentCache = new Map(); // po -> {at, data}
function orderRetail(o) {
  if (String(o.credit_status || "").toLowerCase() === "cancelled") return { retail: 0, units: 0 };
  const items = Array.isArray(o.order_items) ? o.order_items : [];
  if (!items.length) return { retail: Number(o.amount_subtotal || 0), units: Number(o.qty || 0) - Number(o.qty_cxl || 0) };
  let retail = 0, units = 0;
  for (const it of items) { const q = Number(it.qty || 0) - Number(it.qty_cxl || 0); units += q; retail += q * Number(it.unit_price || 0); }
  return { retail, units };
}
async function seasonSpend(me, fresh = false) {
  const hit = spentCache.get(me.po);
  if (!fresh && hit && Date.now() - hit.at < 60000) return hit.data;
  const cid = await customerId(me.amc);
  const rows = await amGet("orders/", [
    { field: "customer_id", operator: "=", value: cid, include_type: "AND" },
    { field: "customer_po", operator: "=", value: me.po, include_type: "AND" },
  ], { pagination: { page_size: 1000 } });
  const orders = rows.filter(o => String(o.customer_id) === cid && String(o.customer_po || "").trim() === me.po)
    .map(o => ({ amOrderId: String(o.order_id), date: o.date || "", ...orderRetail(o) }))
    .filter(o => o.units > 0);
  for (const r of recent.get(me.po) || []) if (!orders.some(o => o.amOrderId === String(r.amOrderId))) orders.push(r);
  const data = { spent: Math.round(orders.reduce((t, o) => t + o.retail, 0) * 100) / 100, orders };
  spentCache.set(me.po, { at: Date.now(), data });
  return data;
}

/* ---------- profile: every season's ambassador orders for this customer ---------- */
const SEASON_NAMES = { SPR: "Spring", SUM: "Summer", FAL: "Fall", HOL: "Holiday" };
function seasonOfPo(po) {
  const m = String(po || "").match(/\bAMB,\s*([A-Z]{3})(\d{2})\b(.*)$/i);
  if (!m) return null;
  const code = m[1].toUpperCase() + m[2];
  return { code, label: `${SEASON_NAMES[m[1].toUpperCase()] || m[1].toUpperCase()} 20${m[2]}`, test: /TEST/i.test(m[3] || ""),
           sort: Number(m[2]) * 10 + ({ SPR: 1, SUM: 2, FAL: 3, HOL: 4 }[m[1].toUpperCase()] || 0) };
}
const histCache = new Map();
async function allOrders(cid) {
  const out = []; let last = null;
  for (let page = 0; page < 20; page++) {
    const pag = { page_size: 1000 }; if (last) pag.last_id = String(last);
    const r = await fetch(AM_BASE + "orders/?" + qs({ ...auth(), parameters: [{ field: "customer_id", operator: "=", value: cid }], pagination: pag }),
      { headers: { "User-Agent": UA, Accept: "application/json" } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`AM GET orders failed (${r.status})`);
    out.push(...(j.response || []));
    last = j.meta?.pagination?.last_id;
    if (!last) break;
  }
  return out.filter(o => String(o.customer_id) === cid);
}
async function history(me) {
  const hit = histCache.get(me.po);
  if (hit && Date.now() - hit.at < 60000) return hit.data;
  const cur = seasonOfPo(me.po);
  const rows = await allOrders(await customerId(me.amc));
  const seasons = new Map();
  for (const o of rows) {
    const s = seasonOfPo(o.customer_po); if (!s) continue;
    if (s.test !== !!me.t) continue;                       // test link sees test orders only, ambassadors never see tests
    const cancelled = String(o.credit_status || "").toLowerCase() === "cancelled";
    const items = (o.order_items || []).map(it => {
      const qty = cancelled ? 0 : Number(it.qty || 0) - Number(it.qty_cxl || 0);
      return { style: it.style_number || "", desc: it.description || "", color: it.attr_2 || "", size: it.size || "", qty, retail: Number(it.unit_price || 0) };
    }).filter(it => it.qty > 0);
    if (!items.length) continue;
    if (!seasons.has(s.code)) seasons.set(s.code, { ...s, allowance: s.code === cur?.code ? Number(me.a) : (me.pa || {})[s.code] ?? null, orders: [] });
    seasons.get(s.code).orders.push({ amOrderId: String(o.order_id), date: o.date || "", items,
      units: items.reduce((t, i) => t + i.qty, 0), retail: items.reduce((t, i) => t + i.qty * i.retail, 0) });
  }
  if (cur && !seasons.has(cur.code)) seasons.set(cur.code, { ...cur, allowance: Number(me.a), orders: [] });
  const list = [...seasons.values()].map(s => ({ code: s.code, label: s.label, current: s.code === cur?.code, allowance: s.allowance,
    spent: Math.round(s.orders.reduce((t, o) => t + o.retail, 0) * 100) / 100, units: s.orders.reduce((t, o) => t + o.units, 0),
    orders: s.orders.sort((a, b) => Number(b.amOrderId) - Number(a.amOrderId)), sort: s.sort })).sort((a, b) => b.sort - a.sort);
  const data = { name: me.n, seasons: list };
  histCache.set(me.po, { at: Date.now(), data });
  return data;
}

/* ---------- order ---------- */
const seen = new Map(); // orderId -> result (stops double submits)
async function handleOrder(input) {
  const me = unlock(String(input.code || "").toUpperCase());
  if (!me.amc) throw Object.assign(new Error("This ambassador has no AM customer set up yet."), { status: 409 });
  const orderId = String(input.orderId || "").slice(0, 40);
  if (orderId && seen.has(orderId)) return seen.get(orderId);

  const lines = (input.lines || []).map(l => ({ upc: String(l.upc), qty: parseInt(l.qty, 10) }))
    .filter(l => CATALOG[l.upc] && l.qty > 0 && l.qty <= 99);
  if (!lines.length) throw Object.assign(new Error("Cart is empty."), { status: 400 });

  const method = String(input.method || "");
  const s = input.shipTo || {};
  const notes = String(input.notes || "").slice(0, 1000);
  const header = {
    customer_id: await customerId(me.amc),
    customer_po: me.po,
    warehouse_id: await warehouseId(),
    division_id: await divisionId(),
    [SOURCE_FIELD]: SOURCE_VALUE,
    pct_discount: "100",
    state: DEFAULT_STATE,
    date_start: process.env.AM_START_DATE || SEASON.startDate,
  };
  let fulfil;
  if (PICKUP[method]) {
    fulfil = `${PICKUP[method].label} (${PICKUP[method].addr})`;
    header.shipping_info = PICKUP[method].label;
  } else if (method === "delivery") {
    for (const k of ["name", "line1", "city", "zip"]) if (!String(s[k] || "").trim()) throw Object.assign(new Error("Delivery address is incomplete."), { status: 400 });
    Object.assign(header, {
      name: String(s.name).slice(0, 100), address_1: String(s.line1).slice(0, 100), address_2: String(s.line2 || "").slice(0, 100),
      city: String(s.city).slice(0, 60), state: stateCode(s.state), postal_code: String(s.zip).slice(0, 12),
      country: "USA", phone: String(s.phone || "").slice(0, 30), shipping_info: "Delivery",
    });
    fulfil = "Delivery";
  } else throw Object.assign(new Error("Choose pickup or delivery."), { status: 400 });

  const retail = lines.reduce((t, l) => t + l.qty * CATALOG[l.upc].p, 0);
  let before = null;
  try { before = (await seasonSpend(me, true)).spent; } catch (e) { console.error(JSON.stringify({ event: "spend_lookup_failed", error: e.message })); }
  const total = (before || 0) + retail;
  header.notes = [`Ambassador store order ${orderId} – ${me.n}${me.t ? " (TEST)" : ""}`, fulfil,
    `This order: $${retail.toFixed(2)} retail` + (before !== null ? `. Season total: $${total.toFixed(2)} of $${Number(me.a).toFixed(2)} allowance${total > me.a ? ` (OVER by $${(total - me.a).toFixed(2)})` : ""}` : ` (allowance $${Number(me.a).toFixed(2)})`),
    notes ? `Ambassador notes: ${notes}` : ""].filter(Boolean).join("\n");

  const ids = await skuIds(lines.map(l => l.upc));
  const items = lines.map(l => ({ sku_id: ids[l.upc], qty: String(l.qty), unit_price: CATALOG[l.upc].p.toFixed(2), warehouse_id: header.warehouse_id }));
  const payload = { header, items };

  console.log(JSON.stringify({ event: "order", dryRun: DRY_RUN, orderId, ambassador: me.n, customer: me.amc, po: me.po, units: lines.reduce((t, l) => t + l.qty, 0), retail, payload }));
  if (DRY_RUN) return { ok: true, dryRun: true, orderId, wouldSend: payload };

  const res = await amPost("orders/", payload);
  const amOrderId = (Array.isArray(res) ? res[0] : res)?.order_id || null;
  const units = lines.reduce((t, l) => t + l.qty, 0);
  if (!recent.has(me.po)) recent.set(me.po, []);
  recent.get(me.po).push({ amOrderId: String(amOrderId || orderId), date: new Date().toLocaleDateString("en-US"), retail, units });
  spentCache.delete(me.po); histCache.delete(me.po);
  const out = { ok: true, orderId, amOrderId, spent: Math.round(total * 100) / 100 };
  if (orderId) seen.set(orderId, out);
  console.log(JSON.stringify({ event: "order_created", orderId, amOrderId }));
  return out;
}

/* ---------- http ---------- */
const TYPES = { ".html": "text/html; charset=utf-8", ".json": "application/json", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".txt": "text/plain", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml" };
const PUBLIC = /^\/(index\.html|robots\.txt|a\/[0-9a-f]{20}\.json|(img|brand)\/[^/]+\.(jpg|jpeg|png|webp))?$/i;
function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store", "X-Robots-Tag": "noindex" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (req.method === "POST" && url.pathname === "/api/order") {
      if (!AM_TOKEN && !DRY_RUN) return send(res, 503, { ok: false, error: "Online ordering isn't switched on yet." });
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 100000) return send(res, 413, { ok: false }); }
      try { return send(res, 200, await handleOrder(JSON.parse(raw))); }
      catch (e) {
        console.error(JSON.stringify({ event: "order_error", error: e.message }));
        return send(res, e.status || (e.message === "bad_code" || e.code === "ENOENT" ? 403 : 502), { ok: false, error: e.status ? e.message : "We couldn't send your order to our system." });
      }
    }
    if (req.method === "POST" && url.pathname === "/api/spent") {
      if (!AM_TOKEN) return send(res, 503, { ok: false });
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      try {
        const me = unlock(String(JSON.parse(raw).code || "").toUpperCase());
        if (!me.amc) return send(res, 200, { ok: true, spent: 0, orders: [] });
        return send(res, 200, { ok: true, ...(await seasonSpend(me)) });
      } catch (e) {
        console.error(JSON.stringify({ event: "spent_error", error: e.message }));
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 502, { ok: false });
      }
    }
    if (req.method === "POST" && url.pathname === "/api/history") {
      if (!AM_TOKEN) return send(res, 503, { ok: false });
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      try {
        const me = unlock(String(JSON.parse(raw).code || "").toUpperCase());
        if (!me.amc) return send(res, 200, { ok: true, name: me.n, seasons: [] });
        return send(res, 200, { ok: true, ...(await history(me)) });
      } catch (e) {
        console.error(JSON.stringify({ event: "history_error", error: e.message }));
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 502, { ok: false });
      }
    }
    if (url.pathname === "/api/health") {
      const out = { ok: true, tokenSet: !!AM_TOKEN, dryRun: DRY_RUN, subdomain: AM_BASE.split("//")[1].split(".")[0] };
      if (url.searchParams.get("check") === "1" && process.env.ADMIN_KEY && url.searchParams.get("key") === process.env.ADMIN_KEY) {
        try { out.warehouseId = await warehouseId(); out.divisionId = await divisionId(); out.amReachable = true; } catch (e) { out.amReachable = false; out.amError = e.message; }
      }
      return send(res, 200, out);
    }
    if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, { ok: false });
    const p = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
    if (!PUBLIC.test(p)) return send(res, 404, "Not found", "text/plain");
    const file = path.join(ROOT, p);
    fs.readFile(file, (err, buf) => err ? send(res, 404, "Not found", "text/plain")
      : send(res, 200, buf, TYPES[path.extname(file).toLowerCase()] || "application/octet-stream"));
  } catch (e) { console.error(e); send(res, 500, { ok: false }); }
}).listen(PORT, () => console.log(`Ambassador store on :${PORT} (AM token ${AM_TOKEN ? "set" : "missing"}${DRY_RUN ? ", DRY RUN" : ""})`));
