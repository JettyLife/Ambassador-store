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
const BUILD = "2026-10-06 volume check";
// Site password (Railway variable SITE_PASSWORD). Unset = no password. Changing it signs everyone out.
const SITE_PASSWORD = process.env.SITE_PASSWORD || "";
const AUTH_KEY = crypto.createHash("sha256").update("jas-auth:" + SITE_PASSWORD).digest();
const AUTH_DAYS = 90;
function authCookie() {
  const exp = String(Date.now() + AUTH_DAYS * 864e5);
  return exp + "." + crypto.createHmac("sha256", AUTH_KEY).update(exp).digest("hex");
}
function isAuthed(req) {
  if (!SITE_PASSWORD) return true;
  const m = String(req.headers.cookie || "").match(/(?:^|;\s*)jas_auth=([0-9]+)\.([0-9a-f]{64})/);
  if (!m || Number(m[1]) < Date.now()) return false;
  const want = crypto.createHmac("sha256", AUTH_KEY).update(m[1]).digest();
  const got = Buffer.from(m[2], "hex");
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
const tries = new Map(); // ip -> [timestamps]
function tooMany(ip) {
  const now = Date.now(), t = (tries.get(ip) || []).filter(x => now - x < 60000);
  t.push(now); tries.set(ip, t);
  return t.length > 10;
}
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

async function amPut(endpoint, payload) {
  const r = await fetch(AM_BASE + endpoint, {
    method: "PUT",
    headers: { "User-Agent": UA, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ ...auth(), ...payload }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || (j.meta && j.meta.errors && j.meta.errors.length)) throw new Error(`AM PUT ${endpoint} failed (${r.status}): ${JSON.stringify(j.meta?.errors || j).slice(0, 300)}`);
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
const spentCache = new Map(); // customer|po -> {at, data}
// Two ambassadors can share a PO (e.g. "Woodin AMB, SUM27" for Bree and Kurtis), so everything is keyed by AM customer AND PO.
const ambKey = me => `${String(me.amc || "").trim().toLowerCase()}|${String(me.po || "").trim().toLowerCase()}`;
const poOwner = po => String(po || "").split(/\s+AMB\b/i)[0].trim().toLowerCase();
function orderRetail(o) {
  if (String(o.credit_status || "").toLowerCase() === "cancelled") return { retail: 0, units: 0 };
  const items = Array.isArray(o.order_items) ? o.order_items : [];
  if (!items.length) return { retail: Number(o.amount_subtotal || 0), units: Number(o.qty || 0) - Number(o.qty_cxl || 0) };
  let retail = 0, units = 0;
  for (const it of items) { const q = Number(it.qty || 0) - Number(it.qty_cxl || 0); units += q; retail += q * Number(it.unit_price || 0); }
  return { retail, units };
}
async function seasonSpend(me, fresh = false) {
  const hit = spentCache.get(ambKey(me));
  if (!fresh && hit && Date.now() - hit.at < 60000) return hit.data;
  const cid = await customerId(me.amc);
  const rows = await amGet("orders/", [
    { field: "customer_id", operator: "=", value: cid, include_type: "AND" },
    { field: "customer_po", operator: "=", value: me.po, include_type: "AND" },
  ], { pagination: { page_size: 1000 } });
  const orders = rows.filter(o => String(o.customer_id) === cid && String(o.customer_po || "").trim() === me.po)
    .map(o => ({ amOrderId: String(o.order_id), date: o.date || "", ...orderRetail(o) }))
    .filter(o => o.units > 0);
  for (const r of recent.get(ambKey(me)) || []) if (!orders.some(o => o.amOrderId === String(r.amOrderId))) orders.push(r);
  const data = { spent: Math.round(orders.reduce((t, o) => t + o.retail, 0) * 100) / 100, orders };
  spentCache.set(ambKey(me), { at: Date.now(), data });
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

/* ---------- product photos for past-season styles (not in this season's catalog) ---------- */
const CATALOG_IMG = (() => { try {
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  const data = JSON.parse(html.match(/const PRODUCTS = (\[.*?\]);\n/s)[1]);
  return new Set(data.map(p => p.s));
} catch (e) { return new Set(); } })();
const imgCache = new Map(); // style -> {at, url}
function findImageUrl(obj) {
  if (!obj) return "";
  if (typeof obj === "string") return /^https?:\/\/\S+\.(jpe?g|png|webp)(\?\S*)?$/i.test(obj.trim()) ? obj.trim() : "";
  if (Array.isArray(obj)) { for (const v of obj) { const u = findImageUrl(v); if (u) return u; } return ""; }
  if (typeof obj === "object") {
    // prefer fields that look like the main picture
    for (const k of Object.keys(obj).sort((a, b) => (/pic|image|photo/i.test(b) ? 1 : 0) - (/pic|image|photo/i.test(a) ? 1 : 0))) {
      const u = findImageUrl(obj[k]); if (u) return u;
    }
  }
  return "";
}
async function productImages(styles) {
  const need = [...new Set(styles)].filter(s => s && !CATALOG_IMG.has(s) && !(imgCache.has(s) && Date.now() - imgCache.get(s).at < 864e5));
  for (let i = 0; i < need.length; i += 40) {
    const chunk = need.slice(i, i + 40);
    let rows = [];
    try { rows = await amGet("products/", chunk.map(st => ({ field: "style_number", operator: "=", value: st, include_type: "OR" })), { pagination: { page_size: 1000 } }); }
    catch (e) { console.error(JSON.stringify({ event: "product_images_failed", error: e.message })); }
    for (const st of chunk) {
      const r = rows.find(x => String(x.style_number || "").trim() === st);
      imgCache.set(st, { at: Date.now(), url: r ? findImageUrl(r) : "" });
    }
  }
  return Object.fromEntries([...new Set(styles)].map(s => [s, (imgCache.get(s) || {}).url || ""]));
}

/* ---------- staff: every ambassador's orders grouped by season ---------- */
async function customerIdsFor(names) {
  const need = [...new Set(names.filter(n => n && !cache.customers.has(n)))];
  for (let i = 0; i < need.length; i += 40) {
    const chunk = need.slice(i, i + 40);
    const rows = await amGet("customers/", chunk.map(n => ({ field: "customer_name", operator: "=", value: n, include_type: "OR" })), { pagination: { page_size: 1000 } });
    for (const n of chunk) {
      const hits = rows.filter(r => String(r.customer_name || "").trim() === n.trim());
      if (hits.length === 1) cache.customers.set(n, String(hits[0].customer_id));
    }
  }
  return Object.fromEntries(names.map(n => [n, cache.customers.get(n) || null]));
}
async function ordersForCustomers(ids) {
  const out = [];
  for (let i = 0; i < ids.length; i += 30) {
    const chunk = ids.slice(i, i + 30); let last = null;
    for (let page = 0; page < 20; page++) {
      const pag = { page_size: 1000 }; if (last) pag.last_id = String(last);
      const r = await fetch(AM_BASE + "orders/?" + qs({ ...auth(), parameters: chunk.map(id => ({ field: "customer_id", operator: "=", value: id, include_type: "OR" })), pagination: pag }),
        { headers: { "User-Agent": UA, Accept: "application/json" } });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(`AM GET orders failed (${r.status})`);
      out.push(...(j.response || []));
      last = j.meta?.pagination?.last_id; if (!last) break;
    }
  }
  const want = new Set(ids), seenIds = new Set();
  return out.filter(o => want.has(String(o.customer_id)) && !seenIds.has(String(o.order_id)) && seenIds.add(String(o.order_id)));
}
let seasonsCache = null;
async function seasonOverview(roster, fresh) {
  if (!fresh && seasonsCache && Date.now() - seasonsCache.at < 120000) return seasonsCache.data;
  const ids = await customerIdsFor(roster.map(r => r.amc).filter(Boolean));
  const byCust = new Map(); for (const r of roster) if (ids[r.amc]) byCust.set(ids[r.amc], [...(byCust.get(ids[r.amc]) || []), r]);
  const orders = await ordersForCustomers([...byCust.keys()]);
  const cur = seasonOfPo(roster[0]?.po);
  const seasons = new Map();
  for (const o of orders) {
    const s = seasonOfPo(o.customer_po); if (!s || s.test) continue;
    const cands = byCust.get(String(o.customer_id)) || [];
    const last = String(o.customer_po).split(" AMB")[0].trim().toLowerCase();
    const amb = cands.length === 1 ? cands[0] : cands.find(c => c.po.toLowerCase().startsWith(last + " amb")) || cands[0];
    if (!amb) continue;
    const { retail, units } = orderRetail(o);
    if (units <= 0) continue;
    if (!seasons.has(s.code)) seasons.set(s.code, { code: s.code, label: s.label, sort: s.sort, people: new Map() });
    const ppl = seasons.get(s.code).people;
    if (!ppl.has(amb.id)) ppl.set(amb.id, { id: amb.id, n: amb.n, allowance: s.code === cur?.code ? amb.a : (amb.pa || {})[s.code] ?? null, orders: 0, units: 0, retail: 0, pending: 0, last: "", items: {} });
    const p = ppl.get(amb.id);
    if (String(o.credit_status || "").toLowerCase() !== "cancelled") for (const it of (o.order_items || [])) {
      const q = Number(it.qty || 0) - Number(it.qty_cxl || 0); if (q <= 0) continue;
      const st = String(it.style_number || ""), k = st + "|" + String(it.size || "");
      if (!p.items[k]) p.items[k] = { s: st, d: String(it.description || ""), c: String(it.attr_2 || ""), z: String(it.size || ""), q: 0 };
      p.items[k].q += q;
    }
    p.orders++; p.units += units; p.retail += retail;
    if (String(o.credit_status || "").toLowerCase() === "pending") p.pending++;
    if (String(o.date || "") > p.last) p.last = String(o.date || "");
  }
  if (cur && !seasons.has(cur.code)) seasons.set(cur.code, { code: cur.code, label: cur.label, sort: cur.sort, people: new Map() });
  const data = [...seasons.values()].sort((a, b) => b.sort - a.sort).map(s => {
    const people = [...s.people.values()].map(p => ({ ...p, items: Object.values(p.items), retail: Math.round(p.retail * 100) / 100 })).sort((a, b) => a.n.localeCompare(b.n));
    const orderedIds = new Set(people.map(p => p.id));
    return { code: s.code, label: s.label, current: s.code === cur?.code, people,
      notOrdered: roster.filter(r => !orderedIds.has(r.id)).map(r => ({ id: r.id, n: r.n, allowance: s.code === cur?.code ? r.a : (r.pa || {})[s.code] ?? null })),
      totals: { ambassadors: people.length, orders: people.reduce((t, p) => t + p.orders, 0), units: people.reduce((t, p) => t + p.units, 0),
                retail: Math.round(people.reduce((t, p) => t + p.retail, 0) * 100) / 100, pending: people.reduce((t, p) => t + p.pending, 0) } };
  });
  seasonsCache = { at: Date.now(), data };
  return data;
}

/* ---------- shipping / tracking ---------- */
// Finds tracking numbers on an order's shipments. Field names are matched loosely (anything containing "tracking")
// so it works whether AM stores them on the shipment or on its boxes/packages.
function carrierFor(num, hint) {
  const n = String(num).replace(/\s+/g, ""), h = String(hint || "").toLowerCase();
  if (/^1Z[0-9A-Z]{16}$/i.test(n) || h.includes("ups")) return { carrier: "UPS", url: `https://www.ups.com/track?tracknum=${encodeURIComponent(n)}` };
  if (h.includes("fedex") || /^\d{12}$|^\d{15}$/.test(n)) return { carrier: "FedEx", url: `https://www.fedex.com/fedextrack/?trknbr=${encodeURIComponent(n)}` };
  if (h.includes("usps") || /^(9[1-5]\d{18,24}|[A-Z]{2}\d{9}US)$/i.test(n)) return { carrier: "USPS", url: `https://tools.usps.com/go/TrackConfirmAction?tLabels=${encodeURIComponent(n)}` };
  if (h.includes("dhl")) return { carrier: "DHL", url: `https://www.dhl.com/us-en/home/tracking.html?tracking-id=${encodeURIComponent(n)}` };
  return { carrier: hint ? String(hint) : "", url: `https://www.google.com/search?q=${encodeURIComponent(n + " tracking")}` };
}
function findTracking(obj, hint, out = []) {
  if (Array.isArray(obj)) { obj.forEach(o => findTracking(o, hint, out)); return out; }
  if (!obj || typeof obj !== "object") return out;
  const localHint = obj.ship_via || obj.carrier || obj.shipping_method || obj.service || hint || "";
  for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === "object") findTracking(v, localHint, out);
    else if (/track/i.test(k) && !/url|link|status|date/i.test(k) && v && String(v).trim().length >= 8) {
      for (const num of String(v).split(/[\s,;]+/).filter(x => x.length >= 8)) out.push({ number: num, ...carrierFor(num, localHint) });
    }
  }
  return out;
}
const shipCache = new Map(); // order_id -> {at, data}
async function shipmentsFor(orderIds, fresh = false) {
  // Re-check every 2 minutes until a tracking number shows up, then every 5 minutes (so an edited number updates quickly).
  const need = orderIds.filter(id => { const c = shipCache.get(id); return fresh || !c || Date.now() - c.at > (c.data.tracking.length || c.data.invoiced ? 5 : 2) * 60000; });
  for (let i = 0; i < need.length; i += 25) {
    const chunk = need.slice(i, i + 25);
    let rows = [];
    try { rows = await amGet("shipments/", chunk.map(id => ({ field: "order_id", operator: "=", value: id, include_type: "OR" })), { pagination: { page_size: 1000 } }); }
    catch (e) { console.error(JSON.stringify({ event: "shipments_lookup_failed", error: e.message })); }
    // Invoices can carry the tracking number too (AM creates one when an order ships).
    try { rows = rows.concat((await amGet("invoices/", chunk.map(id => ({ field: "order_id", operator: "=", value: id, include_type: "OR" })), { pagination: { page_size: 1000 } })).map(r => ({ ...r, _invoice: true }))); }
    catch (e) { console.error(JSON.stringify({ event: "invoices_lookup_failed", error: e.message })); }
    const by = new Map(chunk.map(id => [id, []]));
    for (const r of rows) {
      const ids = new Set([r.order_id, ...(Array.isArray(r.shipment_items) ? r.shipment_items.map(x => x.order_id) : []), ...(Array.isArray(r.invoice_items) ? r.invoice_items.map(x => x.order_id) : [])].filter(Boolean).map(String));
      for (const id of ids) if (by.has(id)) by.get(id).push(r);
    }
    for (const [id, list] of by) {
      const seen = new Set(), tracking = findTracking(list).filter(t => !seen.has(t.number) && seen.add(t.number));
      const inv = list.find(r => r._invoice);
      shipCache.set(id, { at: Date.now(), data: { tracking, invoiced: !!inv, invoiceDate: inv ? (inv.date || "") : "", shipDate: (list.find(r => r.date || r.ship_date) || {}).date || (list[0] || {}).ship_date || "" } });
    }
  }
  return Object.fromEntries(orderIds.map(id => [id, (shipCache.get(id) || {}).data || { tracking: [] }]));
}
/* Live tracking (optional): Railway variable EASYPOST_API_KEY. Each tracking number becomes an EasyPost tracker
   (EasyPost dedupes the same number for 3 months), refreshed at most every 30 minutes. */
const EASYPOST = process.env.EASYPOST_API_KEY || "";
const liveCache = new Map(); // number -> {at, data}
const EP_CARRIER = { UPS: "UPS", FedEx: "FedEx", USPS: "USPS", DHL: "DHLExpress" };
async function liveTracking(t) {
  if (!EASYPOST || !t || !t.number) return null;
  const hit = liveCache.get(t.number);
  if (hit && Date.now() - hit.at < (hit.data && hit.data.status === "delivered" ? 864e5 : 30 * 60000)) return hit.data;
  try {
    const r = await fetch("https://api.easypost.com/v2/trackers", { method: "POST",
      headers: { Authorization: "Basic " + Buffer.from(EASYPOST + ":").toString("base64"), "Content-Type": "application/json" },
      body: JSON.stringify({ tracker: { tracking_code: t.number, ...(EP_CARRIER[t.carrier] ? { carrier: EP_CARRIER[t.carrier] } : {}) } }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`EasyPost ${r.status}: ${JSON.stringify(j.error || j).slice(0, 200)}`);
    const loc = l => l ? [l.city, l.state].filter(Boolean).map(x => String(x).replace(/\b\w+/g, w => w[0] + w.slice(1).toLowerCase())).join(", ") : "";
    const data = { status: j.status || "unknown", detail: j.status_detail || "", carrier: j.carrier || t.carrier || "", est: j.est_delivery_date || null,
      signedBy: j.signed_by || "", publicUrl: j.public_url || "", updated: j.updated_at || "",
      events: (j.tracking_details || []).slice().reverse().slice(0, 12).map(d => ({ at: d.datetime_local || d.datetime, msg: d.message || d.status, where: loc(d.tracking_location) })) };
    liveCache.set(t.number, { at: Date.now(), data });
    return data;
  } catch (e) { console.error(JSON.stringify({ event: "live_tracking_failed", number: t.number, error: e.message })); return hit ? hit.data : null; }
}

// Pickup orders: once AM marks them shipped they're "Ready for pickup"; the ambassador (or staff) confirms the pickup on the site.
const PICK_FILE = () => path.join(DATA_DIR, "pickups.json");
function readPickups() { try { return JSON.parse(fs.readFileSync(PICK_FILE(), "utf8")); } catch (e) { return {}; } }
function writePickups(m) { fs.mkdirSync(DATA_DIR, { recursive: true }); const t = PICK_FILE() + ".tmp"; fs.writeFileSync(t, JSON.stringify(m, null, 1)); fs.renameSync(t, PICK_FILE()); }
function shipStatus(o, pickups) {
  const qty = Number(o.qty || 0) - Number(o.qty_cxl || 0), shipped = Number(o.qty_shipped || 0);
  const pickup = /pickup/i.test(String(o.shipping_info || ""));
  if (pickup) {
    const p = (pickups || {})[String(o.order_id)];
    if (p) return { state: "shipped", label: "Picked up", pickup, pickedUpAt: p.at, pickedUpBy: p.by };
    if (shipped <= 0) return { state: "processing", label: "Getting your order ready", pickup };
    return { state: "ready", label: shipped < qty ? "Partly ready for pickup" : "Ready for pickup", pickup, canConfirm: true };
  }
  if (shipped <= 0) return { state: "processing", label: "Not shipped yet", pickup };
  if (shipped < qty) return { state: "partial", label: "Partly shipped", pickup };
  return { state: "shipped", label: "Shipped", pickup };
}
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
async function history(me, fresh = false) {
  const hit = histCache.get(ambKey(me));
  if (!fresh && hit && Date.now() - hit.at < 60000) return hit.data;
  const cur = seasonOfPo(me.po);
  const rows = await allOrders(await customerId(me.amc));
  const seasons = new Map(), pickups = readPickups();
  for (const o of rows) {
    const s = seasonOfPo(o.customer_po); if (!s) continue;
    if (s.test !== !!me.t) continue;                       // test link sees test orders only, ambassadors never see tests
    if (poOwner(o.customer_po) !== poOwner(me.po)) continue; // same customer AND this ambassador's PO name
    const cancelled = String(o.credit_status || "").toLowerCase() === "cancelled";
    const items = (o.order_items || []).map(it => {
      const qty = cancelled ? 0 : Number(it.qty || 0) - Number(it.qty_cxl || 0);
      return { style: it.style_number || "", desc: it.description || "", color: it.attr_2 || "", size: it.size || "", qty, retail: Number(it.unit_price || 0) };
    }).filter(it => it.qty > 0);
    if (!items.length) continue;
    if (!seasons.has(s.code)) seasons.set(s.code, { ...s, allowance: s.code === cur?.code ? Number(me.a) : (me.pa || {})[s.code] ?? null, orders: [] });
    const orderTrk = findTracking(Object.fromEntries(Object.entries(o).filter(([k]) => k !== "order_items")), o.ship_via || "");
    seasons.get(s.code).orders.push({ amOrderId: String(o.order_id), date: o.date || "", items, ship: shipStatus(o, pickups),
      method: String(o.shipping_info || ""), shipVia: String(o.ship_via || ""), tracking: orderTrk,
      units: items.reduce((t, i) => t + i.qty, 0), retail: items.reduce((t, i) => t + i.qty * i.retail, 0) });
  }
  if (cur && !seasons.has(cur.code)) seasons.set(cur.code, { ...cur, allowance: Number(me.a), orders: [] });
  const pastStyles = [...seasons.values()].flatMap(s => s.orders.flatMap(o => o.items.map(i => i.style))).filter(st => !CATALOG_IMG.has(st));
  if (pastStyles.length) {
    const imgs = await productImages(pastStyles);
    for (const s of seasons.values()) for (const o of s.orders) for (const it of o.items) if (imgs[it.style]) it.img = imgs[it.style];
  }
  const allOrds = [...seasons.values()].flatMap(s => s.orders);
  // Delivery orders: look up shipments/invoices for tracking. Pickup orders not yet picked up: look for the invoice,
  // since Wholesale invoicing the order is the signal that it's ready for pickup.
  const shippedIds = allOrds.filter(o => o.ship.pickup ? !o.ship.pickedUpAt && o.ship.state !== "ready" : (o.ship.state !== "processing" || o.tracking.length)).map(o => o.amOrderId);
  if (shippedIds.length) {
    const info = await shipmentsFor(shippedIds, fresh);
    for (const o of allOrds) if (o.ship.pickup && info[o.amOrderId] && info[o.amOrderId].invoiced && !o.ship.pickedUpAt)
      o.ship = { state: "ready", label: "Ready for pickup", pickup: true, canConfirm: true, readySince: info[o.amOrderId].invoiceDate };
    for (const o of allOrds) if (!o.ship.pickup && info[o.amOrderId]) {
      const seen = new Set(o.tracking.map(t => t.number));
      o.tracking = o.tracking.concat(info[o.amOrderId].tracking.filter(t => !seen.has(t.number) && seen.add(t.number)));
      o.shipDate = info[o.amOrderId].shipDate;
    }
  }
  if (EASYPOST) await Promise.all(allOrds.flatMap(o => o.tracking.slice(0, 5).map(async t => { t.live = await liveTracking(t); })));
  const list = [...seasons.values()].map(s => ({ code: s.code, label: s.label, current: s.code === cur?.code, allowance: s.allowance,
    spent: Math.round(s.orders.reduce((t, o) => t + o.retail, 0) * 100) / 100, units: s.orders.reduce((t, o) => t + o.units, 0),
    orders: s.orders.sort((a, b) => Number(b.amOrderId) - Number(a.amOrderId)), sort: s.sort })).sort((a, b) => b.sort - a.sort);
  const data = { name: me.n, seasons: list };
  histCache.set(ambKey(me), { at: Date.now(), data });
  return data;
}

/* ---------- internal notifications to Slack (Incoming Webhook) ----------
   Railway variables: SLACK_WEBHOOK_URL (from a Slack app's Incoming Webhooks, posts to one channel)
                      SLACK_NOTIFY (optional) which events, default "requests,uploads,pending"; add "orders" for every order */
const SLACK_URL = process.env.SLACK_WEBHOOK_URL || "";
const SLACK_ON = new Set((process.env.SLACK_NOTIFY || "requests,uploads,pending").split(",").map(x => x.trim().toLowerCase()).filter(Boolean));
const SITE = () => process.env.PUBLIC_URL || "https://jettyambassador.up.railway.app";
const slackEsc = v => String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
async function postSlack(text, blocks) {
  if (!SLACK_URL) return false;
  const r = await fetch(SLACK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, blocks }) });
  if (!r.ok) throw new Error(`Slack ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return true;
}
// Who gets @-mentioned per alert. Railway variable SLACK_MENTIONS overrides, e.g.
// "requests:U0C9M2Q15GC;uploads:U0C9M2Q15GC;pending:U0C9M2Q15GC,UM3REF944;orders:" (Slack member IDs; Jon = U0C9M2Q15GC, Arlynn = U0BPU0W4BCK, Jerm = U4UAC501F, Tyler = UM3REF944)
const SLACK_MENTIONS = (() => {
  const m = { requests: ["U0C9M2Q15GC", "U0BPU0W4BCK"], uploads: ["U0C9M2Q15GC", "U0BPU0W4BCK"], pending: ["U0C9M2Q15GC", "U0BPU0W4BCK", "U4UAC501F"], orders: [] };
  for (const part of String(process.env.SLACK_MENTIONS || "").split(";")) {
    const [k, v] = part.split(":"); if (!k || !(k.trim().toLowerCase() in m) || v === undefined) continue;
    m[k.trim().toLowerCase()] = v.split(",").map(x => x.trim()).filter(x => /^[UW][A-Z0-9]{6,}$/.test(x));
  }
  return m;
})();
function notify(kind, text, blocks, test) {
  if (!SLACK_URL || !SLACK_ON.has(kind)) return;
  // Test activity (Sandbox, Jetty Admin) doesn't ping anyone, unless Railway variable SLACK_TAG_TESTS = 1 (for checking the tags).
  const who = test && process.env.SLACK_TAG_TESTS !== "1" ? [] : (SLACK_MENTIONS[kind] || []);
  if (who.length) {
    const tag = who.map(id => `<@${id}>`).join(" ");
    text = `${tag} ${text}`;
    blocks = [{ type: "section", text: { type: "mrkdwn", text: tag } }, ...blocks];
  }
  postSlack(text, blocks).catch(e => console.error(JSON.stringify({ event: "slack_failed", kind, error: e.message })));
}
const sDate = d => d ? new Date(String(d).slice(0, 10) + "T12:00:00").toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" }) : "";
const fieldsBlock = rows => ({ type: "section", fields: rows.filter(x => x[1]).slice(0, 10).map(([k, v]) => ({ type: "mrkdwn", text: `*${slackEsc(k)}*\n${slackEsc(v)}` })) });
const ctx = t => ({ type: "context", elements: [{ type: "mrkdwn", text: t }] });

/* ---------- email templates (Jetty Admin → Email Templates), sent one-by-one from Jon's Gmail ---------- */
const TPL_FILE = () => path.join(DATA_DIR, "email-templates.json");
const DEFAULT_TEMPLATES = [
  { id: "welcome", name: "Welcome / your ambassador link", subject: "Your Jetty Ambassador page",
    body: "Hi {first_name},\n\nWelcome to Jetty Ambassador, your own page for everything ambassador-related with Jetty.\n\nFrom your page you can:\n- Upload the photos and video you shoot for us\n- Request gear for an upcoming shoot\n- See your past orders and track shipments\n\nYour personal link (just for you, please don't share it):\n{link}\n\nSite password: {password}\n\nAny questions, just reply to this email.\n\nThanks,\nJon" },
  { id: "order-time", name: "It's Time to Order Again", subject: "It's time to order your {season} gear",
    body: "Hi {first_name},\n\nThe {season} ambassador store is open! You have {allowance} to put toward this season's gear.\n\nOrder here with your personal link (it's only for you):\n{link}\n\nSite password: {password}\n\nPlease place your order by {deadline}.\n\nThanks,\nJon" },
  { id: "content", name: "Content reminder", subject: "Got any new Jetty shots?",
    body: "Hi {first_name},\n\nJust a reminder that you can upload photos and video from your shoots any time from your ambassador page, and request gear for upcoming shoots there too.\n\n{link}\n\nThanks,\nJon" },
];
function readTemplates() {
  const d = readJson(TPL_FILE(), null) || {};
  return { templates: Array.isArray(d.templates) && d.templates.length ? d.templates : DEFAULT_TEMPLATES.map(t => ({ ...t })), sends: Array.isArray(d.sends) ? d.sends : [] };
}
function writeTemplates(d) { writeJson(TPL_FILE(), { templates: d.templates, sends: d.sends.slice(-200) }); }
const PLACEHOLDERS = ["first_name", "name", "link", "password", "allowance", "season", "next_season", "deadline", "contact_name"];
function fillTemplate(str, amb, extra = {}) {
  const v = { first_name: String(amb.n || "").replace(/[“"].*?[”"]\s*/g, "").split(" ")[0], name: amb.n, link: `${SITE()}/#${amb.code}`,
    password: SITE_PASSWORD || "(no password set)", allowance: amb.a != null ? "$" + Number(amb.a).toLocaleString("en-US", { maximumFractionDigits: 2 }) : "",
    season: SEASON.storeOpen === false ? (SEASON.nextSeason || SEASON.season) : SEASON.season, next_season: SEASON.nextSeason || "", deadline: SEASON.deadline || "the deadline we'll share soon",
    contact_name: "Jon Coen", ...extra };
  return String(str || "").replace(/\{(\w+)\}/g, (m, k) => (k in v ? String(v[k] ?? "") : m));
}
function emailHtml(text, link) {
  const esc = v => String(v).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const lines = String(text).split("\n"), out = []; let list = [];
  const flush = () => { if (list.length) { out.push(`<ul style="margin:0 0 14px;padding-left:20px">${list.map(x => `<li style="margin:3px 0">${x}</li>`).join("")}</ul>`); list = []; } };
  const autolink = s => esc(s).replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#43575E">$1</a>');
  let para = [];
  const pflush = () => { if (para.length) { out.push(`<p style="margin:0 0 14px;line-height:1.5">${para.join("<br>")}</p>`); para = []; } };
  for (const raw of lines) {
    const l = raw.trimEnd();
    if (!l.trim()) { pflush(); flush(); continue; }
    if (link && l.trim() === link) { pflush(); flush(); out.push(`<p style="margin:6px 0 18px"><a href="${esc(link)}" style="display:inline-block;background:#43575E;color:#fff;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:6px">Open your Jetty Ambassador page</a><br><span style="font-size:12px;color:#5b6b71">${esc(link)}</span></p>`); continue; }
    if (/^\s*[-•]\s+/.test(l)) { pflush(); list.push(autolink(l.replace(/^\s*[-•]\s+/, ""))); continue; }
    flush(); para.push(autolink(l));
  }
  pflush(); flush();
  return `<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#0d0f10;max-width:560px">
    <div style="background:#43575E;color:#fff;padding:14px 18px;font-weight:bold;letter-spacing:.12em;font-size:13px">JETTY AMBASSADOR</div>
    <div style="padding:18px 4px 4px">${out.join("")}</div></div>`;
}
function renderTemplate(t, amb) {
  const subject = fillTemplate(t.subject, amb), text = fillTemplate(t.body, amb);
  return { subject, text, html: emailHtml(text, `${SITE()}/#${amb.code}`) };
}
const ambEmails = a => String(a.e || "").split(/[,;\s]+/).filter(x => /@/.test(x));

/* ---------- photoshoot gear requests ---------- */
// Stored as JSON on disk. On Railway attach a Volume mounted at /data so requests survive redeploys.
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync("/data") ? "/data" : path.join(ROOT, "data"));
const REQ_FILE = path.join(DATA_DIR, "gear-requests.json");
const GEAR = ["Swim", "Walkshorts", "Tees", "Wovens / Button-ups", "Polos & Knits", "Hoodies & Sweatshirts", "Flannels", "Jackets", "Hats", "Accessories"];
function readRequests() { try { return JSON.parse(fs.readFileSync(REQ_FILE, "utf8")); } catch (e) { return []; } }
function writeRequests(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = REQ_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(list, null, 1)); fs.renameSync(tmp, REQ_FILE);
}
const clip = (v, n) => String(v || "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n);
const isDate = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || ""));
function newRequest(me, f) {
  const gear = (Array.isArray(f.gear) ? f.gear : []).filter(g => GEAR.includes(g));
  const other = clip(f.other, 200);
  const r = {
    id: "REQ-" + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString("hex").toUpperCase(),
    at: new Date().toISOString(), status: "Open", test: !!me.t,
    who: { id: me.id, n: me.n, e: me.e, amc: me.amc || "" },
    location: clip(f.location, 200), shootDate: isDate(f.shootDate) ? f.shootDate : "", needBy: isDate(f.needBy) ? f.needBy : "",
    gear, other, sizes: clip(f.sizes, 300), notes: clip(f.notes, 1500),
  };
  if (!r.location) throw Object.assign(new Error("Add where the shoot is taking place."), { status: 400 });
  if (!r.needBy) throw Object.assign(new Error("Add the date you need the gear by."), { status: 400 });
  if (!r.gear.length && !r.other) throw Object.assign(new Error("Choose at least one kind of gear."), { status: 400 });
  const list = readRequests(); list.push(r); writeRequests(list);
  console.log(JSON.stringify({ event: "gear_request", id: r.id, who: r.who.n, needBy: r.needBy, gear: r.gear, other: r.other }));
  // Internal notice goes to Slack. Never blocks the request.
  const gearTxt = r.gear.concat(r.other ? ["Other: " + r.other] : []).join(", ");
  notify("requests", `${r.test ? "[TEST] " : ""}Gear request from ${r.who.n}: need by ${sDate(r.needBy)}`, [
    { type: "header", text: { type: "plain_text", text: `${r.test ? "[TEST] " : ""}Photo gear request` } },
    { type: "section", text: { type: "mrkdwn", text: `*${slackEsc(r.who.n)}* needs gear for a shoot at *${slackEsc(r.location)}*` } },
    fieldsBlock([["Need by", sDate(r.needBy)], ["Shoot date", sDate(r.shootDate)], ["Gear", gearTxt], ["Sizes", r.sizes], ["Email", r.who.e], ["AM customer", r.who.amc]]),
    ...(r.notes ? [{ type: "section", text: { type: "mrkdwn", text: `*Notes*\n${slackEsc(r.notes)}` } }] : []),
    { type: "actions", elements: [{ type: "button", style: "primary", text: { type: "plain_text", text: "Open request" }, url: `${SITE()}/#${r.id}` }] },
    ctx(`Request ${r.id} · Opens in Jetty Ambassador on a device where the Jetty Admin link has been used`),
  ], r.test);
  // Optional email copy (only if REQUEST_EMAIL_TO is set in Railway and Jon's Gmail is connected).
  if (process.env.REQUEST_EMAIL_TO && mailReady()) {
    const m = gearRequestEmail(r, process.env.PUBLIC_URL || "https://jettyambassador.up.railway.app");
    sendMail({ to: MAIL_TO, replyTo: r.who.e, ...m })
      .then(id => { const all = readRequests(), x = all.find(q => q.id === r.id); if (x) { x.emailed = new Date().toISOString(); writeRequests(all); } })
      .catch(e => console.error(JSON.stringify({ event: "gear_request_email_failed", id: r.id, error: e.message })));
  }
  return r;
}

/* ---------- content uploads to Google Drive ----------
   Railway variables:
     GOOGLE_SERVICE_ACCOUNT_JSON  the service account's JSON key (whole file contents)
     DRIVE_ROOT_FOLDER_ID         folder that holds one folder per ambassador (default: Jetty's Fileshare folder)
   Layout: <root>/<Ambassador Name>/<YYYY-MM-DD> - <Description>/  (files + "Upload info.txt")
   Files go straight from the ambassador's browser to Google (resumable upload sessions), not through this server. */
const DRIVE_ROOT = process.env.DRIVE_ROOT_FOLDER_ID || "1ff5nCjSfAlN_j7ZH76BodiezKfJsWdHv";
let SA = null; try { if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) SA = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON); } catch (e) { console.error("GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON"); }
let gTok = { token: "", exp: 0 };
const GAPI = process.env.GOOGLE_API_BASE || "https://www.googleapis.com/", GTOKEN = process.env.GOOGLE_TOKEN_URL || "https://oauth2.googleapis.com/token";
/* Upload as a real Google account (Tyler's), approved once through "Connect Google Drive" on the admin profile.
   Railway variables: GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET (from an OAuth client of type "Web application"
   with redirect URI https://<site>/api/google/callback). The approval is saved on the Volume (/data/google-oauth.json).
   Falls back to the service account only if no account is connected. */
const GO = { id: process.env.GOOGLE_OAUTH_CLIENT_ID || "", secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET || "" };
const OAUTH_FILE = () => path.join(DATA_DIR, "google-oauth.json");
const oauthSaved = () => { try { return JSON.parse(fs.readFileSync(OAUTH_FILE(), "utf8")); } catch (e) { return process.env.GOOGLE_OAUTH_REFRESH_TOKEN ? { refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN, email: "" } : null; } };
const googleMode = () => (GO.id && GO.secret && oauthSaved()?.refresh_token) ? "account" : SA ? "service" : "";
const googleReady = () => !!googleMode();
async function googleToken() {
  const mode = googleMode();
  if (!mode) throw Object.assign(new Error("Uploads aren't switched on yet."), { status: 503 });
  if (gTok.token && gTok.mode === mode && Date.now() < gTok.exp - 60000) return gTok.token;
  if (mode === "account") {
    const r = await fetch(GTOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: oauthSaved().refresh_token, client_id: GO.id, client_secret: GO.secret }).toString() });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) throw new Error("Google sign-in failed: " + JSON.stringify(j).slice(0, 200));
    gTok = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000, mode };
    return gTok.token;
  }
  const now = Math.floor(Date.now() / 1000), b64 = o => Buffer.from(JSON.stringify(o)).toString("base64url");
  const unsigned = b64({ alg: "RS256", typ: "JWT" }) + "." + b64({ iss: SA.client_email, scope: "https://www.googleapis.com/auth/drive", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 });
  const jwt = unsigned + "." + crypto.createSign("RSA-SHA256").update(unsigned).sign(SA.private_key, "base64url");
  const r = await fetch(GTOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + jwt });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("Google sign-in failed: " + JSON.stringify(j).slice(0, 200));
  gTok = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000, mode };
  return gTok.token;
}
const oauthStates = new Map(); // state -> {exp, kind}
function siteUrl(req) { return process.env.PUBLIC_URL || `https://${req.headers.host}`; }
// kind "drive" = Tyler's account for uploads; kind "gmail" = Jon's account for sending notification emails.
const MAIL_FROM = process.env.MAIL_FROM || "joncoen@jettylife.com";
const CONNECT = {
  drive: { scope: "https://www.googleapis.com/auth/drive openid email", hint: process.env.GOOGLE_UPLOAD_ACCOUNT || "tyler@jettylife.com", file: () => OAUTH_FILE() },
  gmail: { scope: "https://www.googleapis.com/auth/gmail.send openid email", hint: MAIL_FROM, file: () => path.join(DATA_DIR, "google-gmail.json") },
};
function connectUrl(req, kind = "drive") {
  const c = CONNECT[kind], state = crypto.randomBytes(16).toString("hex"); oauthStates.set(state, { exp: Date.now() + 10 * 60000, kind });
  return "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({ client_id: GO.id, redirect_uri: siteUrl(req) + "/api/google/callback",
    response_type: "code", scope: c.scope, access_type: "offline", prompt: "consent", login_hint: c.hint, state }).toString();
}
async function finishConnect(req, url) {
  const state = url.searchParams.get("state"), code = url.searchParams.get("code"), st = oauthStates.get(state || "");
  if (!st || !(st.exp > Date.now())) throw new Error("This approval link expired. Go back to the admin profile and click Connect again.");
  oauthStates.delete(state);
  if (url.searchParams.get("error")) throw new Error("Google approval was cancelled (" + url.searchParams.get("error") + ").");
  const r = await fetch(GTOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: siteUrl(req) + "/api/google/callback", client_id: GO.id, client_secret: GO.secret }).toString() });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.refresh_token) throw new Error("Google didn't return a long-term approval: " + JSON.stringify(j).slice(0, 200));
  let email = ""; try { email = JSON.parse(Buffer.from(String(j.id_token).split(".")[1], "base64url").toString()).email || ""; } catch (e) {}
  writeJson(CONNECT[st.kind].file(), { refresh_token: j.refresh_token, email, at: new Date().toISOString() });
  if (st.kind === "drive") gTok = { token: "", exp: 0 }; else mTok = { token: "", exp: 0 };
  console.log(JSON.stringify({ event: "google_connected", kind: st.kind, email }));
  return { email, kind: st.kind };
}

/* ---------- email (Gmail API, sent as the connected sender, e.g. joncoen@jettylife.com) ---------- */
const MAIL_TO = (process.env.REQUEST_EMAIL_TO || MAIL_FROM).split(",").map(x => x.trim()).filter(Boolean);
let mTok = { token: "", exp: 0 };
const mailSaved = () => readJson(CONNECT.gmail.file(), null);
const mailReady = () => !!(GO.id && GO.secret && mailSaved()?.refresh_token);
async function mailToken() {
  if (!mailReady()) throw new Error("Email isn't connected yet.");
  if (mTok.token && Date.now() < mTok.exp - 60000) return mTok.token;
  const r = await fetch(GTOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: mailSaved().refresh_token, client_id: GO.id, client_secret: GO.secret }).toString() });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("Gmail sign-in failed: " + JSON.stringify(j).slice(0, 200));
  mTok = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return mTok.token;
}
const hdr = v => /[^\x20-\x7e]/.test(v) ? "=?UTF-8?B?" + Buffer.from(v).toString("base64") + "?=" : v;
async function sendMail({ to, subject, text, html, replyTo }) {
  const from = mailSaved()?.email || MAIL_FROM, b = "jasmail" + crypto.randomBytes(6).toString("hex");
  const msg = [
    `From: ${hdr("Jetty Ambassador")} <${from}>`, `To: ${[].concat(to).join(", ")}`, ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
    `Subject: ${hdr(subject)}`, "MIME-Version: 1.0", `Content-Type: multipart/alternative; boundary="${b}"`, "",
    `--${b}`, "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64", "", Buffer.from(text).toString("base64"),
    `--${b}`, "Content-Type: text/html; charset=UTF-8", "Content-Transfer-Encoding: base64", "", Buffer.from(html || text).toString("base64"), `--${b}--`,
  ].join("\r\n");
  const r = await fetch((process.env.GMAIL_API_BASE || "https://gmail.googleapis.com/") + "gmail/v1/users/me/messages/send", {
    method: "POST", headers: { Authorization: "Bearer " + await mailToken(), "Content-Type": "application/json" }, body: JSON.stringify({ raw: Buffer.from(msg).toString("base64url") }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Gmail ${r.status}: ${JSON.stringify(j.error || j).slice(0, 300)}`);
  return j.id;
}
const escH = v => String(v ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
function gearRequestEmail(r, site) {
  const nice = d => d ? new Date(d + "T12:00:00").toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" }) : "";
  const gear = r.gear.concat(r.other ? ["Other: " + r.other] : []).join(", ");
  const rows = [["Ambassador", r.who.n], ["Email", r.who.e], ["AM customer", r.who.amc], ["Shoot location", r.location], ["Need gear by", nice(r.needBy)],
    ["Shoot date", nice(r.shootDate)], ["Gear", gear], ["Sizes", r.sizes], ["Notes", r.notes], ["Request ID", r.id]].filter(x => x[1]);
  const subject = `${r.test ? "[TEST] " : ""}Gear request: ${r.who.n} – need by ${nice(r.needBy)}`;
  const text = `New photoshoot gear request${r.test ? " (TEST)" : ""}\n\n` + rows.map(([k, v]) => `${k}: ${v}`).join("\n")
    + `\n\nManage it in Jetty Ambassador: Jetty Admin profile → Photo Gear Requests\n${site}`;
  const html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#0d0f10;max-width:560px">
    <div style="background:#43575E;color:#fff;padding:14px 18px;font-weight:bold;letter-spacing:.06em">JETTY AMBASSADOR · GEAR REQUEST${r.test ? " (TEST)" : ""}</div>
    <table style="border-collapse:collapse;width:100%;margin:10px 0">${rows.map(([k, v]) => `<tr><td style="padding:7px 10px;color:#5b6b71;border-bottom:1px solid #e3e9eb;white-space:nowrap;vertical-align:top">${escH(k)}</td><td style="padding:7px 10px;border-bottom:1px solid #e3e9eb">${escH(v).replace(/\n/g, "<br>")}</td></tr>`).join("")}</table>
    <p style="color:#5b6b71">Reply to this email to reach ${escH(r.who.n)} directly. Update the status in Jetty Ambassador under Jetty Admin → Photo Gear Requests.</p></div>`;
  return { subject, text, html };
}
async function gdrive(pathAndQuery, opts = {}) {
  const r = await fetch(GAPI + pathAndQuery, { ...opts, headers: { Authorization: "Bearer " + await googleToken(), ...(opts.headers || {}) } });
  if (opts.raw) return r;
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Drive ${r.status}: ${JSON.stringify(j.error || j).slice(0, 300)}`);
  return j;
}
const ALL = "supportsAllDrives=true&includeItemsFromAllDrives=true";
const folderName = s => String(s || "").replace(/[\/\\:*?"<>|]/g, " ").replace(/\s+/g, " ").trim().slice(0, 120);
async function findFolder(name, parent) {
  const q = `name = '${name.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}' and '${parent}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
  const j = await gdrive(`drive/v3/files?${ALL}&corpora=allDrives&fields=files(id,name)&q=${encodeURIComponent(q)}`);
  return (j.files || [])[0] || null;
}
async function makeFolder(name, parent) {
  return gdrive(`drive/v3/files?supportsAllDrives=true&fields=id,name,webViewLink`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, mimeType: "application/vnd.google-apps.folder", parents: [parent] }) });
}
const FOLDERS_FILE = () => path.join(DATA_DIR, "drive-folders.json");
function readJson(f, d) { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { return d; } }
function writeJson(f, v) { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(f + ".tmp", JSON.stringify(v, null, 1)); fs.renameSync(f + ".tmp", f); }
// A: one folder per ambassador, created the first time and reused after that (remembered by ambassador id).
async function ambassadorFolder(me) {
  const map = readJson(FOLDERS_FILE(), {});
  if (map[me.id]) {
    try { const f = await gdrive(`drive/v3/files/${map[me.id]}?supportsAllDrives=true&fields=id,trashed`); if (!f.trashed) return map[me.id]; } catch (e) {}
  }
  const name = folderName(me.n);
  const f = (await findFolder(name, DRIVE_ROOT)) || (await makeFolder(name, DRIVE_ROOT));
  map[me.id] = f.id; writeJson(FOLDERS_FILE(), map);
  return f.id;
}
async function uploadText(name, parent, text, fileId) {
  const boundary = "jas" + crypto.randomBytes(8).toString("hex");
  const meta = fileId ? {} : { name, parents: [parent], mimeType: "text/plain" };
  const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${text}\r\n--${boundary}--`;
  return gdrive(`upload/drive/v3/files${fileId ? "/" + fileId : ""}?uploadType=multipart&supportsAllDrives=true&fields=id`,
    { method: fileId ? "PATCH" : "POST", headers: { "Content-Type": `multipart/related; boundary=${boundary}` }, body });
}
async function resumableSession(file, parent, origin) {
  const r = await gdrive(`upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true&fields=id,name,size`, { raw: true, method: "POST",
    headers: { "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": file.type || "application/octet-stream",
               "X-Upload-Content-Length": String(file.size), ...(origin ? { Origin: origin } : {}) },
    body: JSON.stringify({ name: folderName(file.name) || "upload", parents: [parent] }) });
  if (!r.ok) throw new Error(`Drive upload session ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return r.headers.get("location");
}
const UPLOADS_FILE = () => path.join(DATA_DIR, "uploads.json");
// Plain-English cause for the common Google setup problems (shown to staff and test accounts only).
function explainDrive(msg) {
  const m = String(msg || "");
  if (/switched on/i.test(m) || !googleReady()) return GO.id ? "No Google account is connected yet. On the Jetty Admin profile, open Upload Content and click Connect Google Drive." : "Google isn't set up yet: add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in Railway.";
  if (googleMode() === "account" && /sign-in failed|invalid_grant/i.test(m)) return "The Google approval expired or was removed. On the Jetty Admin profile, click Connect Google Drive again.";
  if (/sign-in failed|invalid_grant|invalid_client|PEM|DECODER|asn1|private key/i.test(m)) return "Google rejected the service account key. Re-paste the whole JSON file into GOOGLE_SERVICE_ACCOUNT_JSON (or make a new key).";
  if (/accessNotConfigured|has not been used|is disabled|SERVICE_DISABLED/i.test(m)) return "The Google Drive API isn't enabled in the Cloud project. APIs & Services → Library → Google Drive API → Enable.";
  if (/storageQuotaExceeded|storage quota|do not have storage/i.test(m)) return "The folder is in someone's My Drive. Service accounts can only upload into a Shared Drive. Use a folder inside a Shared Drive.";
  if (/404|notFound|File not found/i.test(m)) return `The upload account can't see the folder (${DRIVE_ROOT}). Share it with ${SA && SA.client_email} as Content manager or Editor.`;
  if (/403|insufficient|forbidden|permission/i.test(m)) return `The upload account can see the folder but can't add to it. Give ${SA && SA.client_email} Content manager (or Editor) access.`;
  return m.slice(0, 300);
}
async function driveCheck() {
  try {
    const f = await gdrive(`drive/v3/files/${DRIVE_ROOT}?supportsAllDrives=true&fields=id,name,driveId,capabilities(canAddChildren)`);
    const mode = googleMode(), canAdd = !!(f.capabilities && f.capabilities.canAddChildren);
    return { ok: true, mode, account: mode === "account" ? oauthSaved().email : SA && SA.client_email, folder: f.name, sharedDrive: !!f.driveId, canAdd,
      problem: !canAdd ? (mode === "account" ? `${oauthSaved().email || "The connected account"} needs Editor access to the folder.` : explainDrive("403"))
        : (!f.driveId && mode === "service") ? explainDrive("storageQuotaExceeded") : null };
  } catch (e) { return { ok: false, problem: explainDrive(e.message), detail: e.message.slice(0, 300) }; }
}
const usDate = iso => { const m = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})$/); return m ? `${m[2]}/${m[3]}/${m[1]}` : ""; };
const todayET = () => new Date().toLocaleDateString("en-CA", { timeZone: "America/New_York" }); // YYYY-MM-DD
// Labeled lines first, in the order the Jetty media library reads them (see Ambassador Form Build.md).
function uploadInfo(me, f, files, status) {
  const L = [
    `Name: ${me.n}`,
    `Date of Upload: ${usDate(f.uploadDate)}`,
    `Date of Shoot: ${usDate(f.shootDate)}`,
    `Description: ${f.desc}`,
    `Location: ${f.location}`,
    `Photo: ${f.photo ? "yes" : "no"}`,
    `Video: ${f.video ? "yes" : "no"}`,
    `Is there Jetty product in photos? ${f.product === "Yes" ? "yes" : "no"}`,
    `Photographer: ${f.photographer}`,
    `Who is in the photos: ${f.people || ""}`,
    `Shoot Notes: ${String(f.notes || "").replace(/\r?\n/g, " ").trim()}`,
    "",
    "---",
    `Ambassador email: ${me.e || ""}`,
    `Submitted: ${new Date().toLocaleString("en-US", { timeZone: "America/New_York" })} ET`,
    `Files (${files.length}):`, ...files.map(x => `- ${x.name} (${(x.size / 1048576).toFixed(1)} MB)${x.status ? " - " + x.status : ""}`),
  ];
  if (status) L.push("", status);
  return L.join("\n");
}

/* Suggestions for Location / Photographer: the Jetty media library's published list + anything uploaded here. */
const OPTIONS_URL = process.env.MEDIA_OPTIONS_URL || "https://jetty-media-library.netlify.app/ambassador-options.json";
let optCache = { at: 0, data: { locations: [], photographers: [], people: [] } };
async function uploadOptions() {
  if (Date.now() - optCache.at < 10 * 60000) return optCache.data;
  const tally = { locations: new Map(), photographers: new Map(), people: new Map() };
  const add = (kind, name, uses = 1, last = "") => {
    const n = String(name || "").replace(/\s+/g, " ").trim(); if (!n) return;
    const k = n.toLowerCase(), cur = tally[kind].get(k);
    if (cur) { cur.uses += uses; if (last > cur.last) cur.last = last; } else tally[kind].set(k, { name: n, uses, last });
  };
  try {
    const r = await fetch(OPTIONS_URL, { headers: { "User-Agent": UA } });
    if (r.ok) { const j = await r.json(); for (const k of ["locations", "photographers", "people"]) for (const x of (j[k] || [])) add(k, x.name, Number(x.uses) || 1, x.last || "");
      for (const n of (j.ambassadors || [])) add("people", typeof n === "string" ? n : n.name, 1, ""); }
  } catch (e) { console.error(JSON.stringify({ event: "media_options_unreachable", error: e.message })); }
  for (const u of readJson(UPLOADS_FILE(), [])) { if (u.test) continue; add("locations", u.form.location, 1, u.form.shootDate || ""); add("photographers", u.form.photographer, 1, u.form.shootDate || "");
    add("people", u.who.n, 1, u.form.shootDate || "");
    for (const n of String(u.form.people || "").split(/\s*,\s*/)) add("people", n, 1, u.form.shootDate || ""); }
  for (const [k, v] of tally.photographers) if (!tally.people.has(k)) tally.people.set(k, { ...v, uses: 0 });   // photographers are often in shots too
  const sorted = m => [...m.values()].sort((a, b) => b.uses - a.uses || String(b.last).localeCompare(String(a.last))).map(x => x.name);
  optCache = { at: Date.now(), data: { locations: sorted(tally.locations), photographers: sorted(tally.photographers), people: sorted(tally.people) } };
  return optCache.data;
}
async function startUpload(me, form, files, origin) {
  const f = {
    uploadDate: todayET(), shootDate: isDate(form.shootDate) ? form.shootDate : "", desc: clip(form.desc, 12), location: clip(form.location, 500),
    photo: !!form.photo, video: !!form.video, product: form.product === "Yes" ? "Yes" : form.product === "No" ? "No" : "",
    photographer: clip(form.photographer, 120), notes: clip(form.notes, 5000),
    people: String(form.people || "").split(",").map(x => clip(x, 80)).filter(Boolean).slice(0, 30).join(", "),
  };
  if (!f.shootDate) throw Object.assign(new Error("Pick the Date of Shoot from the calendar."), { status: 400 });
  if (f.shootDate > f.uploadDate) throw Object.assign(new Error("The Date of Shoot can't be after today."), { status: 400 });
  if (!f.desc) throw Object.assign(new Error("Add a short description (12 characters max)."), { status: 400 });
  if (!f.location) throw Object.assign(new Error("Add the location."), { status: 400 });
  if (!f.photo && !f.video) throw Object.assign(new Error("Check Photo, Video, or both."), { status: 400 });
  if (!f.product) throw Object.assign(new Error("Answer whether there's Jetty product in the photos."), { status: 400 });
  if (!f.photographer) throw Object.assign(new Error("Add the photographer or videographer's name."), { status: 400 });
  const list = (Array.isArray(files) ? files : []).slice(0, 200).map((x, i) => ({ i, name: String(x.name || "file").slice(0, 200), size: Math.max(0, Number(x.size) || 0), type: String(x.type || "") }))
    .map(x => ({ ...x, type: x.type || (/\.(jpe?g)$/i.test(x.name) ? "image/jpeg" : /\.png$/i.test(x.name) ? "image/png" : /\.(heic|heif)$/i.test(x.name) ? "image/heic"
      : /\.(dng|cr2|cr3|nef|arw|raf|orf|rw2)$/i.test(x.name) ? "image/x-raw" : /\.(mov)$/i.test(x.name) ? "video/quicktime" : /\.(mp4|m4v)$/i.test(x.name) ? "video/mp4" : "") }))
    .filter(x => x.size > 0 && /^(image|video)\//.test(x.type));
  if (!list.length) throw Object.assign(new Error("Add at least one photo or video."), { status: 400 });
  const amb = await ambassadorFolder(me);
  // B: "<date> - <description>" subfolder; a second upload with the same name gets " (2)", " (3)"...
  let base = folderName(`${f.shootDate} - ${f.desc}`), name = base, n = 2;
  while (await findFolder(name, amb)) name = `${base} (${n++})`;
  const sub = await makeFolder(name, amb);
  // C: the form answers as a text file in the folder
  const info = await uploadText("Upload info.txt", sub.id, uploadInfo(me, f, list));
  optCache.at = 0;
  const sessions = [];
  for (const x of list) sessions.push({ i: x.i, name: x.name, url: await resumableSession(x, sub.id, origin) });
  const rec = { id: "UP-" + Date.now().toString(36).toUpperCase(), at: new Date().toISOString(), test: !!me.t, who: { id: me.id, n: me.n, e: me.e },
    form: f, folder: { id: sub.id, name, url: sub.webViewLink || `https://drive.google.com/drive/folders/${sub.id}` }, infoId: info.id, files: list, done: false };
  const all = readJson(UPLOADS_FILE(), []); all.push(rec); writeJson(UPLOADS_FILE(), all);
  console.log(JSON.stringify({ event: "upload_started", id: rec.id, who: me.n, folder: name, files: list.length }));
  return { uploadId: rec.id, folder: rec.folder.name, sessions };
}
async function finishUpload(me, id, results) {
  const all = readJson(UPLOADS_FILE(), []), rec = all.find(r => r.id === id && r.who.id === me.id);
  if (!rec) throw Object.assign(new Error("Upload not found."), { status: 404 });
  const ok = new Set((Array.isArray(results) ? results : []).filter(r => r && r.ok).map(r => Number(r.i)));
  rec.files = rec.files.map(x => ({ ...x, status: ok.has(x.i) ? "uploaded" : "NOT uploaded" }));
  rec.done = true; rec.uploaded = rec.files.filter(x => x.status === "uploaded").length;
  const missing = rec.files.length - rec.uploaded;
  try { await uploadText("Upload info.txt", null, uploadInfo(me, rec.form, rec.files, missing ? `${missing} file(s) did not finish uploading.` : "All files uploaded."), rec.infoId); }
  catch (e) { console.error(JSON.stringify({ event: "upload_info_update_failed", error: e.message })); }
  writeJson(UPLOADS_FILE(), all);
  console.log(JSON.stringify({ event: "upload_finished", id, uploaded: rec.uploaded, missing }));
  const photos = rec.files.filter(x => x.status === "uploaded" && /^image\//.test(x.type)).length, videos = rec.files.filter(x => x.status === "uploaded" && /^video\//.test(x.type)).length;
  const gb = rec.files.filter(x => x.status === "uploaded").reduce((t, x) => t + x.size, 0) / 1073741824;
  notify("uploads", `${rec.test ? "[TEST] " : ""}New content from ${me.n}: ${rec.folder.name}`, [
    { type: "header", text: { type: "plain_text", text: `${rec.test ? "[TEST] " : ""}New ambassador content` } },
    { type: "section", text: { type: "mrkdwn", text: `*${slackEsc(me.n)}* uploaded *${slackEsc(rec.folder.name)}*` },
      accessory: { type: "button", text: { type: "plain_text", text: "Open folder" }, url: rec.folder.url } },
    { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "View in Jetty Ambassador" }, url: `${SITE()}/#${rec.id}` }] },
    fieldsBlock([["Files", `${photos} photo${photos === 1 ? "" : "s"}, ${videos} video${videos === 1 ? "" : "s"} (${gb >= 1 ? gb.toFixed(1) + " GB" : Math.round(gb * 1024) + " MB"})`],
      ["Shoot date", sDate(rec.form.shootDate)], ["Location", rec.form.location], ["Shot by", rec.form.photographer], ["In the shots", rec.form.people], ["Jetty product", rec.form.product]]),
    ...(rec.form.notes ? [{ type: "section", text: { type: "mrkdwn", text: `*Shoot notes*\n${slackEsc(rec.form.notes)}` } }] : []),
    ...(missing ? [ctx(`:warning: ${missing} file(s) didn't finish uploading.`)] : []),
  ], rec.test);
  return { uploaded: rec.uploaded, missing, folder: rec.folder.name };
}

/* ---------- place suggestions for the Location field (OpenStreetMap data via Photon; no key needed) ---------- */
const placeCache = new Map(); // query -> {at, list}
const US = { "Alabama":"AL","Alaska":"AK","Arizona":"AZ","Arkansas":"AR","California":"CA","Colorado":"CO","Connecticut":"CT","Delaware":"DE","Florida":"FL","Georgia":"GA","Hawaii":"HI","Idaho":"ID","Illinois":"IL","Indiana":"IN","Iowa":"IA","Kansas":"KS","Kentucky":"KY","Louisiana":"LA","Maine":"ME","Maryland":"MD","Massachusetts":"MA","Michigan":"MI","Minnesota":"MN","Mississippi":"MS","Missouri":"MO","Montana":"MT","Nebraska":"NE","Nevada":"NV","New Hampshire":"NH","New Jersey":"NJ","New Mexico":"NM","New York":"NY","North Carolina":"NC","North Dakota":"ND","Ohio":"OH","Oklahoma":"OK","Oregon":"OR","Pennsylvania":"PA","Rhode Island":"RI","South Carolina":"SC","South Dakota":"SD","Tennessee":"TN","Texas":"TX","Utah":"UT","Vermont":"VT","Virginia":"VA","Washington":"WA","West Virginia":"WV","Wisconsin":"WI","Wyoming":"WY","Puerto Rico":"PR" };
async function placeSuggestions(q) {
  q = String(q || "").replace(/\s+/g, " ").trim().slice(0, 60);
  if (q.length < 2) return [];
  const key = q.toLowerCase(), hit = placeCache.get(key);
  if (hit && Date.now() - hit.at < 864e5) return hit.list;
  const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 2500);
  try {
    const r = await fetch(`https://photon.komoot.io/api/?q=${encodeURIComponent(q)}&limit=12&lang=en`, { headers: { "User-Agent": UA }, signal: ctl.signal });
    const j = await r.json();
    const seen = new Set(), list = [];
    for (const f of (j.features || [])) {
      const p = f.properties || {}; if (!p.name) continue;
      if (!/^(country|state|city|town|village|district|county|locality|island|beach|bay|peninsula|cape|region|archipelago|national_park|hamlet|suburb|neighbourhood)$/.test(String(p.type || p.osm_value || ""))
          && !["place", "natural", "boundary", "leisure", "tourism"].includes(p.osm_key)) continue;
      let label;
      if (p.type === "country") label = p.name;
      else if (p.countrycode === "US") label = [p.name, US[p.state] || p.state].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(", ");
      else label = [p.name, p.state && p.state !== p.name && p.type !== "state" ? p.state : "", p.country !== p.name ? p.country : ""].filter(Boolean).join(", ");
      const k = label.toLowerCase(); if (seen.has(k)) continue; seen.add(k); list.push(label);
      if (list.length >= 5) break;
    }
    placeCache.set(key, { at: Date.now(), list });
    if (placeCache.size > 2000) placeCache.delete(placeCache.keys().next().value);
    return list;
  } catch (e) { return []; } finally { clearTimeout(timer); }
}

/* ---------- order ---------- */
const seen = new Map(); // orderId -> result (stops double submits)
async function handleOrder(input) {
  if (SEASON.storeOpen === false && process.env.STORE_OPEN !== "1") throw Object.assign(new Error(`Ordering opens with ${SEASON.nextSeason || "the next season"}. We'll let you know when it's ready.`), { status: 403 });
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

  // Over the season allowance (counting earlier orders) -> order goes in as Pending for review; otherwise Approved.
  const overAllowance = total > Number(me.a) + 0.005;
  header.credit_status = overAllowance ? "Pending" : "Approved";

  const ids = await skuIds(lines.map(l => l.upc));
  const items = lines.map(l => ({ sku_id: ids[l.upc], qty: String(l.qty), unit_price: CATALOG[l.upc].p.toFixed(2), warehouse_id: header.warehouse_id }));
  const payload = { header, items };

  console.log(JSON.stringify({ event: "order", dryRun: DRY_RUN, orderId, ambassador: me.n, customer: me.amc, po: me.po, units: lines.reduce((t, l) => t + l.qty, 0), retail, payload }));
  if (DRY_RUN) return { ok: true, dryRun: true, orderId, wouldSend: payload };

  const res = await amPost("orders/", payload);
  const created = Array.isArray(res) ? res[0] : res;
  const amOrderId = created?.order_id || null;
  // Make sure the status stuck (AM may default new orders to Approved).
  if (amOrderId && String(created?.credit_status || "") !== header.credit_status) {
    try { await amPut(`orders/${amOrderId}`, { order_id: String(amOrderId), credit_status: header.credit_status }); }
    catch (e) { console.error(JSON.stringify({ event: "credit_status_update_failed", amOrderId, want: header.credit_status, error: e.message })); }
  }
  const units = lines.reduce((t, l) => t + l.qty, 0);
  if (!recent.has(ambKey(me))) recent.set(ambKey(me), []);
  recent.get(ambKey(me)).push({ amOrderId: String(amOrderId || orderId), date: new Date().toLocaleDateString("en-US"), retail, units });
  spentCache.delete(ambKey(me)); histCache.delete(ambKey(me)); seasonsCache = null;
  const out = { ok: true, orderId, amOrderId, spent: Math.round(total * 100) / 100, pending: overAllowance };
  if (orderId) seen.set(orderId, out);
  console.log(JSON.stringify({ event: "order_created", orderId, amOrderId, creditStatus: header.credit_status }));
  const kind = overAllowance ? "pending" : "orders";
  if (SLACK_ON.has(kind) || (overAllowance && SLACK_ON.has("orders"))) notify(SLACK_ON.has(kind) ? kind : "orders",
    `${me.t ? "[TEST] " : ""}${overAllowance ? "Order over allowance (Pending)" : "New order"}: ${me.n}`, [
    { type: "header", text: { type: "plain_text", text: `${me.t ? "[TEST] " : ""}${overAllowance ? "Order over allowance: Pending review" : "New ambassador order"}` } },
    fieldsBlock([["Ambassador", me.n], ["AM order", String(amOrderId || "")], ["PO", me.po], ["This order", `$${retail.toFixed(2)} retail, ${units} units`],
      ["Season total", `$${total.toFixed(2)} of $${Number(me.a).toFixed(2)}${overAllowance ? ` (over by $${(total - me.a).toFixed(2)})` : ""}`], ["Fulfillment", fulfil]]),
    ...(overAllowance ? [ctx("Approve or adjust it in ApparelMagic (credit status is Pending).")] : []),
  ], me.t);
  return out;
}

/* ---------- http ---------- */
const TYPES = { ".html": "text/html; charset=utf-8", ".json": "application/json", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".txt": "text/plain", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json" };
const PUBLIC = /^\/(index\.html|robots\.txt|manifest\.webmanifest|a\/[0-9a-f]{20}\.json|(img|brand)\/[^/]+\.(jpg|jpeg|png|webp))?$/i;
function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store", "X-Robots-Tag": "noindex" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (req.method === "POST" && url.pathname === "/api/login") {
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
      if (tooMany(ip)) return send(res, 429, { ok: false });
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      let pw = ""; try { pw = String(JSON.parse(raw).password || ""); } catch (e) {}
      const a = crypto.createHash("sha256").update(pw).digest(), b = crypto.createHash("sha256").update(SITE_PASSWORD).digest();
      if (!SITE_PASSWORD || !crypto.timingSafeEqual(a, b)) return send(res, 401, { ok: false });
      res.setHeader("Set-Cookie", `jas_auth=${authCookie()}; Path=/; Max-Age=${AUTH_DAYS * 86400}; HttpOnly; Secure; SameSite=Lax`);
      return send(res, 200, { ok: true });
    }
    // Everything except the login page's own logo/pattern needs the site password.
    if (url.pathname === "/favicon.ico") return fs.readFile(path.join(ROOT, "brand/favicon-48.png"), (e, b) => send(res, e ? 404 : 200, e ? "" : b, "image/png"));
    if (!isAuthed(req) && !/^\/(brand\/[^/]+\.png|manifest\.webmanifest)$/.test(url.pathname)) {
      if (url.pathname.startsWith("/api/")) return send(res, 401, { ok: false, error: "Please sign in again." });
      return fs.readFile(path.join(ROOT, "login.html"), (err, buf) => send(res, err ? 500 : 200, err ? "Error" : buf, "text/html; charset=utf-8"));
    }
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
        const body = JSON.parse(raw);
        let me = unlock(String(body.code || "").toUpperCase());
        if (body.as) {                                   // admin looking at another ambassador
          if (!me.admin || !Array.isArray(me.roster)) return send(res, 403, { ok: false });
          const who = me.roster.find(r => r.id === String(body.as));
          if (!who) return send(res, 404, { ok: false });
          me = { n: who.n, a: who.a, amc: who.amc, po: who.po, pa: who.pa || {} };
        }
        if (!me.amc) return send(res, 200, { ok: true, name: me.n, seasons: [] });
        return send(res, 200, { ok: true, ...(await history(me, !!body.fresh)) });
      } catch (e) {
        console.error(JSON.stringify({ event: "history_error", error: e.message }));
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 502, { ok: false });
      }
    }
    if (req.method === "POST" && url.pathname.startsWith("/api/requests/")) {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 20000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw);
        const me = unlock(String(body.code || "").toUpperCase());
        const action = url.pathname.slice("/api/requests/".length);
        if (action === "new") return send(res, 200, { ok: true, request: newRequest(me, body.request || {}) });
        if (action === "mine") return send(res, 200, { ok: true, requests: readRequests().filter(r => r.who.id === me.id).reverse() });
        if (!me.admin) return send(res, 403, { ok: false });
        if (action === "all") return send(res, 200, { ok: true, requests: readRequests().reverse() });
        if (action === "slack") return send(res, 200, { ok: true, ready: !!SLACK_URL, events: [...SLACK_ON], mentions: SLACK_MENTIONS });
        if (action === "slack-test") {
          if (!SLACK_URL) return send(res, 503, { ok: false, error: "Add SLACK_WEBHOOK_URL in Railway first." });
          const names = { requests: "Gear requests", uploads: "Content uploads", pending: "Orders over allowance", orders: "Every order" };
          const lines = [...SLACK_ON].map(k => `• ${names[k] || k}: ${(SLACK_MENTIONS[k] || []).map(id => `<@${id}>`).join(" ") || "no one tagged"}`).join("\n");
          try { await postSlack("Jetty Ambassador is connected to this channel.", [{ type: "section", text: { type: "mrkdwn", text: `:white_check_mark: *Jetty Ambassador* is connected to this channel.\nAlerts and who gets tagged:\n${lines}` } }]);
            return send(res, 200, { ok: true }); } catch (e) { return send(res, 502, { ok: false, error: e.message.slice(0, 200) }); }
        }
        if (action === "email") return send(res, 200, { ok: true, ready: mailReady(), from: mailSaved()?.email || "", to: MAIL_TO, canConnect: !!(GO.id && GO.secret) });
        if (action === "email-connect") { if (!GO.id || !GO.secret) return send(res, 503, { ok: false, error: "Add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in Railway first." });
          return send(res, 200, { ok: true, url: connectUrl(req, "gmail") }); }
        if (action === "email-test") {
          try { await sendMail({ to: MAIL_TO, subject: "[TEST] Jetty Ambassador email is working", text: `This is a test from Jetty Ambassador.\nGear requests will be emailed to: ${MAIL_TO.join(", ")}` });
            return send(res, 200, { ok: true, to: MAIL_TO }); }
          catch (e) { return send(res, 502, { ok: false, error: /insufficient|scope|403/i.test(e.message) ? "Gmail refused. Make sure the Gmail API is enabled in the Cloud project, then reconnect." : e.message.slice(0, 200) }); }
        }
        if (action === "status") {
          const list = readRequests(), r = list.find(x => x.id === body.id);
          if (!r || !["Open", "Sent", "Done", "Declined"].includes(body.status)) return send(res, 400, { ok: false });
          r.status = body.status; r.statusAt = new Date().toISOString(); writeRequests(list);
          return send(res, 200, { ok: true, request: r });
        }
        return send(res, 404, { ok: false });
      } catch (e) {
        if (e.status) return send(res, e.status, { ok: false, error: e.message });
        console.error(JSON.stringify({ event: "request_error", error: e.message }));
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 500, { ok: false, error: "Something went wrong. Try again." });
      }
    }
    if (req.method === "POST" && url.pathname.startsWith("/api/uploads/")) {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 200000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw), me = unlock(String(body.code || "").toUpperCase()), action = url.pathname.slice("/api/uploads/".length);
        const origin = req.headers.origin || `https://${req.headers.host}`;
        if (action === "start") return send(res, 200, { ok: true, ...(await startUpload(me, body.form || {}, body.files || [], origin)) });
        if (action === "finish") return send(res, 200, { ok: true, ...(await finishUpload(me, String(body.uploadId || ""), body.results)) });
        if (action === "options") return send(res, 200, { ok: true, ...(await uploadOptions()), self: me.n, today: todayET() });
        if (action === "mine") return send(res, 200, { ok: true, enabled: googleReady(), uploads: readJson(UPLOADS_FILE(), []).filter(r => r.who.id === me.id).reverse() });
        if (action === "all") { if (!me.admin) return send(res, 403, { ok: false }); return send(res, 200, { ok: true, enabled: googleReady(),
          google: { mode: googleMode(), account: googleMode() === "account" ? oauthSaved().email : SA ? SA.client_email : "", canConnect: !!(GO.id && GO.secret) },
          uploads: readJson(UPLOADS_FILE(), []).reverse() }); }
        if (action === "connect") { if (!me.admin) return send(res, 403, { ok: false });
          if (!GO.id || !GO.secret) return send(res, 503, { ok: false, error: "Add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in Railway first." });
          return send(res, 200, { ok: true, url: connectUrl(req) }); }
        return send(res, 404, { ok: false });
      } catch (e) {
        if (e.status) return send(res, e.status, { ok: false, error: e.message });
        console.error(JSON.stringify({ event: "upload_error", error: e.message, cause: explainDrive(e.message) }));
        let staff = false; try { const m = unlock(String(JSON.parse(raw).code || "").toUpperCase()); staff = !!(m.admin || m.t); } catch (x) {}
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 502, { ok: false,
          error: staff ? "Upload setup problem: " + explainDrive(e.message) : "The upload couldn't be set up. Try again in a minute." });
      }
    }
    if (req.method === "POST" && url.pathname.startsWith("/api/emails/")) {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 300000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw), me = unlock(String(body.code || "").toUpperCase()), action = url.pathname.slice("/api/emails/".length);
        if (!me.admin || !Array.isArray(me.roster)) return send(res, 403, { ok: false });
        const d = readTemplates(), roster = me.roster;
        const sample = roster.find(r => r.id === body.ambassadorId) || roster[0] || { n: "Sample Ambassador", a: 500, code: "SAMPLECODE", e: "" };
        if (action === "list") return send(res, 200, { ok: true, templates: d.templates, sends: d.sends.slice(-40).reverse(), placeholders: PLACEHOLDERS,
          mail: { ready: mailReady(), from: mailSaved()?.email || "" }, passwordSet: !!SITE_PASSWORD });
        if (action === "save") {
          const t = body.template || {}; const name = clip(t.name, 120), subject = clip(t.subject, 300), text = String(t.body || "").slice(0, 20000);
          if (!name || !subject || !text.trim()) return send(res, 400, { ok: false, error: "A template needs a name, subject and message." });
          let cur = d.templates.find(x => x.id === t.id);
          if (!cur) { cur = { id: "t" + Date.now().toString(36) }; d.templates.push(cur); }
          Object.assign(cur, { name, subject, body: text, updated: new Date().toISOString() });
          writeTemplates(d); return send(res, 200, { ok: true, template: cur });
        }
        if (action === "delete") { d.templates = d.templates.filter(x => x.id !== body.id); if (!d.templates.length) d.templates = DEFAULT_TEMPLATES.map(t => ({ ...t })); writeTemplates(d); return send(res, 200, { ok: true }); }
        if (action === "reset") { const def = DEFAULT_TEMPLATES.find(x => x.id === body.id); if (!def) return send(res, 404, { ok: false });
          const i = d.templates.findIndex(x => x.id === body.id); if (i >= 0) d.templates[i] = { ...def }; else d.templates.push({ ...def }); writeTemplates(d); return send(res, 200, { ok: true, template: def }); }
        if (action === "preview") {
          const t = body.template || d.templates.find(x => x.id === body.id); if (!t) return send(res, 404, { ok: false });
          return send(res, 200, { ok: true, to: ambEmails(sample), name: sample.n, ...renderTemplate(t, sample) });
        }
        if (action === "send") {
          if (!mailReady()) return send(res, 503, { ok: false, error: "Connect Jon's Gmail first (Photo Gear Requests → Jon's Gmail → Connect)." });
          const t = d.templates.find(x => x.id === body.id); if (!t) return send(res, 404, { ok: false, error: "Save the template first." });
          if (body.test) {     // test: rendered for one ambassador but delivered to the given address (default: the sender)
            const to = clip(body.testTo || mailSaved()?.email || MAIL_FROM, 200); const m = renderTemplate(t, sample);
            await sendMail({ to, subject: "[TEST] " + m.subject, text: m.text, html: m.html }); return send(res, 200, { ok: true, test: true, to });
          }
          const ids = new Set(Array.isArray(body.ambassadorIds) ? body.ambassadorIds : []);
          const targets = roster.filter(r => ids.has(r.id));
          if (!targets.length) return send(res, 400, { ok: false, error: "Pick at least one ambassador." });
          const results = [];
          for (const a of targets) {          // one email per ambassador, each with only their own link
            const to = ambEmails(a);
            if (!to.length) { results.push({ id: a.id, n: a.n, ok: false, error: "no email on file" }); continue; }
            try { const m = renderTemplate(t, a); await sendMail({ to, subject: m.subject, text: m.text, html: m.html }); results.push({ id: a.id, n: a.n, ok: true }); }
            catch (e) { results.push({ id: a.id, n: a.n, ok: false, error: e.message.slice(0, 160) }); }
            await new Promise(r => setTimeout(r, 250));
          }
          const rec = { id: "S" + Date.now().toString(36), at: new Date().toISOString(), templateId: t.id, templateName: t.name, subject: t.subject,
            sent: results.filter(r => r.ok).length, failed: results.filter(r => !r.ok).length, results };
          d.sends.push(rec); writeTemplates(d);
          console.log(JSON.stringify({ event: "emails_sent", template: t.name, sent: rec.sent, failed: rec.failed }));
          return send(res, 200, { ok: true, ...rec });
        }
        return send(res, 404, { ok: false });
      } catch (e) {
        console.error(JSON.stringify({ event: "emails_error", error: e.message }));
        return send(res, e.message === "bad_code" || e.code === "ENOENT" ? 403 : 500, { ok: false, error: e.message.slice(0, 200) });
      }
    }
    if (req.method === "POST" && url.pathname === "/api/admin/seasons") {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw), me = unlock(String(body.code || "").toUpperCase());
        if (!me.admin || !Array.isArray(me.roster)) return send(res, 403, { ok: false });
        return send(res, 200, { ok: true, seasons: await seasonOverview(me.roster, !!body.fresh) });
      } catch (e) { console.error(JSON.stringify({ event: "seasons_error", error: e.message })); return send(res, 502, { ok: false }); }
    }
    if (req.method === "POST" && url.pathname === "/api/pickup") {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw), me = unlock(String(body.code || "").toUpperCase()), id = String(body.order || "");
        let owner = me;
        if (body.as) {
          if (!me.admin) return send(res, 403, { ok: false });
          const w = (me.roster || []).find(r => r.id === String(body.as)); if (!w) return send(res, 404, { ok: false });
          owner = { n: w.n, a: w.a, amc: w.amc, po: w.po, pa: w.pa || {} };
        }
        histCache.delete(ambKey(owner));
        const h = await history(owner);
        const o = h.seasons.flatMap(s => s.orders).find(x => x.amOrderId === id);
        if (!o || !o.ship.canConfirm) return send(res, 409, { ok: false, error: "This order isn't ready for pickup yet." });
        const m = readPickups(); m[id] = { at: new Date().toISOString(), by: body.as ? "Jetty staff" : me.n }; writePickups(m);
        histCache.delete(ambKey(owner));
        console.log(JSON.stringify({ event: "picked_up", order: id, by: m[id].by }));
        return send(res, 200, { ok: true });
      } catch (e) { console.error(JSON.stringify({ event: "pickup_error", error: e.message })); return send(res, 500, { ok: false, error: "Couldn't save that. Try again." }); }
    }
    if (req.method === "POST" && url.pathname === "/api/debug/shipments") {
      let raw = ""; for await (const c of req) { raw += c; if (raw.length > 2000) return send(res, 413, { ok: false }); }
      try {
        const body = JSON.parse(raw), me = unlock(String(body.code || "").toUpperCase());
        if (!me.admin) return send(res, 403, { ok: false });
        const rows = await amGet("shipments/", [{ field: "order_id", operator: "=", value: String(body.order) }]);
        return send(res, 200, { ok: true, count: rows.length, sample: rows.slice(0, 2), tracking: findTracking(rows) });
      } catch (e) { return send(res, 502, { ok: false, error: e.message }); }
    }
    if (url.pathname === "/api/places") return send(res, 200, { ok: true, places: await placeSuggestions(url.searchParams.get("q")) });
    if (url.pathname === "/api/google/callback") {
      const page = (title, msg) => `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Jetty Ambassador</title><body style="font-family:system-ui;max-width:480px;margin:12vh auto;padding:0 16px;color:#0d0f10"><h2 style="color:#43575E">${title}</h2><p>${msg}</p><p><a href="/" style="color:#43575E">Back to Jetty Ambassador</a></p></body>`;
      try { const c = await finishConnect(req, url);
        return send(res, 200, c.kind === "gmail" ? page("Email connected", `Notification emails will now be sent from <b>${c.email || "the approved account"}</b>. You can close this page.`)
          : page("Google Drive connected", `Uploads will now go to Drive as <b>${c.email || "the approved account"}</b>. You can close this page.`), "text/html; charset=utf-8"); }
      catch (e) { return send(res, 400, page("Couldn't connect Google Drive", String(e.message).replace(/</g, "&lt;")), "text/html; charset=utf-8"); }
    }
    if (url.pathname === "/api/health/drive") return send(res, 200, googleReady() ? await driveCheck() : { ok: false, problem: explainDrive("") });
    if (url.pathname === "/api/health") {
      const out = { ok: true, build: BUILD, liveTracking: !!EASYPOST, slackReady: !!SLACK_URL, slackEvents: [...SLACK_ON], emailReady: mailReady(), emailFrom: mailSaved()?.email || null, emailTo: MAIL_TO, uploadsEnabled: googleReady(), uploadsMode: googleMode(), uploadsAccount: googleMode() === "account" ? oauthSaved().email : SA ? SA.client_email : null, savedRequests: readRequests().length, tokenSet: !!AM_TOKEN, dryRun: DRY_RUN, dataDir: DATA_DIR, persistentStorage: DATA_DIR === "/data", subdomain: AM_BASE.split("//")[1].split(".")[0] };
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
}).listen(PORT, () => console.log(`Ambassador store on :${PORT} (AM token ${AM_TOKEN ? "set" : "missing"}${DRY_RUN ? ", DRY RUN" : ""}, password ${SITE_PASSWORD ? "on" : "OFF"})`));
