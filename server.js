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
async function shipmentsFor(orderIds) {
  // Re-check every 2 minutes until a tracking number shows up, then every 30 minutes.
  const need = orderIds.filter(id => { const c = shipCache.get(id); return !c || Date.now() - c.at > (c.data.tracking.length ? 30 : 2) * 60000; });
  for (let i = 0; i < need.length; i += 25) {
    const chunk = need.slice(i, i + 25);
    let rows = [];
    try { rows = await amGet("shipments/", chunk.map(id => ({ field: "order_id", operator: "=", value: id, include_type: "OR" })), { pagination: { page_size: 1000 } }); }
    catch (e) { console.error(JSON.stringify({ event: "shipments_lookup_failed", error: e.message })); }
    const by = new Map(chunk.map(id => [id, []]));
    for (const r of rows) {
      const ids = new Set([r.order_id, ...(Array.isArray(r.shipment_items) ? r.shipment_items.map(x => x.order_id) : [])].filter(Boolean).map(String));
      for (const id of ids) if (by.has(id)) by.get(id).push(r);
    }
    for (const [id, list] of by) {
      const seen = new Set(), tracking = findTracking(list).filter(t => !seen.has(t.number) && seen.add(t.number));
      shipCache.set(id, { at: Date.now(), data: { tracking, shipDate: (list.find(r => r.date || r.ship_date) || {}).date || (list[0] || {}).ship_date || "" } });
    }
  }
  return Object.fromEntries(orderIds.map(id => [id, (shipCache.get(id) || {}).data || { tracking: [] }]));
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
async function history(me) {
  const hit = histCache.get(me.po);
  if (hit && Date.now() - hit.at < 60000) return hit.data;
  const cur = seasonOfPo(me.po);
  const rows = await allOrders(await customerId(me.amc));
  const seasons = new Map(), pickups = readPickups();
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
    seasons.get(s.code).orders.push({ amOrderId: String(o.order_id), date: o.date || "", items, ship: shipStatus(o, pickups),
      method: String(o.shipping_info || ""),
      units: items.reduce((t, i) => t + i.qty, 0), retail: items.reduce((t, i) => t + i.qty * i.retail, 0) });
  }
  if (cur && !seasons.has(cur.code)) seasons.set(cur.code, { ...cur, allowance: Number(me.a), orders: [] });
  const shippedIds = [...seasons.values()].flatMap(s => s.orders).filter(o => o.ship.state !== "processing" && !o.ship.pickup).map(o => o.amOrderId);
  if (shippedIds.length) {
    const info = await shipmentsFor(shippedIds);
    for (const s of seasons.values()) for (const o of s.orders) if (info[o.amOrderId]) { o.tracking = info[o.amOrderId].tracking; o.shipDate = info[o.amOrderId].shipDate; }
  }
  const list = [...seasons.values()].map(s => ({ code: s.code, label: s.label, current: s.code === cur?.code, allowance: s.allowance,
    spent: Math.round(s.orders.reduce((t, o) => t + o.retail, 0) * 100) / 100, units: s.orders.reduce((t, o) => t + o.units, 0),
    orders: s.orders.sort((a, b) => Number(b.amOrderId) - Number(a.amOrderId)), sort: s.sort })).sort((a, b) => b.sort - a.sort);
  const data = { name: me.n, seasons: list };
  histCache.set(me.po, { at: Date.now(), data });
  return data;
}

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
  // TODO (email): send the request details + who it came from once an email service is chosen.
  return r;
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
    if (!isAuthed(req) && !/^\/brand\/[^/]+\.png$/.test(url.pathname)) {
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
        return send(res, 200, { ok: true, ...(await history(me)) });
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
        histCache.delete(owner.po);
        const h = await history(owner);
        const o = h.seasons.flatMap(s => s.orders).find(x => x.amOrderId === id);
        if (!o || !o.ship.canConfirm) return send(res, 409, { ok: false, error: "This order isn't ready for pickup yet." });
        const m = readPickups(); m[id] = { at: new Date().toISOString(), by: body.as ? "Jetty staff" : me.n }; writePickups(m);
        histCache.delete(owner.po);
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
    if (url.pathname === "/api/health") {
      const out = { ok: true, tokenSet: !!AM_TOKEN, dryRun: DRY_RUN, dataDir: DATA_DIR, persistentStorage: DATA_DIR === "/data", subdomain: AM_BASE.split("//")[1].split(".")[0] };
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
