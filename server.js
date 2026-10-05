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
async function amGet(endpoint, params = []) {
  const body = { ...auth() };
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
  header.notes = [`Ambassador store order ${orderId} – ${me.n}${me.t ? " (TEST)" : ""}`, fulfil,
    `Retail value $${retail.toFixed(2)} of $${Number(me.a).toFixed(2)} allowance${retail > me.a ? ` (OVER by $${(retail - me.a).toFixed(2)})` : ""}`,
    notes ? `Ambassador notes: ${notes}` : ""].filter(Boolean).join("\n");

  const ids = await skuIds(lines.map(l => l.upc));
  const items = lines.map(l => ({ sku_id: ids[l.upc], qty: String(l.qty), unit_price: CATALOG[l.upc].p.toFixed(2), warehouse_id: header.warehouse_id }));
  const payload = { header, items };

  console.log(JSON.stringify({ event: "order", dryRun: DRY_RUN, orderId, ambassador: me.n, customer: me.amc, po: me.po, units: lines.reduce((t, l) => t + l.qty, 0), retail, payload }));
  if (DRY_RUN) return { ok: true, dryRun: true, orderId, wouldSend: payload };

  const res = await amPost("orders/", payload);
  const amOrderId = (Array.isArray(res) ? res[0] : res)?.order_id || null;
  const out = { ok: true, orderId, amOrderId };
  if (orderId) seen.set(orderId, out);
  console.log(JSON.stringify({ event: "order_created", orderId, amOrderId }));
  return out;
}

/* ---------- http ---------- */
const TYPES = { ".html": "text/html; charset=utf-8", ".json": "application/json", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".txt": "text/plain", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml" };
const PUBLIC = /^\/(index\.html|robots\.txt|a\/[0-9a-f]{20}\.json|img\/[^/]+\.(jpg|jpeg|png|webp))?$/i;
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
