/* Szihalom drone survey viewer.
   Everything (image tiles and data) is AES-GCM encrypted; the password unlocks the content key
   (key.json, PBKDF2-SHA256). Coordinates are WGS 84 / UTM 34N (EPSG:32634), as in the survey. */
'use strict';

const KEY_STORE = 'szihalom-survey-ck';
const $ = (s) => document.querySelector(s);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const fmt = (v, d = 0) => (v == null ? '–' : Number(v).toLocaleString('en-GB', { minimumFractionDigits: d, maximumFractionDigits: d }));

let CK = null;          // AES-GCM content key
let DATA = null;

// ------------------------------------------------------------------ unlock
async function contentKeyFromPassword(pw) {
  const kj = await (await fetch('key.json', { cache: 'no-store' })).json();
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(kj.salt), iterations: kj.iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(kj.iv) }, kek, b64(kj.wrapped)));
}

async function decrypt(buf) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, CK, buf.slice(12)));
}

async function start(raw) {
  CK = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const enc = new Uint8Array(await (await fetch('data.enc', { cache: 'no-store' })).arrayBuffer());
  DATA = JSON.parse(new TextDecoder().decode(fflate.gunzipSync(await decrypt(enc))));
  $('#lock').hidden = true;
  buildMap();
  buildPanel();
}

$('#lockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#unlockBtn');
  btn.disabled = true; btn.textContent = 'Opening…'; $('#lockMsg').textContent = '';
  try {
    const raw = await contentKeyFromPassword($('#pw').value);
    if ($('#remember').checked) {
      try { localStorage.setItem(KEY_STORE, btoa(String.fromCharCode(...raw))); } catch (_) { /* private mode */ }
    }
    await start(raw);
  } catch (err) {
    console.error(err);
    $('#lockMsg').textContent = 'Wrong password.';
    btn.disabled = false; btn.textContent = 'Open';
  }
});

$('#logout').addEventListener('click', () => {
  try { localStorage.removeItem(KEY_STORE); } catch (_) { /* ignore */ }
  location.reload();
});

(async () => {
  let saved = null;
  try { saved = localStorage.getItem(KEY_STORE); } catch (_) { /* ignore */ }
  if (saved) {
    try { await start(b64(saved)); return; } catch (err) { console.error(err); }
  }
  $('#pw').focus();
})();

// ------------------------------------------------------------------ map
proj4.defs('EPSG:32634', '+proj=utm +zone=34 +datum=WGS84 +units=m +no_defs +type=crs');
ol.proj.proj4.register(proj4);
const UTM = ol.proj.get('EPSG:32634');
const S = ol.style;
let map, layers = {}, heapSource, areaSource, selectSource, popup;

// a tile that fails once (network hiccup) would otherwise stay blurry: retry a few times
async function fetchRetry(url, tries = 4) {
  for (let i = 0; ; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return await res.arrayBuffer();
      if (res.status === 404 || i >= tries - 1) throw new Error(res.status);
    } catch (err) {
      if (i >= tries - 1 || err.message === '404') throw err;
    }
    await new Promise((r) => setTimeout(r, 400 * 2 ** i));
  }
}

function droneLayer(im) {
  const n = im.nlev, r = im.res, T = im.tile;
  const resolutions = Array.from({ length: n }, (_, z) => r * 2 ** (n - 1 - z));
  const extent = [im.origin[0], im.origin[1] - im.H * im.res_y, im.origin[0] + im.W * r, im.origin[1]];
  const have = new Set();
  for (const [z, list] of Object.entries(im.have)) for (const [x, y] of list) have.add(`${z}/${x}/${y}`);
  const source = new ol.source.TileImage({
    projection: UTM,
    tileGrid: new ol.tilegrid.TileGrid({ origin: im.origin, resolutions, tileSize: T, extent }),
    interpolate: true,
    transition: 150,
    tileUrlFunction: (c) => (have.has(`${c[0]}/${c[1]}/${c[2]}`) ? `${DATA.tile_base}/${im.id}/${c[0]}/${c[1]}/${c[2]}.bin` : undefined),
    tileLoadFunction: (tile, src) => {
      fetchRetry(src)
        .then((buf) => decrypt(new Uint8Array(buf)))
        .then((plain) => {
          const url = URL.createObjectURL(new Blob([plain], { type: 'image/webp' }));
          const img = tile.getImage();
          img.onload = img.onerror = () => URL.revokeObjectURL(url);
          img.src = url;
        })
        .catch(() => tile.setState(ol.TileState.ERROR));
    },
  });
  return new ol.layer.Tile({ source, extent, preload: 1 });
}

const areaStyleCache = {};
function areaStyle(f, res) {
  const st = f.get('status');
  const key = st + (res < 6 ? 'L' : '');
  if (!areaStyleCache[key]) {
    const noImg = st === 'pending' || st === 'noimage';
    const col = noImg ? '#c9ced8' : '#ffffff';
    areaStyleCache[key] = [
      new S.Style({ stroke: new S.Stroke({ color: 'rgba(15,30,60,.65)', width: 4.5 }) }),
      new S.Style({
        stroke: new S.Stroke({ color: col, width: 2, lineDash: noImg ? [8, 6] : undefined }),
        fill: new S.Fill({ color: noImg ? 'rgba(120,130,150,.18)' : 'rgba(0,0,0,0)' }),
      }),
    ];
  }
  const label = new S.Style({
    text: new S.Text({
      text: f.get('id') + (res < 3 ? ({ pending: '\nsurvey pending', noimage: '\nimage pending' }[f.get('status')] || '') : ''),
      font: `700 ${res > 4 ? 13 : 16}px "Segoe UI", system-ui, sans-serif`,
      fill: new S.Fill({ color: '#fff' }), stroke: new S.Stroke({ color: 'rgba(15,30,60,.85)', width: 4 }),
      overflow: true,
    }),
  });
  return res > 0.6 ? [...areaStyleCache[key], label] : areaStyleCache[key];
}

function heapStyle(f, res) {
  const sand = f.get('type') === 'Bedding sand';
  const color = sand ? '#ffd600' : '#ff6d00';
  const st = [new S.Style({
    stroke: new S.Stroke({ color, width: res < 0.2 ? 2.5 : 2 }),
    fill: new S.Fill({ color: res > 0.6 ? color + '99' : 'rgba(0,0,0,0.01)' }),
  })];
  if (res < 0.15) {
    const v = f.get('volume_m3');
    st.push(new S.Style({
      text: new S.Text({
        text: `${f.get('id')}\n${v == null ? 'volume pending' : fmt(v, 2) + ' m³'}`,
        font: '600 12px "Segoe UI", system-ui, sans-serif', fill: new S.Fill({ color: '#fff' }),
        stroke: new S.Stroke({ color: 'rgba(0,0,0,.8)', width: 3 }), overflow: true,
      }),
    }));
  }
  return st;
}

function lines(list, color, width, minRes) {
  const src = new ol.source.Vector({
    features: [new ol.Feature(new ol.geom.MultiLineString(list))],
  });
  return new ol.layer.Vector({ source: src, style: new S.Style({ stroke: new S.Stroke({ color, width }) }), maxResolution: minRes, updateWhileInteracting: false });
}

function buildMap() {
  const gj = new ol.format.GeoJSON({ dataProjection: UTM, featureProjection: UTM });

  layers.satellite = new ol.layer.Tile({
    source: new ol.source.XYZ({
      url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
      maxZoom: 18, crossOrigin: 'anonymous',
      attributions: 'Background outside the survey: Esri World Imagery',
    }),
  });
  layers.drone = new ol.layer.Group({ layers: DATA.images.slice().reverse().map(droneLayer) });

  areaSource = new ol.source.Vector();
  for (const a of DATA.areas) {
    const f = gj.readFeature({ type: 'Feature', geometry: a.geom, properties: {} });
    f.setProperties({ ...a, geom: undefined, kind: 'area' });
    areaSource.addFeature(f);
  }
  layers.areas = new ol.layer.Vector({ source: areaSource, style: areaStyle, declutter: true });

  heapSource = new ol.source.Vector({ features: gj.readFeatures(DATA.heaps) });
  heapSource.forEachFeature((f) => f.set('kind', 'heap'));
  layers.heaps = new ol.layer.Vector({ source: heapSource, style: heapStyle, declutter: false });

  // grass already cut, as marked by our crew in the Fűvágás app (off by default)
  if (DATA.grass_cut) {
    const gsrc = new ol.source.Vector({ features: gj.readFeatures(DATA.grass_cut.features) });
    gsrc.forEachFeature((f) => f.set('kind', 'cut'));
    layers.grassCut = new ol.layer.Vector({
      source: gsrc, visible: false,
      style: (f, res) => new S.Style({
        stroke: new S.Stroke({ color: '#00c853', width: 1.5 }),
        fill: new S.Fill({ color: 'rgba(0,200,83,.28)' }),
        text: res < 0.8 ? new S.Text({ text: shortDate(f.get('date')), font: '600 12px "Segoe UI", system-ui, sans-serif',
          fill: new S.Fill({ color: '#fff' }), stroke: new S.Stroke({ color: '#0b5d1e', width: 3 }), overflow: true }) : undefined,
      }),
    });
  }

  layers.fences = lines(DATA.dwg.fences, 'rgba(255,235,59,.9)', 1.5, 30);
  layers.roads = lines(DATA.dwg.roads, 'rgba(255,255,255,.75)', 1, 6);
  layers.tables = lines(DATA.dwg.tables, 'rgba(0,229,255,.8)', 1, 2);
  layers.droneFences = new ol.layer.Vector({
    source: new ol.source.Vector({ features: gj.readFeatures(DATA.drone_fences) }),
    style: new S.Style({ stroke: new S.Stroke({ color: '#00e676', width: 2, lineDash: [6, 5] }) }),
  });
  layers.mv = new ol.layer.Vector({
    source: new ol.source.Vector({ features: DATA.mv.map((m) => new ol.Feature({ geometry: new ol.geom.Point([m.x, m.y]), name: m.name })) }),
    maxResolution: 1.2,
    style: (f) => new S.Style({
      image: new S.Circle({ radius: 4, fill: new S.Fill({ color: '#1f3864' }), stroke: new S.Stroke({ color: '#fff', width: 1.5 }) }),
      text: new S.Text({ text: f.get('name'), offsetY: -12, font: '600 11px "Segoe UI", system-ui, sans-serif', fill: new S.Fill({ color: '#fff' }), stroke: new S.Stroke({ color: '#1f3864', width: 3 }) }),
    }),
  });
  selectSource = new ol.source.Vector();
  layers.select = new ol.layer.Vector({
    source: selectSource,
    style: new S.Style({ stroke: new S.Stroke({ color: '#00b0ff', width: 4 }) }),
  });
  layers.tables.setVisible(false);
  layers.roads.setVisible(false);
  layers.droneFences.setVisible(false);

  popup = new ol.Overlay({ element: $('#popup'), positioning: 'bottom-center', offset: [0, -14], autoPan: { animation: { duration: 250 }, margin: 40 }, stopEvent: true });
  map = new ol.Map({
    target: 'map',
    layers: [layers.satellite, layers.drone, layers.roads, layers.tables, layers.fences, layers.droneFences,
      ...(layers.grassCut ? [layers.grassCut] : []), layers.areas, layers.heaps, layers.mv, layers.select],
    overlays: [popup],
    view: new ol.View({ projection: UTM, maxResolution: 40, minResolution: 0.006, constrainResolution: false }),
    controls: ol.control.defaults.defaults({ rotate: false, attributionOptions: { collapsible: true } })
      .extend([new ol.control.ScaleLine({ units: 'metric' })]),
  });
  map.getView().fit(areaSource.getExtent(), { padding: [30, 30, 30, 30] });

  // loading indicator while image tiles are still arriving
  map.on('loadstart', () => { $('#loading').hidden = false; });
  map.on('loadend', () => { $('#loading').hidden = true; });

  map.on('singleclick', onClick);
  map.on('pointermove', (e) => {
    if (e.dragging || measuring) return;
    const hit = map.hasFeatureAtPixel(e.pixel, { layerFilter: (l) => l === layers.heaps || l === layers.areas || l === layers.grassCut });
    map.getTargetElement().style.cursor = hit ? 'pointer' : '';
  });
  $('#popup .popup-close').addEventListener('click', closePopup);
  setupMeasure();
}

function closePopup() { popup.setPosition(undefined); $('#popup').hidden = true; selectSource.clear(); }

function showPopup(coord, html, feature) {
  $('#popupBody').innerHTML = html;
  $('#popup').hidden = false;
  popup.setPosition(coord);
  selectSource.clear();
  if (feature) selectSource.addFeature(feature.clone());
}

function heapHtml(p) {
  const v = (x) => (x == null ? '–' : fmt(x, 2) + ' m³');
  return `<h4>Heap ${p.id}</h4><table>
    <tr><td>Type</td><td>${p.type}</td></tr>
    <tr><td>Area</td><td>${p.area}</td></tr>
    <tr><td>Footprint</td><td>${fmt(p.area_m2, 1)} m²</td></tr>
    <tr><td><b>Volume (net)</b></td><td><b>${p.volume_m3 == null ? 'pending' : v(p.volume_m3)}</b></td></tr>
    <tr><td>above base (cut)</td><td>${v(p.cut_m3)}</td></tr>
    <tr><td>below base (fill)</td><td>${v(p.fill_m3)}</td></tr>
    <tr><td>Survey date</td><td>${p.survey_date || 'not stated'}</td></tr>
    ${p.outside_fence ? '<tr><td colspan="2"><i>Outside the project fence</i></td></tr>' : ''}
  </table><div class="src">Survey company record “${p.name || ''}” · ${p.source}</div>`;
}

function cutHtml(p) {
  return `<h4>Grass cut</h4><table>
    <tr><td>Date</td><td>${p.date ? new Date(p.date + 'T12:00:00').toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '–'}</td></tr>
    <tr><td>Area of this mark</td><td>${fmt(p.area_m2, 0)} m²</td></tr>
  </table><div class="src">Marked on site by our crew in the grass-cutting app.</div>`;
}

function areaHtml(a) {
  const st = { surveyed: 'Surveyed', partly: 'Partly surveyed', pending: 'Survey pending', noimage: 'Measured, image pending' }[a.status];
  return `<h4>Area ${a.id}</h4><table>
    <tr><td>Status</td><td><span class="chip ${a.status}">${st}</span></td></tr>
    <tr><td>MV stations</td><td>${a.mv.join(', ') || '–'}</td></tr>
    <tr><td>${a.drawn ? 'Area (our outline)' : 'Fenced area (drawing)'}</td><td>${fmt(a.fenced_m2 / 1e4, 2)} ha</td></tr>
    ${a.drone_fence_m2 ? `<tr><td>Fence measured by drone</td><td>${fmt(a.drone_fence_m2 / 1e4, 2)} ha</td></tr>` : ''}
    <tr><td>Flight</td><td>${a.date || (a.status === 'pending' || a.status === 'noimage' ? '–' : 'not stated')}</td></tr>
    <tr><td>Soil heaps</td><td>${a.soil_n} · ${fmt(a.soil_m3, 1)} m³</td></tr>
    ${a.sand_n ? `<tr><td>Bedding sand</td><td>${a.sand_n} · ${fmt(a.sand_m3, 1)} m³</td></tr>` : ''}
    ${a.note ? `<tr><td colspan="2"><i>${a.note}</i></td></tr>` : ''}
  </table>`;
}

function onClick(e) {
  if (measuring) return;
  // priority: heap > cut-grass mark > area
  let hit = null, rank = 0;
  map.forEachFeatureAtPixel(e.pixel, (f, l) => {
    const r = l === layers.heaps ? 3 : l === layers.grassCut ? 2 : 1;
    if (r > rank) { hit = f; rank = r; }
    return rank === 3;
  }, { hitTolerance: 3, layerFilter: (l) => l === layers.heaps || l === layers.areas || l === layers.grassCut });
  if (!hit) { closePopup(); return; }
  const kind = hit.get('kind');
  if (kind === 'heap') showPopup(e.coordinate, heapHtml(hit.getProperties()), hit);
  else if (kind === 'cut') showPopup(e.coordinate, cutHtml(hit.getProperties()), hit);
  else showPopup(e.coordinate, areaHtml(hit.getProperties()), hit);
}

function zoomTo(feature, maxRes) {
  map.getView().fit(feature.getGeometry().getExtent(), { padding: [60, 60, 60, 60], maxZoom: undefined, duration: 500,
    minResolution: maxRes });
}

// ------------------------------------------------------------------ measuring
let measuring = null, draw = null, measureSrc = null;
function setupMeasure() {
  measureSrc = new ol.source.Vector();
  map.addLayer(new ol.layer.Vector({
    source: measureSrc, zIndex: 20,
    style: new S.Style({ stroke: new S.Stroke({ color: '#00b0ff', width: 2.5 }), fill: new S.Fill({ color: 'rgba(0,176,255,.15)' }) }),
  }));
  const tip = $('#measureTip');
  const text = (g) => (g instanceof ol.geom.Polygon
    ? `${fmt(g.getArea(), 1)} m²  (${fmt(g.getArea() / 1e4, 4)} ha)`
    : `${fmt(g.getLength(), 2)} m`);
  document.querySelectorAll('[data-measure]').forEach((b) => b.addEventListener('click', () => {
    const type = b.dataset.measure;
    if (draw) { map.removeInteraction(draw); draw = null; }
    document.querySelectorAll('[data-measure]').forEach((x) => x.classList.remove('on'));
    if (type === 'clear' || measuring === type) {
      measuring = null; measureSrc.clear(); tip.hidden = true; return;
    }
    measuring = type; b.classList.add('on'); closePopup();
    draw = new ol.interaction.Draw({ source: measureSrc, type });
    draw.on('drawstart', (ev) => {
      ev.feature.getGeometry().on('change', (g) => {
        const geom = g.target;
        const c = geom instanceof ol.geom.Polygon ? geom.getInteriorPoint().getCoordinates() : geom.getLastCoordinate();
        const px = map.getPixelFromCoordinate(c);
        tip.textContent = text(geom); tip.hidden = false;
        tip.style.left = px[0] + 12 + 'px'; tip.style.top = px[1] - 12 + 'px';
      });
    });
    draw.on('drawend', (ev) => {
      const g = ev.feature.getGeometry();
      ev.feature.setStyle(new S.Style({
        stroke: new S.Stroke({ color: '#00b0ff', width: 2.5 }), fill: new S.Fill({ color: 'rgba(0,176,255,.15)' }),
        text: new S.Text({ text: text(g), font: '700 13px "Segoe UI", sans-serif', fill: new S.Fill({ color: '#fff' }),
          stroke: new S.Stroke({ color: '#003a57', width: 4 }), overflow: true,
          placement: g instanceof ol.geom.Polygon ? 'point' : 'line' }),
      }));
      tip.hidden = true;
    });
    map.addInteraction(draw);
  }));
}

// ------------------------------------------------------------------ side panel
function datesInWords(dates) {
  // ['2026-10-02', '2026-10-03', '2026-10-10'] -> '2, 3 and 10 October 2026' when all in one month
  const d = dates.map((x) => new Date(x + 'T12:00:00'));
  const oneMonth = d.every((x) => x.getMonth() === d[0].getMonth() && x.getFullYear() === d[0].getFullYear());
  if (!oneMonth) return d.map((x) => x.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })).join(', ');
  const days = d.map((x) => x.getDate());
  const list = days.length > 1 ? `${days.slice(0, -1).join(', ')} and ${days[days.length - 1]}` : String(days[0]);
  return `${list} ${d[0].toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}`;
}

function shortDate(x) {
  return x ? new Date(x + 'T12:00:00').toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) : '';
}

function buildPanel() {
  const s = DATA.summary;
  const kpi = (v, l, wide) => `<div class="kpi${wide ? ' wide' : ''}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  $('#kpis').innerHTML =
    kpi(`${fmt(s.imaged_ha, 1)} ha`, `surveyed of ${fmt(s.fenced_ha, 1)} ha fenced`) +
    kpi(`${s.px_cm[0]}–${s.px_cm[1]} cm`, 'per image pixel') +
    kpi(`${s.soil_n}`, 'displaced-soil heaps') +
    kpi(`${fmt(s.soil_m3, 1)} m³`, 'displaced soil, net volume') +
    kpi(datesInWords(s.dates), 'flight dates', true);

  // layer switches
  const items = [
    ['drone', 'Drone survey images', '#1f3864', true],
    ['satellite', 'Satellite background (outside survey)', '#7a8a6a', true],
    ['areas', 'Areas (design drawing)', '#ffffff', true],
    ['heaps', 'Soil heaps / bedding sand', '#ff6d00', true],
    ['fences', 'Drawing: fences', '#ffeb3b', true],
    ['roads', 'Drawing: roads', '#cfd6e0', false],
    ['tables', 'Drawing: panel tables', '#00e5ff', false],
    ['droneFences', 'Fence lines measured by drone', '#00e676', false],
    ['mv', 'MV stations', '#1f3864', true],
  ];
  if (layers.grassCut) {
    const g = DATA.grass_cut;
    items.splice(4, 0, ['grassCut', `Grass cut so far – our worklog (${fmt(g.covered_m2 / 1e4, 2)} ha, ${g.n} areas)`, '#00c853', false]);
  }
  $('#layerList').innerHTML = items.map(([k, l, c, on]) =>
    `<label><input type="checkbox" data-layer="${k}" ${on ? 'checked' : ''}><span class="swatch" style="border-color:${c};background:${c}33"></span>${l}</label>`).join('');
  document.querySelectorAll('[data-layer]').forEach((cb) => cb.addEventListener('change', () => layers[cb.dataset.layer].setVisible(cb.checked)));

  // areas table, with three views: soil heaps / grass cut / machinery
  document.querySelectorAll('#areaMode button').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('#areaMode button').forEach((x) => x.classList.toggle('on', x === b));
    renderAreas(b.dataset.mode);
    if (b.dataset.mode === 'grass' && layers.grassCut) setLayer('grassCut', true);
  }));
  renderAreas('heaps');
  if (!layers.grassCut) document.querySelector('#areaMode [data-mode="grass"]').disabled = true;
  if (!DATA.machines) document.querySelector('#areaMode [data-mode="machines"]').disabled = true;

  // heaps
  const sel = $('#heapArea');
  const ids = [...new Set(heapSource.getFeatures().map((f) => f.get('area')))].sort();
  sel.innerHTML = '<option value="">All areas</option>' + ids.map((i) => `<option>${i}</option>`).join('');
  sel.addEventListener('change', renderHeaps);
  $('#heapType').addEventListener('change', renderHeaps);
  $('#csv').addEventListener('click', downloadCsv);
  renderHeaps();

  // tabs (the machinery layers show only while the Machinery tab is open)
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('active', x === b));
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + b.dataset.tab));
    machinesActive(b.dataset.tab === 'machines');
  }));
  if (DATA.machines) buildMachines();
  else document.querySelector('.tabs [data-tab="machines"]').hidden = true;
  $('#panelToggle').addEventListener('click', () => { $('#panel').classList.toggle('hidden'); map.updateSize(); });

  buildProof();
}

// ------------------------------------------------------------------ machinery: where each machine worked, day by day
// Routes: computed at build time along the site roads with the machinery worklog's own router
// (tools/routes.py), so the animation follows the roads behind the logged distances.
const M_COLORS = { DZ: '#f9a825', EX1: '#ef6c00', EX2: '#c62828', T1: '#1e88e5', T2: '#3949ab', T3: '#00897b', T4: '#8e24aa' };
const mColor = (s) => M_COLORS[s] || '#546e7a';
const mType = (name) => (/dozer/i.test(name) ? 'dozer' : /excavator/i.test(name) ? 'excavator' : 'truck');
let M = { day: 0, play: null, anim: null, markers: {}, routes: [], active: false, fitted: false };

// --- machine pictures (SVG): top view for the map (front = up), side view for the list
const GLASS = '#1b2a3a';
const SHADE = 'rgba(0,0,0,.28)';
const svgUrl = (s) => 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s);
const TOP = {                        // real length (m) and natural pixel length of each top view
  truck: { len: 10.0, px: 100 },
  excavator: { len: 9.6, px: 96 },
  dozer: { len: 6.6, px: 66 },
};
function topSvg(type, c) {
  if (type === 'truck') {
    const wheels = [10, 20, 66, 79].map((y) => `<rect x="0" y="${y}" width="3.2" height="8" rx="1" fill="#1e1e1e"/><rect x="22.8" y="${y}" width="3.2" height="8" rx="1" fill="#1e1e1e"/>`).join('');
    return `<svg xmlns="http://www.w3.org/2000/svg" width="26" height="100" viewBox="0 0 26 100">${wheels}
      <rect x="1.5" y="0.6" width="23" height="17" rx="3.2" fill="${c}" stroke="${SHADE}" stroke-width=".6"/>
      <rect x="3.4" y="2" width="19.2" height="4.6" rx="1.2" fill="${GLASS}"/>
      <rect x="4.2" y="8.4" width="17.6" height="7" rx="1.6" fill="rgba(255,255,255,.22)"/>
      <rect x="10" y="17" width="6" height="4" fill="#333"/>
      <rect x="1" y="20.5" width="24" height="79" rx="1.6" fill="${c}" stroke="${SHADE}" stroke-width=".8"/>
      <rect x="3.4" y="23" width="19.2" height="74" rx="1.2" fill="#7b5e45"/>
      <path d="M5 40 Q13 33 21 40 M5 60 Q13 53 21 60 M5 80 Q13 73 21 80" stroke="#5d4433" stroke-width="1.2" fill="none"/></svg>`;
  }
  if (type === 'excavator') {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="30" height="96" viewBox="0 0 30 96">
      <rect x="0" y="50" width="7.5" height="44" rx="2.2" fill="#2b2b2b"/><rect x="22.5" y="50" width="7.5" height="44" rx="2.2" fill="#2b2b2b"/>
      <path d="M1 54h5.5M1 60h5.5M1 66h5.5M1 72h5.5M1 78h5.5M1 84h5.5M1 90h5.5M23.5 54h5.5M23.5 60h5.5M23.5 66h5.5M23.5 72h5.5M23.5 78h5.5M23.5 84h5.5M23.5 90h5.5" stroke="#555" stroke-width=".9"/>
      <rect x="3" y="45" width="24" height="38" rx="3.2" fill="${c}" stroke="${SHADE}" stroke-width=".8"/>
      <rect x="3" y="76" width="24" height="8" rx="3" fill="rgba(0,0,0,.32)"/>
      <rect x="4.6" y="47.5" width="9" height="13" rx="1.6" fill="${GLASS}"/>
      <rect x="5.6" y="49" width="7" height="3.5" rx="1" fill="rgba(255,255,255,.25)"/>
      <path d="M17 64h8M17 67h8M17 70h8" stroke="rgba(0,0,0,.35)" stroke-width=".9"/>
      <rect x="14.2" y="9" width="6.2" height="42" rx="1.8" fill="${c}" stroke="${SHADE}" stroke-width=".8"/>
      <rect x="16.4" y="18" width="1.8" height="26" rx=".9" fill="#d9d9d9"/>
      <path d="M11 1.6h12.6v8.6H11z" fill="#3a3a3a"/><path d="M11.6 1.6v-1.4M14.4 1.6v-1.4M17.3 1.6v-1.4M20.2 1.6v-1.4M23 1.6v-1.4" stroke="#3a3a3a" stroke-width="1.1"/></svg>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="37" height="66" viewBox="0 0 37 66">
    <rect x="0.3" y="0.3" width="36.4" height="5.2" rx="1.2" fill="${c}" stroke="rgba(0,0,0,.45)" stroke-width=".8"/>
    <rect x="1.5" y="1.4" width="34" height="1.6" rx=".8" fill="rgba(255,255,255,.35)"/>
    <rect x="4" y="5" width="3" height="11" fill="#333"/><rect x="30" y="5" width="3" height="11" fill="#333"/>
    <rect x="2" y="12" width="8" height="48" rx="2.2" fill="#2b2b2b"/><rect x="27" y="12" width="8" height="48" rx="2.2" fill="#2b2b2b"/>
    <path d="M3 16h6M3 22h6M3 28h6M3 34h6M3 40h6M3 46h6M3 52h6M28 16h6M28 22h6M28 28h6M28 34h6M28 40h6M28 46h6M28 52h6" stroke="#555" stroke-width=".9"/>
    <rect x="9" y="13" width="19" height="45" rx="2.4" fill="${c}" stroke="${SHADE}" stroke-width=".8"/>
    <path d="M12 18h13M12 21h13M12 24h13" stroke="rgba(0,0,0,.3)" stroke-width=".8"/>
    <circle cx="14" cy="28.5" r="1.3" fill="#222"/>
    <rect x="11" y="34" width="15" height="14" rx="1.8" fill="${GLASS}"/>
    <rect x="12.2" y="35.4" width="12.6" height="3.4" rx="1" fill="rgba(255,255,255,.25)"/>
    <rect x="15" y="58" width="7" height="7" rx="1" fill="#333"/></svg>`;
}
function sideSvg(type, c) {
  if (type === 'truck') {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 40"><rect x="5" y="24" width="55" height="4" fill="#333"/>
      <path d="M4 25V13q0-3 3-3h8q2 0 3 3v12z" fill="${c}"/><rect x="6" y="12.5" width="7.5" height="5.5" rx="1" fill="#bcd2e6"/>
      <path d="M19 9h41l-3 15H19z" fill="${c}"/><path d="M21 9q19-9 37 0z" fill="#7b5e45"/>
      ${[11, 21, 43, 53].map((x) => `<circle cx="${x}" cy="31" r="5" fill="#222"/><circle cx="${x}" cy="31" r="1.8" fill="#9e9e9e"/>`).join('')}</svg>`;
  }
  if (type === 'excavator') {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 40"><rect x="5" y="29" width="34" height="8" rx="4" fill="#333"/>
      ${[10, 17, 24, 31].map((x) => `<circle cx="${x}" cy="33" r="2.2" fill="#666"/>`).join('')}
      <rect x="8" y="19" width="28" height="10" rx="2" fill="${c}"/><rect x="10" y="9" width="10" height="11" rx="1.5" fill="${c}"/>
      <rect x="11.5" y="10.5" width="7" height="5.5" rx="1" fill="#bcd2e6"/>
      <path d="M28 21L43 5L55 22" stroke="${c}" stroke-width="4.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M52 21h8l-2 8h-7z" fill="#3a3a3a"/></svg>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 40"><rect x="13" y="28" width="38" height="9" rx="4.5" fill="#333"/>
    ${[19, 26, 33, 40, 46].map((x) => `<circle cx="${x}" cy="32.5" r="2.2" fill="#666"/>`).join('')}
    <rect x="16" y="16" width="30" height="12" rx="2" fill="${c}"/><rect x="28" y="5" width="14" height="12" rx="1.5" fill="${c}"/>
    <rect x="30" y="7" width="10" height="5.5" rx="1" fill="#bcd2e6"/>
    <path d="M5 13h5v22H3z" fill="${c}" stroke="rgba(0,0,0,.35)" stroke-width=".8"/><path d="M10 26l7-4" stroke="#333" stroke-width="2.2"/>
    <path d="M51 27l6 6" stroke="#333" stroke-width="2.4"/></svg>`;
}

function buildMachines() {
  const md = DATA.machines;
  const all = new ol.source.Vector();
  md.days.forEach((d) => d.machines.forEach((m) => m.places.forEach((p) =>
    all.addFeature(new ol.Feature({ geometry: new ol.geom.Point([p.x, p.y]) })))));
  layers.mAll = new ol.layer.Vector({ source: all, visible: false, zIndex: 30,
    style: new S.Style({ image: new S.Circle({ radius: 3, fill: new S.Fill({ color: 'rgba(255,255,255,.55)' }),
      stroke: new S.Stroke({ color: 'rgba(31,56,100,.7)', width: 1 }) }) }) });
  layers.mRoutes = new ol.layer.Vector({ source: new ol.source.Vector(), visible: false, zIndex: 31,
    style: (f) => [new S.Style({ stroke: new S.Stroke({ color: 'rgba(0,0,0,.45)', width: 6 }) }),
      new S.Style({ stroke: new S.Stroke({ color: mColor(f.get('short')), width: 3.5, lineDash: f.get('shuttle') ? [12, 8] : undefined }) })] });
  // machine pictures: top view turned to the direction of travel; true size when zoomed in close
  const icons = {};
  layers.mMachines = new ol.layer.Vector({ source: new ol.source.Vector(), visible: false, zIndex: 32,
    style: (f, res) => {
      const k = f.get('short'), type = f.get('type'), t = TOP[type];
      if (!icons[k]) icons[k] = new S.Icon({ src: svgUrl(topSvg(type, mColor(k))), rotateWithView: true });
      const px = Math.max(38, Math.min(420, t.len / res));
      icons[k].setScale(px / t.px);
      icons[k].setRotation(f.get('heading') || 0);
      const st = [new S.Style({ image: icons[k] })];
      if (res > 0.35) {
        st.push(new S.Style({ text: new S.Text({ text: k, offsetY: px / 2 + 11, font: '700 11px "Segoe UI", system-ui, sans-serif',
          fill: new S.Fill({ color: '#fff' }), stroke: new S.Stroke({ color: mColor(k), width: 4 }) }) }));
      }
      return st;
    } });
  [layers.mAll, layers.mRoutes, layers.mMachines].forEach((l) => map.addLayer(l));

  const first = md.days[0].date, last = md.days[md.days.length - 1].date;
  const range = `${shortDate(first)} – ${new Date(last + 'T12:00:00').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}`;
  $('#mSummary').innerHTML =
    `<div class="kpi"><div class="v">${md.machine_days}</div><div class="l">machine-days with marked positions</div></div>` +
    `<div class="kpi"><div class="v">${fmt(md.hours, 0)} h</div><div class="l">machine-hours logged</div></div>` +
    `<div class="kpi wide"><div class="v">${range}</div><div class="l">${md.days.length} working days · ${md.machines.length} machines · PO ${md.po}</div></div>`;
  const sl = $('#mSlider');
  sl.max = md.days.length - 1;
  sl.addEventListener('input', () => { stopPlay(); showDay(+sl.value); });
  $('#mPrev').addEventListener('click', () => { stopPlay(); showDay(Math.max(0, M.day - 1)); });
  $('#mNext').addEventListener('click', () => { stopPlay(); showDay(Math.min(md.days.length - 1, M.day + 1)); });
  $('#mPlay').addEventListener('click', () => (M.play ? stopPlay() : startPlay()));
}

function machinesActive(on) {
  if (!DATA.machines) return;
  M.active = on;
  ['mAll', 'mRoutes', 'mMachines'].forEach((k) => layers[k].setVisible(on));
  if (!on) { stopPlay(); cancelAnimationFrame(M.anim); M.anim = null; return; }
  closePopup();
  if (!M.fitted) {
    map.getView().fit(layers.mAll.getSource().getExtent(), { padding: [60, 60, 60, 60], duration: 600 });
    M.fitted = true;
  }
  showDay(M.day, true);
}

function startPlay() {
  const n = DATA.machines.days.length;
  if (M.day >= n - 1) showDay(0);
  $('#mPlay').textContent = '❚❚ Pause';
  M.play = setInterval(() => {
    if (M.day >= n - 1) { stopPlay(); return; }
    showDay(M.day + 1);
  }, 5200);
}

function stopPlay() {
  if (M.play) clearInterval(M.play);
  M.play = null;
  $('#mPlay').textContent = '▶ Play';
}

// direction of travel at fraction t of a line (map heading, clockwise from north)
function headingAt(line, t, back) {
  const a = line.getCoordinateAt(Math.max(0, Math.min(1, t - 0.004))), b = line.getCoordinateAt(Math.max(0, Math.min(1, t + 0.004)));
  if (a[0] === b[0] && a[1] === b[1]) return null;
  const h = Math.PI / 2 - Math.atan2(b[1] - a[1], b[0] - a[0]);
  return back ? h + Math.PI : h;
}

function showDay(i, instant) {
  const md = DATA.machines;
  const day = md.days[i];
  const next = i === M.day + 1;          // only a step to the next day drives there; other jumps place the machines directly
  M.day = i;
  $('#mSlider').value = i;
  const dt = new Date(day.date + 'T12:00:00');
  $('#mDay').innerHTML = `${dt.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })}
    <small>Day ${i + 1} of ${md.days.length} · ${day.machines.length} machines · ${fmt(day.machines.reduce((s, m) => s + (m.hours || 0), 0), 0)} machine-hours</small>`;
  $('#mList').innerHTML = day.machines.map((m) => {
    const where = [...new Set(m.places.map((p) => p.where))].join(' → ');
    const work = [...new Set(m.places.map((p) => p.work).filter(Boolean))].join('; ');
    const route = m.path_m > 30 ? ` · ${fmt(m.path_m / 1000, 1)} km along the roads` : '';
    return `<div class="mrow" data-m="${m.short}"><div class="mpic"><img src="${svgUrl(sideSvg(mType(m.name), mColor(m.short)))}" alt=""><span style="background:${mColor(m.short)}">${m.short}</span></div>
      <div class="t"><b>${m.name}</b><span>${where}${m.shuttle ? ` · all-day shuttle${m.shuttle_km ? `, ${fmt(m.shuttle_km, 1)} km per round trip (logged)` : ''}` : route}</span>
      ${work ? `<br><span>${work}</span>` : ''}</div><div class="n">${m.hours ? fmt(m.hours, 0) + ' h' : ''}</div></div>`;
  }).join('');
  document.querySelectorAll('.mrow').forEach((r) => r.addEventListener('click', () => {
    const f = M.markers[r.dataset.m];
    if (f) map.getView().animate({ center: f.getGeometry().getCoordinates(), resolution: Math.min(map.getView().getResolution(), 0.25), duration: 600 });
  }));
  if (!M.active) return;

  // the day's routes along the roads (dashed: all-day shuttle back and forth)
  const rs = layers.mRoutes.getSource();
  rs.clear();
  M.routes = [];
  day.machines.forEach((m) => {
    if (m.path && m.path.length > 1) {
      const line = new ol.geom.LineString(m.path);
      rs.addFeature(new ol.Feature({ geometry: line, short: m.short, shuttle: m.shuttle }));
      if (m.shuttle) {
        // trucks loading at the same spot take turns: each waits half a trip after the one before
        const p0 = m.path[0];
        const queue = M.routes.filter((r) => Math.hypot(r.start[0] - p0[0], r.start[1] - p0[1]) < 60).length;
        M.routes.push({ short: m.short, line, start: p0, wait: 0.5 * queue });
      }
    }
  });
  // markers: drive from yesterday's place to today's along the roads (route computed at build time)
  const ms = layers.mMachines.getSource();
  const arrive = {}, to = {};
  day.machines.forEach((m) => {
    to[m.short] = [m.places[0].x, m.places[0].y];
    if (!instant && next && m.arrive && m.arrive.length > 1 && M.markers[m.short]) arrive[m.short] = new ol.geom.LineString(m.arrive);
  });
  Object.keys(M.markers).forEach((k) => { if (!(k in to)) { ms.removeFeature(M.markers[k]); delete M.markers[k]; } });
  day.machines.forEach((m) => {
    if (!M.markers[m.short]) {
      M.markers[m.short] = new ol.Feature({ geometry: new ol.geom.Point(to[m.short]), short: m.short, type: mType(m.name), heading: 0 });
      ms.addFeature(M.markers[m.short]);
    }
  });
  const t0 = performance.now(), DRIVE = instant ? 1 : 2400;
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
  cancelAnimationFrame(M.anim);
  const frame = (now) => {
    const t = Math.min(1, (now - t0) / DRIVE);
    Object.keys(to).forEach((k) => {
      const f = M.markers[k];
      let c = to[k], h = null;
      if (t < 1 && arrive[k]) {
        const e = ease(t);
        c = arrive[k].getCoordinateAt(e);
        h = headingAt(arrive[k], e, false);
      } else if (t >= 1) {
        // after arriving: shuttling trucks drive back and forth along the day's road route
        const r = M.routes.find((x) => x.short === k);
        if (r) {
          const len = r.line.getLength();
          const period = Math.max(6000, Math.min(16000, len * 5));      // ms for one way, longer routes take longer
          const phase = Math.max(0, (now - t0 - DRIVE) / period - r.wait) % 2;
          const back = phase >= 1, s = back ? 2 - phase : phase;
          c = r.line.getCoordinateAt(s);
          h = headingAt(r.line, s, back);
        }
      }
      f.getGeometry().setCoordinates(c);
      if (h !== null) f.set('heading', h, true);
    });
    layers.mMachines.changed();
    M.anim = M.active ? requestAnimationFrame(frame) : null;
  };
  M.anim = requestAnimationFrame(frame);
}

function setLayer(key, on) {
  if (!layers[key]) return;
  layers[key].setVisible(on);
  const cb = document.querySelector(`[data-layer="${key}"]`);
  if (cb) cb.checked = on;
}

function renderAreas(mode) {
  const chip = (st) => `<span class="chip ${st}">${{ surveyed: 'surveyed', partly: 'partly', pending: 'pending', noimage: 'image pending' }[st]}</span>`;
  const head = { heaps: ['Heaps', 'm³'], grass: ['Cut ha', '% cut'], machines: ['Machine-days', 'Last day'] }[mode];
  const cols = (a) => {
    if (mode === 'heaps') {
      return [a.soil_n + a.sand_n || '', (a.soil_n + a.sand_n ? fmt(a.soil_m3 + a.sand_m3, 1) : '') +
        (a.soil_novol ? `<br><span class="hint">+${a.soil_novol} pending</span>` : '')];
    }
    if (mode === 'grass') {
      return a.cut_m2 ? [fmt(a.cut_m2 / 1e4, 2), `${fmt(100 * a.cut_m2 / a.fenced_m2, 0)}%`] : ['', ''];
    }
    return a.machine_days ? [a.machine_days, shortDate(a.machine_last)] : ['', ''];
  };
  $('#areaTable').innerHTML = `<tr><th>Area</th><th class="n">${DATA.areas.some((a) => a.drawn) ? 'Area ha' : 'Fenced ha'}</th><th>Survey</th><th class="n">${head[0]}</th><th class="n">${head[1]}</th></tr>` +
    DATA.areas.map((a) => {
      const [c1, c2] = cols(a);
      return `<tr class="click" data-area="${a.id}"><td><b>${a.id}</b><br><span class="hint">${a.mv.join(', ')}</span></td>
      <td class="n">${fmt(a.fenced_m2 / 1e4, 2)}</td><td>${chip(a.status)}<br><span class="hint">${shortDate(a.date)}</span></td>
      <td class="n">${c1}</td><td class="n">${c2}</td></tr>`;
    }).join('') + areaTotals(mode);
  document.querySelectorAll('[data-area]').forEach((tr) => tr.addEventListener('click', () => {
    const f = areaSource.getFeatures().find((x) => x.get('id') === tr.dataset.area);
    zoomTo(f, 0.3);
    showPopup(ol.extent.getCenter(f.getGeometry().getExtent()), areaHtml(f.getProperties()), f);
  }));
}

function areaTotals(mode) {
  const sum = (k) => DATA.areas.reduce((s, a) => s + (a[k] || 0), 0);
  if (mode === 'grass' && DATA.grass_cut) {
    return `<tr><td colspan="3"><b>Total ground marked as cut</b><br><span class="hint">a strip marked twice counts once</span></td>
      <td class="n"><b>${fmt(DATA.grass_cut.covered_m2 / 1e4, 2)}</b></td><td></td></tr>`;
  }
  if (mode === 'machines' && DATA.machines) {
    return `<tr><td colspan="3"><b>All machine-days</b><br><span class="hint">incl. pickup points outside the fences</span></td>
      <td class="n"><b>${DATA.machines.machine_days}</b></td><td></td></tr>`;
  }
  return `<tr><td colspan="3"><b>Total</b></td><td class="n"><b>${sum('soil_n') + sum('sand_n')}</b></td><td class="n"><b>${fmt(sum('soil_m3') + sum('sand_m3'), 1)}</b></td></tr>`;
}

function filteredHeaps() {
  const a = $('#heapArea').value, t = $('#heapType').value;
  return heapSource.getFeatures()
    .filter((f) => (!a || f.get('area') === a) && (!t || f.get('type') === t))
    .sort((x, y) => (y.get('volume_m3') ?? -1e9) - (x.get('volume_m3') ?? -1e9));
}

function renderHeaps() {
  const list = filteredHeaps();
  const vol = list.reduce((s, f) => s + (f.get('volume_m3') || 0), 0);
  const pend = list.filter((f) => f.get('volume_m3') == null).length;
  $('#heapTotals').innerHTML = `<b>${list.length}</b> heaps · net volume <b>${fmt(vol, 1)} m³</b> · footprint <b>${fmt(list.reduce((s, f) => s + f.get('area_m2'), 0), 0)} m²</b>` +
    (pend ? `<br><span class="hint">${pend} heaps without a volume yet (survey data pending)</span>` : '');
  $('#heapTable').innerHTML = `<tr><th>Heap</th><th>Type</th><th class="n">m²</th><th class="n">m³</th></tr>` +
    list.map((f) => `<tr class="click" data-heap="${f.get('id')}"><td><b>${f.get('id')}</b></td><td>${f.get('type')}${f.get('outside_fence') ? '<br><span class="hint">outside fence</span>' : ''}</td>
      <td class="n">${fmt(f.get('area_m2'), 1)}</td><td class="n">${f.get('volume_m3') == null ? '–' : fmt(f.get('volume_m3'), 2)}</td></tr>`).join('');
  document.querySelectorAll('[data-heap]').forEach((tr) => tr.addEventListener('click', () => {
    const f = heapSource.getFeatures().find((x) => x.get('id') === tr.dataset.heap);
    zoomTo(f, 0.02);
    const c = f.getGeometry().getInteriorPoint().getCoordinates();
    setTimeout(() => showPopup([c[0], c[1]], heapHtml(f.getProperties()), f), 520);
    if (window.matchMedia('(max-width: 760px)').matches) $('#panel').scrollTop = 0;
  }));
}

function downloadCsv() {
  const cols = ['id', 'area', 'type', 'area_m2', 'volume_m3', 'cut_m3', 'fill_m3', 'survey_date', 'outside_fence', 'name', 'source'];
  const rows = filteredHeaps().map((f) => cols.map((c) => {
    const v = f.get(c);
    return v == null ? '' : typeof v === 'string' ? `"${v.replace(/"/g, '""')}"` : v;
  }).join(';'));
  const blob = new Blob(['﻿' + [cols.join(';'), ...rows].join('\r\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'szihalom_soil_heaps.csv'; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function buildProof() {
  const s = DATA.summary;
  const fenceRows = DATA.areas.filter((a) => a.drone_fence_m2).map((a) => {
    const d = Math.round(10000 * (a.drone_fence_m2 / a.fenced_m2 - 1)) / 100;      // 2 decimals, no "-0.00"
    return `<tr><td><b>${a.id}</b></td><td class="n">${fmt(a.fenced_m2)}</td><td class="n">${fmt(a.drone_fence_m2)}</td><td class="n">${d > 0 ? '+' : ''}${fmt(d || 0, 2)}%</td></tr>`;
  }).join('');
  const imgRows = DATA.images.map((im) => `<tr><td>${im.name}<br><code title="SHA-256">${im.sha256 || ''}</code></td><td>${im.date !== '0' ? im.date : '–'}</td><td class="n">${im.px_cm}</td></tr>`).join('');
  $('#proof').innerHTML = `
    <h3>How the survey was made</h3>
    <ol>
      <li>The site was photographed by drone on ${datesInWords(s.dates)} and the photos were stitched into orthophotos (true-to-scale aerial images) of ${s.px_cm[0]}–${s.px_cm[1]} cm per pixel, in WGS 84 / UTM zone 34N.</li>
      <li>On this map each place shows the image flown for that area. <b>At the closest zoom you see the original survey pixels, unchanged</b> (stored lossless); only zoomed-out views use reduced copies.</li>
      <li>Soil heaps were outlined by the survey company on the images and measured on the 3D surface model: the volume is the material above a base surface drawn from the heap's edge (cut), less any hollow below it (fill).</li>
      <li>Areas are numbered as in the design drawing <i>${s.drawing}</i>, by their MV stations.</li>
    </ol>
    <h3>Check 1 · Drone survey vs the design drawing</h3>
    <p>The fence lines measured on the drone images against the fences of the design drawing. Matching within a fraction of a percent shows the images are correctly placed and to scale.</p>
    <table class="grid"><tr><th>Area</th><th class="n">Drawing m²</th><th class="n">Drone m²</th><th class="n">Diff.</th></tr>${fenceRows}</table>
    <p class="hint">Area P2.2: the survey company's fence line leaves out the south corner with the battery storage yard, hence the larger difference.</p>
    <h3>Check 2 · Independent re-measurement of the heaps</h3>
    <p>We recomputed the footprint of all ${s.heap_area_check.n} heaps from their outlines: the median difference to the survey company's figure is ${fmt(s.heap_area_check.median_pct, 2)}% (largest ${fmt(s.heap_area_check.max_pct, 1)}%, on the smallest heaps). Use the measuring tool to check any heap yourself.</p>
    ${DATA.grass_cut ? `<h3>Grass cut so far (separate layer)</h3>
    <p>Areas our crew marked as cut on site in our grass-cutting app, ${datesInWords(DATA.grass_cut.dates)}:
    ${DATA.grass_cut.n} areas covering <b>${fmt(DATA.grass_cut.covered_m2 / 1e4, 2)} ha</b> of ground (a strip marked twice counts once).
    State of ${new Date(DATA.grass_cut.taken).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}. Switch it on under Overview → Map layers.</p>` : ''}
    <h3>Check 3 · The original files</h3>
    <p>Each image is identified by its SHA-256 fingerprint; anyone holding the survey files can confirm they are the same (Windows: <code>certutil -hashfile file SHA256</code>).</p>
    <table class="grid"><tr><th>Image</th><th>Flight</th><th class="n">cm/px</th></tr>${imgRows}</table>
    <p class="hint">Prepared by Sky Tech Line Kft. · data version ${DATA.generated}</p>`;
}
