const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));

const VERDICT = {
  affected_exposed: {cls: 'bad', label: 'Affected · reachable from internet'},
  declared_exposed: {cls: 'bad', label: 'Python pin · reachable from internet'},
  affected_internal_declared: {cls: 'warn', label: 'Affected · internal only'},
  affected_exposure_unknown: {cls: 'warn', label: 'Affected · exposure unknown'},
  declared_exposure_unknown: {cls: 'warn', label: 'Python pin · exposure unknown'},
  insufficient_evidence: {cls: 'warn', label: 'Insufficient evidence'},
  not_affected_version: {cls: 'good', label: 'Version not affected'},
  not_present: {cls: 'good', label: 'Package not present'},
  not_applicable: {cls: 'skip', label: 'Different ecosystem'},
};
const ICON = {bad: '✕', warn: '!', good: '✓', skip: '–'};
const RANK = {bad: 0, warn: 1, good: 2, skip: 3};
const TOOL_DESC = {
  scan_public_repo: 'Fetched the latest commit, loaded lockfiles and manifests into FalkorDB, matched the advisory ranges',
  exposure_evidence: 'Walked Internet → ingress → service calls from the Kubernetes manifests',
  service_bridges: 'Ran algo.betweenness over the service call graph',
  advisory_fanout: 'Counted every project the advisory reaches across the graph',
};
const HISTORY_KEY = 'blastradius.investigations';

let current = null;   // {id, repo, advisory, question, at, data}
let cy = null;
let toastTimer;

// ---------- utilities ----------
function toast(message, error = false) {
  const el = $('toast');
  el.textContent = message;
  el.classList.toggle('error', error);
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 7000);
}

async function api(path, options = {}) {
  const res = await fetch(path, {...options, headers: {'Content-Type': 'application/json', ...(options.headers || {})}});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

function projectName(id) {
  const sub = id.includes('::') ? id.split('::')[1] : id.split('/').pop();
  return sub.replace(/#.*$/, '').split('/').filter(Boolean).pop() || id;
}
function projectSub(result, scan) {
  const sub = result.repo.includes('::') ? result.repo.split('::')[1].replace(/#.*$/, '') : 'repository root';
  const manager = result.repo.includes('#pip') ? 'pip' : (scan.source?.managers?.length === 1 ? scan.source.managers[0] : 'npm');
  return `${sub} · ${manager}`;
}
const vclass = (r) => (VERDICT[r.verdict] || {cls: 'warn'}).cls;
const timeAgo = (iso) => {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
};
function uniqueFixes(result) {
  const seen = new Set();
  return (result.fix_candidates || []).filter(f => {
    const k = `${f.package}|${f.target || f.first_patched}|${f.strategy}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
}
const fixable = (r) => r.fix_supported && uniqueFixes(r).find(f => f.strategy === 'lockfile_refresh');

// ---------- history (per-browser convenience only) ----------
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}
function saveHistory(items) {
  for (let n = items.length; n > 0; n--) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, n))); return; } catch { /* quota: keep fewer */ }
  }
}
function remember(entry) {
  const items = loadHistory().filter(i => !(i.repo === entry.repo && i.advisory === entry.advisory));
  items.unshift(entry);
  saveHistory(items.slice(0, 8));
  renderHistory();
}
function renderHistory() {
  const items = loadHistory();
  $('history').innerHTML = items.length ? items.map(i => {
    const res = i.data.evidence.scan_public_repo.results;
    const bad = res.filter(r => vclass(r) === 'bad').length, warn = res.filter(r => vclass(r) === 'warn').length;
    const icon = bad ? '<span class="s-bad">✕</span>' : warn ? '<span class="s-warn">!</span>' : '<span class="s-good">✓</span>';
    return `<li><button type="button" data-history="${esc(i.id)}" class="${current?.id === i.id ? 'active' : ''}">
      <div class="side-item-top">${icon} ${esc(i.advisory)}</div>
      <div class="side-item-sub">${esc(i.repo)} · ${timeAgo(i.at)}</div></button></li>`;
  }).join('') : '<li class="side-empty">None yet</li>';
}

async function refreshSidebar() {
  try {
    const [health, repos] = await Promise.all([api('/api/health'), api('/api/repos')]);
    const ok = health.database === 'connected';
    $('conn').querySelector('.dot').className = `dot ${ok ? 'ok' : 'bad'}`;
    $('conn-label').textContent = ok ? 'FalkorDB connected' : 'FalkorDB unavailable';
    const groups = {};
    for (const r of repos) {
      const base = r.repo.split('::')[0];
      (groups[base] ||= new Set()).add(r.manager || 'npm');
      groups[base].count = (groups[base].count || 0) + 1;
    }
    const names = Object.keys(groups).sort();
    $('repo-count').textContent = names.length || '';
    $('repos').innerHTML = names.length ? names.map(n => `<li><button type="button" data-repo="${esc(n)}">
      <div class="side-item-top">${esc(n)}</div>
      <div class="side-item-sub">${groups[n].count} project${groups[n].count === 1 ? '' : 's'} · ${[...groups[n]].join(', ')}</div></button></li>`).join('')
      : '<li class="side-empty">None yet</li>';
  } catch {
    $('conn').querySelector('.dot').className = 'dot bad';
    $('conn-label').textContent = 'FalkorDB unavailable';
  }
}

// ---------- views ----------
function show(view) {
  for (const v of ['new', 'running', 'result']) $(`view-${v}`).classList.toggle('hidden', v !== view);
}
function crumbs(parts) {
  $('crumbs').innerHTML = parts.map((p, i) => i === parts.length - 1 ? `<b>${esc(p)}</b>` : `<span>${esc(p)}</span>`).join('<span class="sep">/</span>');
}
function newInvestigation(prefillRepo = '') {
  current = null;
  renderHistory();
  crumbs(['Investigations', 'New']);
  if (prefillRepo) $('f-repo').value = prefillRepo;
  show('new');
  (prefillRepo ? $('f-adv') : $('f-repo')).focus();
  history.replaceState(null, '', location.pathname);
}

async function investigate(repo, advisory, question) {
  question = question || `What is the blast radius of ${advisory} in ${repo}?`;
  crumbs(['Investigations', repo, advisory]);
  $('running-title').textContent = `Investigating ${advisory} in ${repo}…`;
  show('running');
  $('submit').disabled = true;
  try {
    const data = await api('/api/agent', {method: 'POST', body: JSON.stringify({repo, advisory, question})});
    const entry = {id: `${Date.now()}`, repo, advisory: data.evidence.scan_public_repo.advisory.id, question, at: new Date().toISOString(), data};
    remember(entry);
    openInvestigation(entry);
    refreshSidebar();
  } catch (err) {
    toast(err.message, true);
    show('new');
  } finally {
    $('submit').disabled = false;
  }
}

function openInvestigation(entry) {
  current = entry;
  renderHistory();
  history.replaceState(null, '', `#inv=${entry.id}`);
  const scan = entry.data.evidence.scan_public_repo;
  crumbs(['Investigations', scan.source?.repo || entry.repo, scan.advisory.id]);
  renderHeader(entry, scan);
  renderVerdict(entry, scan);
  renderOverview(scan);
  renderAgent(entry);
  renderFiles(scan);
  renderHistoryTab(scan);
  selectTab('overview');
  show('result');
  window.scrollTo({top: 0});
}

// ---------- header + verdict ----------
function renderHeader(entry, scan) {
  const a = scan.advisory, src = scan.source || {}, risk = scan.risk_signals || {};
  $('r-title').textContent = a.summary || a.id;
  $('r-adv-link').textContent = a.id;
  $('r-adv-link').href = a.url || '#';
  const dep = src.deployment;
  $('r-meta').innerHTML = [
    `<b>${esc(src.repo || entry.repo)}</b> @ <code>${esc((src.sha || '').slice(0, 7))}</code>`,
    `scanned ${esc(timeAgo(src.scanned_at || entry.at))}`,
    `${src.projects ?? '?'} project${src.projects === 1 ? '' : 's'} · ${src.dependencies ?? '?'} dependencies`,
    dep ? `${dep.workloads} workloads · ${dep.public_routes} public route${dep.public_routes === 1 ? '' : 's'}` : 'no deployment manifests',
  ].join(' · ');
  const sev = (a.severity || 'unknown').toLowerCase();
  const labels = [
    `<span class="label ${['critical', 'high'].includes(sev) ? 'danger' : sev === 'moderate' || sev === 'medium' ? 'attention' : ''}">Severity: ${esc(sev)}</span>`,
    risk.kev === true ? '<span class="label danger">CISA KEV: actively exploited</span>'
      : risk.kev === false ? '<span class="label">Not in CISA KEV</span>' : '<span class="label">KEV unknown</span>',
    risk.epss != null ? `<span class="label ${risk.epss_percentile >= 0.9 ? 'danger' : ''}">EPSS ${(risk.epss * 100).toFixed(2)}% · ${Math.round((risk.epss_percentile || 0) * 100)}th pct</span>` : '<span class="label">EPSS unknown</span>',
  ];
  const fan = entry.data.evidence.advisory_fanout;
  if (fan) labels.push(`<span class="label accent">Graph fan-out: ${fan.count} project${fan.count === 1 ? '' : 's'}</span>`);
  $('r-labels').innerHTML = labels.join('');
}

function renderVerdict(entry, scan) {
  const rel = scan.results.filter(r => r.verdict !== 'not_applicable');
  const skipped = scan.results.length - rel.length;
  const affected = rel.filter(r => r.vulnerable_paths?.length);
  const exposed = rel.filter(r => vclass(r) === 'bad');
  const unknown = affected.filter(r => /exposure_unknown/.test(r.verdict)).length;
  const fixes = affected.filter(fixable).length;
  let cls, icon, title;
  if (exposed.length) {
    cls = 'bad'; icon = '✕';
    title = `${affected.length} of ${rel.length} project${rel.length === 1 ? '' : 's'} affected · ${exposed.length} reachable from the internet`;
  } else if (affected.length) {
    cls = 'warn'; icon = '!';
    title = `${affected.length} of ${rel.length} project${rel.length === 1 ? '' : 's'} affected · none confirmed reachable from the internet`;
  } else {
    cls = 'good'; icon = '✓';
    title = `Not affected · no vulnerable dependency path in ${rel.length} project${rel.length === 1 ? '' : 's'}`;
  }
  const lines = [];
  if (exposed.length) lines.push(`Reachable: ${exposed.map(r => projectName(r.repo)).join(', ')}`);
  if (unknown) lines.push(`${unknown} with no deployment evidence (exposure unknown)`);
  if (affected.length) lines.push(fixes ? `Fix candidate for ${fixes} project${fixes === 1 ? '' : 's'}, verified in Files changed` : 'No automatic fix: manual review');
  if (skipped) lines.push(`${skipped} project${skipped === 1 ? '' : 's'} in another ecosystem skipped`);
  const source = entry.data.summary_source === 'deterministic' ? 'rule-based summary' : esc(entry.data.summary_source || 'agent');
  $('r-verdict').className = `verdict ${cls}`;
  $('r-verdict').innerHTML = `<div class="verdict-icon">${icon}</div><div>
    <h2>${esc(title)}</h2><p>${esc(lines.join(' · '))}</p>
    ${entry.data.summary ? `<div class="agent-says"><span class="who">Agent · ${source}</span><br>${esc(entry.data.summary)}</div>` : ''}
  </div>`;
}

// ---------- overview: checks list ----------
function exposureLine(r) {
  const svc = (r.services || []).find(s => s.exposure_path?.length) || (r.services || [])[0];
  if (!svc) return '<span class="muted">No deployment evidence · exposure unknown</span>';
  if (svc.exposure === 'public' && svc.exposure_path?.length) {
    const hops = svc.exposure_path.filter(n => n.name).map(n => n.name);
    const via = hops.slice(0, -1);
    return `Reachable from the internet${via.length ? ` via ${esc(via.join(' → '))}` : ''}`;
  }
  if (svc.exposure === 'internal') return 'Internal only (declared)';
  return `<span class="muted">Exposure ${esc(svc.exposure || 'unknown')}</span>`;
}

function treeHtml(path, r, vp) {
  const items = path.slice(1).map((name, i, arr) => i === arr.length - 1
    ? `<li class="vuln">${esc(name)} <span class="ver">${esc(vp.version)} · affected ${esc(vp.range)}</span></li>`
    : `<li>${esc(name)}</li>`).join('');
  return `<ul class="tree"><li class="root">${esc(projectName(r.repo))}</li>${items}</ul>`;
}

function stepsHtml(svc) {
  const nodes = svc.exposure_path;
  return `<ul class="steps">${nodes.map((n, i) => {
    const label = n.id === 'internet' ? 'Internet' : n.kind ? `${n.kind} · ${n.url || ''}` : n.name || n.id;
    const cls = i === 0 ? 'entry' : i === nodes.length - 1 ? 'target' : '';
    return `<li class="${cls}">${esc(label)}${n.evidence ? `<span class="ev">${esc(n.evidence)}</span>` : ''}</li>`;
  }).join('')}</ul>`;
}

function moduleHtml(r) {
  return (r.module_evidence || []).map(e => {
    if (e.status === 'unavailable') return `<p class="muted small">Module check: source of ${esc(e.parent)} could not be inspected; no conclusion drawn.</p>`;
    const where = e.file ? ` (<code>${esc(e.file)}:${esc(e.line)}</code>)` : '';
    if (e.status === 'runtime_static_path') return `<div class="callout danger"><b>Loaded at runtime:</b> ${esc(e.parent)}'s main entry imports it${where}.</div>`;
    if (e.status === 'cli_only_static_path') return `<div class="callout success"><b>Only the CLI imports it:</b> ${esc(e.parent)}@${esc(e.parent_version)} has no static path from its main entry; the import is in its CLI${where}. <span class="muted">${esc(e.scope)}</span></div>`;
    return `<div class="callout success"><b>No static import path</b> from ${esc(e.parent)}'s main or CLI. <span class="muted">${esc(e.scope)}</span></div>`;
  }).join('');
}

function checkHtml(r, scan, idx) {
  const c = vclass(r), affected = r.vulnerable_paths?.length;
  const paths = [...(r.vulnerable_paths || [])].sort((a, b) => a.path.length - b.path.length);
  const vp = paths[0];
  const fixes = uniqueFixes(r);
  const fixText = fixes.length ? fixes.map(f => f.strategy === 'lockfile_refresh'
    ? `${esc(f.package)} ${esc(f.before || '')} → ${esc(f.target)} <span class="muted">(fits ${esc(f.parent_name)} ${esc(f.declared_range)})</span>`
    : `${esc(f.package)} → ${esc(f.first_patched)} <span class="muted">(manual review)</span>`).join('<br>') : '<span class="muted">No patched version in the advisory</span>';
  const why = affected
    ? `${exposureLine(r)}<div class="muted">${esc(vp.package)} ${esc(vp.version)} · ${vp.path.length - 1} hop${vp.path.length === 2 ? '' : 's'} · ${paths.length} path${paths.length === 1 ? '' : 's'}${fixes[0] ? ` · fix → ${esc(fixes[0].target || fixes[0].first_patched)}` : ''}</div>`
    : `<span class="muted">${esc(r.explanation)}</span>`;
  const priority = r.priority && r.priority !== 'None' ? r.priority : null;
  const chip = affected ? `<span class="label ${c === 'bad' ? 'danger' : 'attention'} check-chip">${esc(priority && priority.startsWith('P') ? `${priority} provisional` : (VERDICT[r.verdict] || {}).label || r.verdict)}</span>`
    : `<span class="label success check-chip">${esc((VERDICT[r.verdict] || {}).label || r.verdict)}</span>`;
  const svcWithPath = (r.services || []).find(s => s.exposure_path?.length);
  const decision = r.prior_decisions?.[0];
  const detail = affected ? `<div class="check-detail">
      <div class="detail-grid">
        <div><div class="detail-title">Dependency path · shortest of ${paths.length}</div>${treeHtml(vp.path, r, vp)}
          ${paths.length > 1 ? `<details class="raw more-paths"><summary>${paths.length - 1} more path${paths.length === 2 ? '' : 's'}</summary>${paths.slice(1).map(p => treeHtml(p.path, r, p)).join('<br>')}</details>` : ''}</div>
        <div><div class="detail-title">Exposure path · from deployment manifests</div>
          ${svcWithPath ? stepsHtml(svcWithPath) : '<div class="callout attention">No deployment evidence for this project, so exposure is unknown. BlastRadius does not guess.</div>'}</div>
      </div>
      ${moduleHtml(r)}
      <dl class="facts">
        <dt>Owner</dt><dd>${esc(r.owner || 'unknown (no CODEOWNERS)')}</dd>
        <dt>Fix</dt><dd>${fixText}</dd>
        <dt>Why this priority</dt><dd>${esc((r.priority_reasons || []).join(' · ') || r.explanation)}</dd>
        <dt>Last decision</dt><dd>${decision ? `<b>${esc(decision.verdict)}</b> · ${esc(decision.reason)} ${decision.stale ? '<span class="label attention">re-review: repository changed</span>' : ''}` : '<span class="muted">none recorded</span>'}</dd>
      </dl>
      <div class="row-actions">
        ${fixable(r) ? `<button class="btn btn-sm btn-primary" data-goto-fix="${idx}" type="button">Review fix</button>` : ''}
        <button class="btn btn-sm" data-decision="${idx}" type="button">Record decision</button>
        ${r.provenance_supported ? `<button class="btn btn-sm" data-provenance="${idx}" type="button">Who introduced it?</button>` : ''}
      </div>
      <div class="prov" id="prov-${idx}"></div>
    </div>` : '';
  return `<div class="check" data-idx="${idx}">
    <div class="check-row ${affected ? '' : 'static'}" ${affected ? 'data-toggle' : ''}>
      <span class="s-icon s-${c}">${ICON[c]}</span>
      <div style="min-width:0"><div class="check-name">${esc(projectName(r.repo))}</div><div class="check-sub">${esc(projectSub(r, scan))}</div></div>
      <div class="check-why">${why}</div>
      ${chip}
      <span class="chev">${affected ? '›' : ''}</span>
    </div>${detail}</div>`;
}

function renderOverview(scan) {
  const rows = scan.results.map((r, idx) => ({r, idx}));
  const rel = rows.filter(x => x.r.verdict !== 'not_applicable').sort((a, b) => RANK[vclass(a.r)] - RANK[vclass(b.r)]);
  const skip = rows.filter(x => x.r.verdict === 'not_applicable');
  const bad = rel.filter(x => vclass(x.r) === 'bad').length;
  $('c-overview').textContent = rel.length;
  const skipRow = skip.length ? `<div class="check"><div class="check-row static">
      <span class="s-icon s-skip">–</span>
      <div><div class="check-name">${skip.length} project${skip.length === 1 ? '' : 's'} skipped</div><div class="check-sub">different package ecosystem</div></div>
      <div class="check-why muted">${esc(skip.map(x => projectName(x.r.repo)).join(', '))}</div><span></span><span></span></div></div>` : '';
  $('tab-overview').innerHTML = `<div class="box checks">
    <div class="box-header"><span>${rel.length} project${rel.length === 1 ? '' : 's'} checked · ${bad} reachable from the internet</span><span class="muted small">Click a row for the proof</span></div>
    ${rel.map(x => checkHtml(x.r, scan, x.idx)).join('')}${skipRow}</div>`;
  const first = $('tab-overview').querySelector('.check [data-toggle]');
  if (first) first.parentElement.classList.add('open');
}

// ---------- blast radius graph ----------
const ROW_H = 40, LANE_W = 300;

/* One vertical lane per affected project: exposure path, then the project, then its
   shortest dependency path. Nodes shared by lanes (Internet, ingress, frontend, the
   vulnerable package, the advisory) are centred over the lanes that use them. */
function graphElements(entry) {
  const scan = entry.data.evidence.scan_public_repo;
  const bridges = Object.fromEntries((entry.data.evidence.service_bridges?.services || []).map(s => [s.service, s.betweenness]));
  const nodes = new Map(), edges = new Map(), lanesOf = new Map(), depthOf = new Map();
  const node = (id, label, kind, lane, depth, extra = {}) => {
    if (!nodes.has(id)) nodes.set(id, {data: {id, label, kind, ...extra}});
    (lanesOf.get(id) || lanesOf.set(id, new Set()).get(id)).add(lane);
    depthOf.set(id, Math.max(depthOf.get(id) ?? 0, depth));
  };
  const edge = (s, t, kind) => edges.set(`${s}>${t}`, {data: {id: `${s}>${t}`, source: s, target: t, kind}});
  const affected = scan.results.filter(x => x.vulnerable_paths?.length);
  const exposureLen = Math.max(0, ...affected.map(r => (r.services || []).find(s => s.exposure_path?.length)?.exposure_path.length || 0));
  const adv = `adv:${scan.advisory.id}`;
  let maxDepth = 0;
  affected.forEach((r, lane) => {
    const svc = (r.services || []).find(s => s.exposure_path?.length);
    let prev = null;
    (svc?.exposure_path || []).forEach((n, d) => {
      const kind = n.id === 'internet' || n.kind ? 'entry' : 'service';
      const label = n.id === 'internet' ? 'Internet' : n.kind ? `${n.kind} · ${n.url || ''}` : n.name;
      node(n.id, label, kind, lane, d, {bridge: bridges[n.name] || 0});
      if (prev) edge(prev, n.id, 'exposure');
      prev = n.id;
    });
    const proj = `proj:${r.repo}`;
    node(proj, `${projectName(r.repo)} (source)`, 'project', lane, exposureLen);
    if (prev) edge(prev, proj, 'built');
    const vp = [...r.vulnerable_paths].sort((a, b) => a.path.length - b.path.length)[0];
    prev = proj;
    vp.path.slice(1).forEach((name, i, arr) => {
      const last = i === arr.length - 1;
      const id = last ? `pkg:${name}@${vp.version}` : `dep:${r.repo}:${i}:${name}`;
      node(id, last ? `${name} ${vp.version}` : name, last ? 'vuln' : 'package', lane, exposureLen + 1 + i);
      edge(prev, id, 'dep');
      prev = id;
      maxDepth = Math.max(maxDepth, exposureLen + 1 + i);
    });
    edge(prev, adv, 'affects');
  });
  node(adv, scan.advisory.id, 'advisory', 0, maxDepth + 1);
  lanesOf.set(adv, new Set(affected.map((_, i) => i)));
  // The shared vulnerable package sits at the deepest row any lane reaches it.
  for (const [id] of nodes) if (id.startsWith('pkg:')) depthOf.set(id, maxDepth);
  for (const [id, n] of nodes) {
    const lanes = [...lanesOf.get(id)];
    n.position = {x: (lanes.reduce((a, b) => a + b, 0) / lanes.length) * LANE_W, y: depthOf.get(id) * ROW_H};
  }
  return {elements: [...nodes.values(), ...edges.values()], rows: maxDepth + 2};
}

function drawGraph() {
  if (!current) return;
  if (!window.cytoscape) { $('cy').innerHTML = '<p class="muted" style="padding:16px">Graph library could not load (offline?). The same paths are listed in Overview.</p>'; return; }
  if (cy) cy.destroy();
  const {elements, rows} = graphElements(current);
  $('cy').style.height = `${Math.max(360, rows * ROW_H + 60)}px`;
  cy = cytoscape({
    container: $('cy'), elements, wheelSensitivity: 0.2, maxZoom: 1.6,
    style: [
      {selector: 'node', style: {label: 'data(label)', color: '#e6edf3', 'font-size': 11, 'text-valign': 'center', 'text-halign': 'right', 'text-margin-x': 8, 'background-color': '#6e7681', width: 14, height: 14}},
      {selector: 'node[kind="entry"]', style: {'background-color': '#f78166', shape: 'diamond', width: 24, height: 24}},
      {selector: 'node[kind="service"]', style: {'background-color': '#4493f8', shape: 'round-rectangle', width: 'mapData(bridge, 0, 10, 16, 30)', height: 16}},
      {selector: 'node[kind="project"]', style: {'background-color': '#a371f7', shape: 'barrel', width: 18, height: 16, 'font-weight': 600}},
      {selector: 'node[kind="vuln"]', style: {'background-color': '#f85149', width: 18, height: 18, 'font-weight': 700, color: '#ff7b72'}},
      {selector: 'node[kind="advisory"]', style: {'background-color': '#da3633', shape: 'hexagon', width: 26, height: 26, 'font-weight': 700}},
      {selector: 'edge', style: {width: 1.5, 'line-color': '#484f58', 'target-arrow-color': '#484f58', 'target-arrow-shape': 'triangle', 'curve-style': 'straight', 'arrow-scale': .7}},
      {selector: 'edge[kind="exposure"]', style: {'line-color': '#f78166', 'target-arrow-color': '#f78166', 'line-style': 'dashed', width: 2}},
      {selector: 'edge[kind="affects"]', style: {'line-color': '#f85149', 'target-arrow-color': '#f85149', width: 2}},
    ],
    layout: {name: 'preset', padding: 30},
  });
  cy.fit(undefined, 30);
  const bridges = (current.data.evidence.service_bridges?.services || []).filter(s => s.betweenness > 0).slice(0, 4);
  $('graph-note').textContent = `Shortest dependency path per affected project, joined to its exposure path from the Kubernetes manifests. `
    + (bridges.length ? `Service size = betweenness (algo.betweenness): ${bridges.map(s => `${s.service} ${s.betweenness}`).join(', ')}.` : '');
}

// ---------- agent run ----------
function evidenceFor(step, ev) {
  if (step.tool === 'scan_public_repo') {
    const s = ev.scan_public_repo;
    return {source: s.source, verdicts: s.results.map(r => ({project: r.repo, verdict: r.verdict, paths: r.vulnerable_paths?.length || 0}))};
  }
  if (step.tool === 'exposure_evidence') return ev.project_context?.[step.arguments?.repo]?.exposure_evidence;
  return ev[step.tool];
}
function renderAgent(entry) {
  const d = entry.data, ev = d.evidence;
  $('c-agent').textContent = d.tool_trace.length;
  const steps = d.tool_trace.map(step => {
    const args = Object.entries(step.arguments || {}).map(([k, v]) => `${k}: ${String(v).includes('::') ? projectName(String(v)) : v}`).join(' · ');
    const ok = step.status === 'ok';
    const raw = evidenceFor(step, ev);
    return `<li class="tl-item"><div class="tl-badge ${ok ? 'ok' : 'err'}">${ok ? '✓' : '✕'}</div><div class="tl-body">
      <div class="tl-title"><code>${esc(step.tool)}</code> <span class="muted small">${esc(args)}</span></div>
      <div class="tl-sub">${esc(TOOL_DESC[step.tool] || '')}</div>
      ${raw ? `<details class="raw"><summary>Tool output</summary><pre>${esc(JSON.stringify(raw, null, 2).slice(0, 5000))}</pre></details>` : ''}
    </div></li>`;
  }).join('');
  const source = d.summary_source === 'deterministic' ? 'rule-based (no LLM call)' : esc(d.summary_source);
  $('tab-agent').innerHTML = `<ol class="timeline">
    <li class="tl-item"><div class="tl-badge user">?</div><div class="tl-body"><div class="comment">
      <div class="comment-head"><b>You</b> asked</div><div class="comment-body">${esc(entry.question)}</div></div></div></li>
    ${steps}
    <li class="tl-item"><div class="tl-badge agent">◎</div><div class="tl-body"><div class="comment">
      <div class="comment-head"><b>BlastRadius agent</b> answered · ${source}</div>
      <div class="comment-body">${esc(d.summary)}<p class="muted small" style="margin:8px 0 0">${esc(d.limits || '')}</p></div></div></div></li>
  </ol>`;
}

// ---------- files changed ----------
function renderFiles(scan) {
  const affected = scan.results.map((r, idx) => ({r, idx})).filter(x => x.r.vulnerable_paths?.length);
  const ready = affected.filter(x => fixable(x.r));
  const manual = affected.filter(x => !fixable(x.r));
  $('c-files').textContent = ready.length || '';
  $('tab-files').innerHTML = (ready.map(({r, idx}) => {
    const f = fixable(r);
    return `<div class="box file" id="file-${idx}">
      <div class="box-header"><span>${esc(r.repo.includes('::') ? r.repo.split('::')[1] : '.')}/package-lock.json · ${esc(f.package)} ${esc(f.before || '')} → ${esc(f.target)}</span>
        <button class="btn btn-sm" data-load-diff="${idx}" type="button">Load diff</button></div>
      <div class="file-body muted">Candidate: ${esc(f.target)} fits ${esc(f.parent_name)}'s declared range <code>${esc(f.declared_range)}</code>. Loading the diff verifies the patched package against the registry before anything can be approved.</div>
      <div class="diff-wrap"></div></div>`;
  }).join('') || '<div class="box"><div class="box-row muted">No automatic fixes for this advisory.</div></div>')
  + (manual.length ? `<div class="box" style="margin-top:16px"><div class="box-header"><span>Needs manual review</span></div>${manual.map(({r}) =>
      `<div class="box-row"><b>${esc(projectName(r.repo))}</b> <span class="muted">· ${esc(uniqueFixes(r).map(f => `${f.package} → ${f.first_patched || '?'}`).join(', ') || 'no patched version published')}${r.fix_supported ? '' : ' · nested or non-npm project'}</span></div>`).join('')}</div>` : '');
}

function diffHtml(text) {
  return `<div class="diff">${text.split('\n').map(l => {
    const cls = l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : '';
    return `<div class="${cls}">${esc(l) || ' '}</div>`;
  }).join('')}</div>`;
}

async function loadDiff(idx, button) {
  const r = current.data.evidence.scan_public_repo.results[idx];
  const f = fixable(r);
  const box = $(`file-${idx}`).querySelector('.diff-wrap');
  button.disabled = true; button.textContent = 'Preparing…';
  try {
    const p = await api('/api/fixes/preview', {method: 'POST', body: JSON.stringify({repo: r.repo, advisory: current.data.evidence.scan_public_repo.advisory.id, package: f.package})});
    box.innerHTML = diffHtml(p.diff + (p.truncated ? '\n… display truncated; the full change will be committed' : ''))
      + `<div class="approve-row"><input type="password" placeholder="Approval key (BLASTRADIUS_ADMIN_KEY)" autocomplete="off">
         <button class="btn btn-primary" type="button" data-approve="${esc(p.proposal_id)}">Create draft PR</button>
         <span class="hint">Creates a branch and a draft PR. Never merges. Needs a GitHub token with write access.</span></div>`;
    button.textContent = 'Diff loaded';
  } catch (err) {
    const dir = r.repo.includes('::') ? r.repo.split('::')[1] : '.';
    box.innerHTML = `<div class="file-body"><div class="callout attention" style="margin:0"><b>Automatic fix refused:</b> ${esc(err.message)}.
      <br>Safe next step: in <code>${esc(dir)}</code> run <code>npm update ${esc(f.package)}</code>, then review the npm-generated lockfile change by hand.</div></div>`;
    button.textContent = 'Manual review';
  }
}

// ---------- history tab ----------
function renderHistoryTab(scan) {
  const affected = scan.results.map((r, idx) => ({r, idx})).filter(x => x.r.vulnerable_paths?.length);
  if (!affected.length) { $('tab-history').innerHTML = '<div class="box"><div class="box-row muted">Nothing affected, so nothing to decide.</div></div>'; return; }
  $('tab-history').innerHTML = affected.map(({r, idx}) => `<div class="box" style="margin-bottom:16px">
    <div class="box-header"><span>${esc(projectName(r.repo))}</span><span>
      <button class="btn btn-sm" data-decision="${idx}" type="button">Record decision</button>
      ${r.provenance_supported ? `<button class="btn btn-sm" data-provenance="${idx}" data-target="hprov-${idx}" type="button">Who introduced it?</button>` : ''}</span></div>
    <div class="box-row">${(r.prior_decisions || []).length ? `<ol class="timeline">${r.prior_decisions.map(d => `<li class="tl-item"><div class="tl-badge">✎</div><div class="tl-body">
        <div class="tl-title"><b>${esc(d.verdict)}</b> ${d.stale ? '<span class="label attention">re-review: repository changed</span>' : '<span class="label success">current commit</span>'}</div>
        <div class="tl-sub">${esc(d.reason)} · ${esc(d.created_at ? new Date(d.created_at).toLocaleString() : '')}</div></div></li>`).join('')}</ol>`
      : '<span class="muted">No decisions recorded for this advisory yet. Decisions are stored in FalkorDB and recalled on the next investigation.</span>'}
      <div class="prov" id="hprov-${idx}"></div></div></div>`).join('');
}

async function provenance(idx, button) {
  const r = current.data.evidence.scan_public_repo.results[idx];
  const target = $(button.dataset.target || `prov-${idx}`);
  button.disabled = true; button.textContent = 'Tracing git history…';
  try {
    const p = await api('/api/provenance', {method: 'POST', body: JSON.stringify({repo: r.repo, dependency_id: r.vulnerable_paths[0].dependency_id})});
    target.innerHTML = p.status === 'verified'
      ? `<div class="callout">Introduced by commit <a href="${esc(p.commit_url)}" target="_blank" rel="noopener noreferrer"><code>${esc(p.commit.slice(0, 7))}</code></a> by <b>${esc(p.author || 'unknown')}</b>${p.pull_request ? ` · merged in <a href="${esc(p.pull_request.url)}" target="_blank" rel="noopener noreferrer">PR #${esc(p.pull_request.number)}</a>${p.pull_request.verification === 'commit_subject' ? ' <span class="muted">(inferred from commit title)</span>' : ''} · approved by <b>${esc((p.reviewers || []).join(', ') || 'unknown')}</b>` : ' · merging PR unknown'}</div>`
      : `<div class="callout attention">${esc(p.reason || 'Git history could not verify the introducing commit.')}</div>`;
  } catch (err) { toast(err.message, true); }
  finally { button.disabled = false; button.textContent = 'Who introduced it?'; }
}

// ---------- tabs + events ----------
function selectTab(name) {
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.tab === name);
  for (const p of document.querySelectorAll('.tab-panel')) p.classList.toggle('hidden', p.id !== `tab-${name}`);
  if (name === 'graph') drawGraph();
}

let decisionIdx = null;
document.addEventListener('click', async (e) => {
  const t = e.target.closest('[data-tab],[data-toggle],[data-history],[data-repo],[data-goto-fix],[data-decision],[data-provenance],[data-load-diff],[data-approve]');
  if (!t) return;
  if (t.dataset.tab) return selectTab(t.dataset.tab);
  if (t.hasAttribute('data-toggle')) return t.parentElement.classList.toggle('open');
  if (t.dataset.history) { const entry = loadHistory().find(i => i.id === t.dataset.history); if (entry) openInvestigation(entry); return; }
  if (t.dataset.repo) return newInvestigation(t.dataset.repo);
  if (t.dataset.gotoFix) { selectTab('files'); const b = document.querySelector(`[data-load-diff="${t.dataset.gotoFix}"]`); b?.scrollIntoView({block: 'center'}); if (b && !b.disabled) loadDiff(t.dataset.gotoFix, b); return; }
  if (t.dataset.decision) {
    decisionIdx = Number(t.dataset.decision);
    const r = current.data.evidence.scan_public_repo.results[decisionIdx];
    $('decision-desc').textContent = `${current.data.evidence.scan_public_repo.advisory.id} in ${projectName(r.repo)}. Stored as a Decision node in FalkorDB and recalled next time this advisory is investigated.`;
    $('decision-modal').classList.remove('hidden');
    $('decision-reason').focus();
    return;
  }
  if (t.dataset.provenance) return provenance(Number(t.dataset.provenance), t);
  if (t.dataset.loadDiff) return loadDiff(Number(t.dataset.loadDiff), t);
  if (t.dataset.approve) {
    const key = t.parentElement.querySelector('input').value;
    t.disabled = true; t.textContent = 'Creating draft PR…';
    try {
      const res = await api('/api/fixes/approve', {method: 'POST', body: JSON.stringify({proposal_id: t.dataset.approve, admin_key: key})});
      t.parentElement.innerHTML = `<span class="label success">Draft PR created</span> <a href="${esc(res.pull_request_url)}" target="_blank" rel="noopener noreferrer">${esc(res.pull_request_url)}</a>`;
    } catch (err) { toast(err.message, true); t.disabled = false; t.textContent = 'Create draft PR'; }
  }
});

$('form').addEventListener('submit', (e) => { e.preventDefault(); investigate($('f-repo').value.trim(), $('f-adv').value.trim(), $('f-q').value.trim()); });
$('example').addEventListener('click', () => {
  $('f-repo').value = 'GoogleCloudPlatform/microservices-demo';
  $('f-adv').value = 'CVE-2026-12143';
  $('f-q').value = 'What is the blast radius and the public path?';
  $('form').requestSubmit();
});
$('new-investigation').addEventListener('click', () => newInvestigation());
$('home-link').addEventListener('click', (e) => { e.preventDefault(); newInvestigation(); });
$('close-decision').addEventListener('click', () => $('decision-modal').classList.add('hidden'));
$('decision-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = current.data.evidence.scan_public_repo.results[decisionIdx];
  try {
    await api('/api/decisions', {method: 'POST', body: JSON.stringify({repo: r.repo, advisory: current.data.evidence.scan_public_repo.advisory.id, verdict: $('decision-verdict').value, reason: $('decision-reason').value})});
    $('decision-modal').classList.add('hidden');
    $('decision-reason').value = '';
    toast('Decision saved in FalkorDB. Re-run the investigation to see it recalled.');
  } catch (err) { toast(err.message, true); }
});
window.addEventListener('resize', () => cy && cy.resize());

// ---------- boot ----------
renderHistory();
refreshSidebar();
const fromHash = location.hash.match(/inv=(\d+)/);
const restored = fromHash && loadHistory().find(i => i.id === fromHash[1]);
if (restored) openInvestigation(restored); else newInvestigation();
