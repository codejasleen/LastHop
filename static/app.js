const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const labels = {
  affected_exposed: 'Affected · public',
  affected_exposure_unknown: 'Affected · exposure unknown',
  declared_exposed: 'Python pin · public path',
  declared_exposure_unknown: 'Python pin · exposure unknown',
  affected_internal_declared: 'Affected · internal declared',
  insufficient_evidence: 'Insufficient evidence',
  not_affected_version: 'Version unaffected',
  not_present: 'Package not present',
  not_applicable: 'Different ecosystem'
};
let noticeTimer;
let currentAdvisory = null;
let currentProposal = null;
let decisionRepo = null;

function notice(message, error = false) {
  const el = $('notice');
  el.textContent = message;
  el.classList.toggle('error', error);
  el.classList.remove('hidden');
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => el.classList.add('hidden'), 6500);
}

async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {'Content-Type':'application/json', ...(options.headers || {})}});
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

async function refresh() {
  try {
    const [health, repos] = await Promise.all([api('/api/health'), api('/api/repos')]);
    const ok = health.database === 'connected';
    $('connection-dot').className = `dot ${ok ? 'ok' : 'bad'}`;
    $('connection-label').textContent = ok ? 'FalkorDB connected' : 'FalkorDB unavailable';
    $('repo-count').textContent = `${repos.length} ${repos.length === 1 ? 'repo' : 'repos'}`;
    $('repo-list').innerHTML = repos.length
      ? repos.map(r => `<button class="repo-pill" type="button" data-repo="${escapeHtml(r.repo.split('::')[0])}" title="Scan latest commit of ${escapeHtml(r.repo)}">${escapeHtml(r.repo)}${r.manager ? ` · ${escapeHtml(r.manager)}` : ''}</button>`).join('')
      : '<div class="empty-small">No repositories imported yet.</div>';
  } catch (error) {
    $('connection-dot').className = 'dot bad';
    $('connection-label').textContent = 'FalkorDB unavailable';
    $('repo-list').innerHTML = '<div class="empty-small">Graph is unavailable. Start Docker Compose and retry.</div>';
  }
}

function pathHtml(parts) {
  return `<div class="path">${parts.map((name, i) => `${i ? '<span class="path-arrow">→</span>' : ''}<span class="path-node">${escapeHtml(name)}</span>`).join('')}</div>`;
}

function resultHtml(result) {
  const paths = result.vulnerable_paths.length
    ? result.vulnerable_paths.map(p => `<div class="detail">${pathHtml(p.path)}<div style="margin-top:8px">${p.evidence_kind === 'declared_pin' ? 'Declared pin' : 'Installed'} <strong>${escapeHtml(p.package)}@${escapeHtml(p.version)}</strong> · affected range ${escapeHtml(p.range)}</div></div>`).join('')
    : '<div class="detail">No vulnerable dependency path found in this snapshot.</div>';
  const services = result.services.length
    ? result.services.map(s => `<div class="detail"><strong>${escapeHtml(s.name)}</strong> · ${escapeHtml(s.exposure)}${s.public_route ? `<br>Public entry: ${escapeHtml(s.public_route)}` : ''}${s.exposure_path?.length ? `<br>${pathHtml(s.exposure_path.map(n => n.name || n.kind || (n.id === 'internet' ? 'Internet' : n.url || n.id)))}<span class="evidence-caveat">${escapeHtml(s.exposure_path.map(n => n.evidence).filter(Boolean).join(' → '))}</span>` : ''}</div>`).join('')
    : '<div class="detail">No deployment evidence supplied. Exposure is unknown.</div>';
  const fix = result.fix_candidates.length
    ? result.fix_candidates.map(f => f.strategy === 'lockfile_refresh'
      ? `Lockfile refresh: ${escapeHtml(f.package)} → ${escapeHtml(f.target)} fits ${escapeHtml(f.parent_name)} ${escapeHtml(f.declared_range)}`
      : `${escapeHtml(f.package)} → ${escapeHtml(f.first_patched)} (review parent range)`).join(', ')
    : 'No verified patch candidate in advisory';
  const fixable = result.fix_candidates.find(f => f.strategy === 'lockfile_refresh');
  const action = fixable && result.fix_supported
    ? `<button class="secondary fix-action" data-fix-repo="${escapeHtml(result.repo)}" data-fix-package="${escapeHtml(fixable.package)}">Review lockfile fix →</button>`
    : '';
  const moduleEvidence = (result.module_evidence || []).map(e => {
    if (e.status === 'unavailable') return `<div class="detail">${escapeHtml(e.parent)}: source inspection unavailable.</div>`;
    const meaning = e.status === 'runtime_static_path' ? 'Static import path from package main found'
      : e.status === 'cli_only_static_path' ? 'Static import observed in CLI; no path found from package main'
      : 'No static import path found from package main or CLI';
    const sourceLink = e.file
      ? `https://unpkg.com/${encodeURIComponent(e.parent)}@${encodeURIComponent(e.parent_version)}/${e.file.split('/').map(encodeURIComponent).join('/')}`
      : '';
    return `<div class="detail"><strong>${escapeHtml(e.parent)}@${escapeHtml(e.parent_version)}</strong> · ${meaning}<br>
      Main: <code>${escapeHtml(e.main)}</code>${e.file ? ` · Import: <a href="${escapeHtml(sourceLink)}" target="_blank" rel="noopener noreferrer"><code>${escapeHtml(e.file)}:${escapeHtml(e.line)}</code></a>` : ''}<br>
      <span class="evidence-caveat">${escapeHtml(e.scope)}</span></div>`;
  }).join('') || '<div class="detail">No package module trace is available for this result.</div>';
  const decisionAction = result.vulnerable_paths.length
    ? `<button class="ghost decision-action" data-decision-repo="${escapeHtml(result.repo)}">Record decision</button>`
    : '';
  const priorDecision = result.prior_decisions.length
    ? `<div class="decision-memory"><div class="evidence-label">Last recorded decision ${result.prior_decisions[0].stale ? '· review again: repository changed' : '· current commit'}</div><strong>${escapeHtml(result.prior_decisions[0].verdict)}</strong> · ${escapeHtml(result.prior_decisions[0].reason)}</div>`
    : '';
  const provenance = result.vulnerable_paths.length && result.provenance_supported
    ? `<button class="ghost provenance-action" data-provenance-repo="${escapeHtml(result.repo)}" data-dependency-id="${escapeHtml(result.vulnerable_paths[0].dependency_id)}">Trace introducing commit →</button><div class="provenance-result"></div>` : '';
  return `<article class="result-card ${escapeHtml(result.verdict)}">
    <div class="result-head"><h3>${escapeHtml(result.repo)}</h3><span class="badge">${escapeHtml(result.priority || 'Review')}${result.priority?.startsWith('P') ? ' provisional' : ''} · ${escapeHtml(labels[result.verdict] || result.verdict)}</span></div>
    <p class="result-explanation">${escapeHtml(result.explanation)}</p>
    <div class="evidence"><div class="evidence-box"><div class="evidence-label">Dependency path · FalkorDB</div>${paths}</div><div class="evidence-box"><div class="evidence-label">Module entry evidence · FalkorDB</div>${moduleEvidence}</div><div class="evidence-box"><div class="evidence-label">Deployment evidence</div>${services}</div></div>
    <div class="result-foot"><span>Owner <strong>${escapeHtml(result.owner || 'unknown')}</strong></span><span>Fix <strong>${fix}</strong></span><span>Prior decisions <strong>${result.prior_decisions.length}</strong></span></div>${priorDecision}<div class="detail">${escapeHtml((result.priority_reasons || []).join(' · '))}</div>${action}${decisionAction}${provenance}
  </article>`;
}

function renderResults(data, agent = null) {
  currentAdvisory = data.advisory.id;
  $('results-section').classList.remove('hidden');
  $('results-title').textContent = data.advisory.id;
  $('results-summary').textContent = data.advisory.summary;
  $('results-severity').textContent = `Advisory severity: ${data.advisory.severity}`;
  const risk = data.risk_signals;
  $('agent-summary').textContent = agent?.summary || '';
  $('agent-trace').textContent = agent ? `MCP tools: ${agent.tool_trace.map(step => step.tool).join(' → ')}` : '';
  $('graph-summary').textContent = agent ? `Graph fan-out: ${agent.evidence.advisory_fanout?.count ?? 0} affected projects · service bridge ranking: ${(agent.evidence.service_bridges?.services || []).slice(0, 3).map(s => `${s.service} ${s.betweenness}`).join(', ') || 'unavailable'}${risk ? ` · KEV: ${risk.kev === null ? 'unknown' : risk.kev ? 'listed' : 'not listed'} · EPSS: ${risk.epss === null ? 'unknown' : (risk.epss * 100).toFixed(2) + '%'}` : ''}` : '';
  $('results-source').textContent = data.source
    ? `${data.source.repo} · latest commit ${data.source.sha.slice(0, 10)} · ${data.source.projects} ${data.source.projects === 1 ? 'project' : 'projects'} · ${data.source.dependencies} dependencies · ${new Date(data.source.scanned_at).toLocaleString()}`
    : 'Stored graph snapshot';
  const scope = [];
  if (data.source && !data.source.project_paths.includes('.')) scope.push('Only the listed subprojects have supported dependency manifests; the repository root was not analyzed.');
  if (data.source?.other_manifests?.length) scope.push(`Other root manifests not analyzed: ${data.source.other_manifests.join(', ')}.`);
  const unrelated = data.results.filter(result => result.verdict === 'not_applicable').length;
  if (unrelated) scope.push(`${unrelated} project(s) use a different package ecosystem and are omitted below.`);
  $('results-scope').textContent = scope.join(' ');
  $('results-scope').classList.toggle('hidden', !scope.length);
  $('results').innerHTML = data.results.filter(result => result.verdict !== 'not_applicable').map(resultHtml).join('');
  $('results-section').scrollIntoView({behavior:'smooth', block:'start'});
}

$('investigation-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button');
  button.disabled = true;
  button.textContent = 'Scanning…';
  try {
    const question = $('agent-question').value.trim() || `Investigate ${$('advisory').value} in ${$('live-repo').value} and show graph impact`;
    const agent = await api('/api/agent', {method:'POST', body:JSON.stringify({repo:$('live-repo').value, advisory:$('advisory').value, question})});
    renderResults(agent.evidence.scan_public_repo, agent);
    await refresh();
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.innerHTML = 'Scan latest <span aria-hidden="true">→</span>'; }
});

$('real-example').addEventListener('click', () => {
  $('live-repo').value = 'GoogleCloudPlatform/microservices-demo';
  $('advisory').value = 'CVE-2026-12143';
  $('agent-question').value = 'What is the blast radius and public path?';
  $('investigation-form').requestSubmit();
});

$('repo-list').addEventListener('click', event => {
  const button = event.target.closest('[data-repo]');
  if (!button) return;
  $('live-repo').value = button.dataset.repo;
  $('advisory').focus();
  $('investigate').scrollIntoView({behavior:'smooth', block:'start'});
});

$('results').addEventListener('click', async event => {
  const provenanceButton = event.target.closest('[data-provenance-repo]');
  if (provenanceButton) {
    provenanceButton.disabled = true;
    provenanceButton.textContent = 'Tracing Git history…';
    try {
      const result = await api('/api/provenance', {method:'POST', body:JSON.stringify({repo:provenanceButton.dataset.provenanceRepo, dependency_id:provenanceButton.dataset.dependencyId})});
      provenanceButton.nextElementSibling.innerHTML = result.status === 'verified'
        ? `Introduced by <a href="${escapeHtml(result.commit_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(result.commit.slice(0, 10))}</a> · author ${escapeHtml(result.author || 'unknown')}${result.pull_request ? ` · <a href="${escapeHtml(result.pull_request.url)}" target="_blank" rel="noopener noreferrer">PR #${escapeHtml(result.pull_request.number)}</a>${result.pull_request.verification === 'commit_subject' ? ' (inferred from commit title)' : ''} · approving reviewer ${escapeHtml(result.reviewers.join(', ') || 'unknown')}` : ' · merged PR unknown'}`
        : escapeHtml(result.reason || 'Git history could not verify the introducing commit.');
    } catch (error) { notice(error.message, true); }
    finally { provenanceButton.disabled = false; provenanceButton.textContent = 'Trace introducing commit →'; }
    return;
  }
  const decisionButton = event.target.closest('[data-decision-repo]');
  if (decisionButton) {
    decisionRepo = decisionButton.dataset.decisionRepo;
    $('decision-description').textContent = `${currentAdvisory} in ${decisionRepo}. Your reason will be retained as a decision node for later investigations.`;
    $('decision-modal').classList.remove('hidden');
    return;
  }
  const button = event.target.closest('[data-fix-repo]');
  if (!button) return;
  button.disabled = true;
  button.textContent = 'Preparing diff…';
  try {
    currentProposal = await api('/api/fixes/preview', {method:'POST', body:JSON.stringify({repo:button.dataset.fixRepo, advisory:currentAdvisory, package:button.dataset.fixPackage})});
    $('fix-title').textContent = `Review ${currentProposal.package} update`;
    $('fix-description').textContent = `${currentProposal.repo}: ${currentProposal.before} → ${currentProposal.after}. Review the lockfile change before approving a draft PR.`;
    $('fix-diff').textContent = currentProposal.diff + (currentProposal.truncated ? '\n… diff display truncated; full change will be committed.' : '');
    $('fix-modal').classList.remove('hidden');
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Review lockfile fix →'; }
});
$('close-decision').addEventListener('click', () => $('decision-modal').classList.add('hidden'));
$('decision-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await api('/api/decisions', {method:'POST', body:JSON.stringify({repo:decisionRepo, advisory:currentAdvisory, verdict:$('decision-verdict').value, reason:$('decision-reason').value})});
    $('decision-modal').classList.add('hidden');
    $('decision-reason').value = '';
    notice('Decision saved in FalkorDB. Run the investigation again to see its memory.');
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; }
});
$('close-modal').addEventListener('click', () => $('fix-modal').classList.add('hidden'));
$('approve-fix').addEventListener('click', async event => {
  const button = event.currentTarget;
  if (!currentProposal) return;
  button.disabled = true;
  button.textContent = 'Creating draft…';
  try {
    const data = await api('/api/fixes/approve', {method:'POST', body:JSON.stringify({proposal_id:currentProposal.proposal_id, admin_key:$('admin-key').value})});
    $('admin-key').value = '';
    $('fix-modal').classList.add('hidden');
    notice(`Draft PR created: ${data.pull_request_url}`);
    window.open(data.pull_request_url, '_blank', 'noopener,noreferrer');
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Open draft PR →'; }
});

refresh();
