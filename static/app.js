const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const labels = {
  affected_exposed: 'Affected · public',
  affected_exposure_unknown: 'Affected · exposure unknown',
  affected_internal_declared: 'Affected · internal declared',
  insufficient_evidence: 'Insufficient evidence',
  not_affected_version: 'Version unaffected',
  not_present: 'Package not present'
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
      ? repos.map(r => `<div class="repo-pill ${r.repo.startsWith('demo/') ? 'demo' : ''}" title="${escapeHtml(r.source)} · ${escapeHtml(r.sha)}">${escapeHtml(r.repo)}</div>`).join('')
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
    ? result.vulnerable_paths.map(p => `<div class="detail">${pathHtml(p.path)}<div style="margin-top:8px">Installed <strong>${escapeHtml(p.package)}@${escapeHtml(p.version)}</strong> · affected range ${escapeHtml(p.range)}</div></div>`).join('')
    : '<div class="detail">No vulnerable dependency path found in this snapshot.</div>';
  const services = result.services.length
    ? result.services.map(s => `<div class="detail"><strong>${escapeHtml(s.name)}</strong> · ${escapeHtml(s.exposure)}${s.public_route ? `<br>${escapeHtml(s.public_route)}` : ''}</div>`).join('')
    : '<div class="detail">No deployment evidence supplied. Exposure is unknown.</div>';
  const fix = result.fix_candidates.length
    ? result.fix_candidates.map(f => `${escapeHtml(f.package)} → ${escapeHtml(f.first_patched)}${f.direct ? ' (direct)' : ' (transitive; verify parent range)'}`).join(', ')
    : 'No verified patch candidate in advisory';
  const direct = result.fix_candidates.find(f => f.direct);
  const action = direct && !result.repo.startsWith('demo/')
    ? `<button class="secondary fix-action" data-fix-repo="${escapeHtml(result.repo)}" data-fix-package="${escapeHtml(direct.package)}">Review proposed fix →</button>`
    : '';
  const decisionAction = result.vulnerable_paths.length
    ? `<button class="ghost decision-action" data-decision-repo="${escapeHtml(result.repo)}">Record decision</button>`
    : '';
  const priorDecision = result.prior_decisions.length
    ? `<div class="decision-memory"><div class="evidence-label">Last recorded decision</div><strong>${escapeHtml(result.prior_decisions[0].verdict)}</strong> · ${escapeHtml(result.prior_decisions[0].reason)}</div>`
    : '';
  return `<article class="result-card ${escapeHtml(result.verdict)}">
    <div class="result-head"><h3>${escapeHtml(result.repo)}</h3><span class="badge">${escapeHtml(labels[result.verdict] || result.verdict)}</span></div>
    <p class="result-explanation">${escapeHtml(result.explanation)}</p>
    <div class="evidence"><div class="evidence-box"><div class="evidence-label">Dependency path · FalkorDB</div>${paths}</div><div class="evidence-box"><div class="evidence-label">Deployment evidence</div>${services}</div></div>
    <div class="result-foot"><span>Owner <strong>${escapeHtml(result.owner || 'unknown')}</strong></span><span>Fix <strong>${fix}</strong></span><span>Prior decisions <strong>${result.prior_decisions.length}</strong></span></div>${priorDecision}${action}${decisionAction}
  </article>`;
}

$('investigation-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button');
  button.disabled = true;
  button.textContent = 'Tracing…';
  try {
    const data = await api('/api/investigate', {method:'POST', body:JSON.stringify({advisory:$('advisory').value})});
    currentAdvisory = data.advisory.id;
    $('results-section').classList.remove('hidden');
    $('results-title').textContent = data.advisory.id;
    $('results-summary').textContent = data.advisory.summary;
    $('results-severity').textContent = data.advisory.severity;
    $('results').innerHTML = data.results.map(resultHtml).join('');
    $('results-section').scrollIntoView({behavior:'smooth', block:'start'});
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.innerHTML = 'Investigate <span aria-hidden="true">→</span>'; }
});

$('seed-demo').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = 'Loading…';
  try {
    const data = await api('/api/demo/seed', {method:'POST'});
    notice(`Loaded ${data.ingested.length} synthetic repositories into FalkorDB`);
    await refresh();
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Load sample data'; }
});

$('toggle-connect').addEventListener('click', () => $('connect-form').classList.toggle('hidden'));
$('connect-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button');
  button.disabled = true;
  button.textContent = 'Importing…';
  try {
    const data = await api('/api/repos/ingest', {method:'POST', body:JSON.stringify({repo:$('repo-input').value})});
    notice(`Imported ${data.repo}: ${data.dependencies} dependencies`);
    $('repo-input').value = '';
    $('connect-form').classList.add('hidden');
    await refresh();
  } catch (error) { notice(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Import'; }
});

$('results').addEventListener('click', async event => {
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
  finally { button.disabled = false; button.textContent = 'Review proposed fix →'; }
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
