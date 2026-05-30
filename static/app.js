const PROBE_OPTIONS = Object.freeze([
  "auto",
  "none",
  "http",
  "https",
  "rdp",
  "dns_a",
  "dns_aaaa",
  "dns_mx",
  "dns_txt",
  "dns_srv",
  "dns_soa",
  "ntp",
]);

const TCP_PROBE_OPTIONS = new Set(["auto", "none", "http", "https", "rdp"]);
const UDP_PROBE_OPTIONS = new Set([
  "auto",
  "none",
  "dns_a",
  "dns_aaaa",
  "dns_mx",
  "dns_txt",
  "dns_srv",
  "dns_soa",
  "ntp",
]);

const ROLE_TEMPLATES = Object.freeze({
  AD: [
    { port: 53, transport: "tcp", probe: "none", retries: 2 },
    { port: 53, transport: "udp", probe: "dns_a", retries: 2 },
    { port: 53, transport: "udp", probe: "dns_srv", retries: 2 },
    { port: 53, transport: "udp", probe: "dns_soa", retries: 2 },
    { port: 88, transport: "tcp", probe: "none", retries: 2 },
    { port: 88, transport: "udp", probe: "none", retries: 2 },
    { port: 389, transport: "tcp", probe: "none", retries: 2 },
    { port: 445, transport: "tcp", probe: "none", retries: 2 },
    { port: 3389, transport: "tcp", probe: "rdp", retries: 2 },
  ],
  WEB: [
    { port: 80, transport: "tcp", probe: "http", retries: 2 },
    { port: 443, transport: "tcp", probe: "https", retries: 2 },
    { port: 8080, transport: "tcp", probe: "http", retries: 2 },
    { port: 8443, transport: "tcp", probe: "https", retries: 2 },
    { port: 3389, transport: "tcp", probe: "rdp", retries: 2 },
  ],
  DB: [
    { port: 1433, transport: "tcp", probe: "none", retries: 2 },
    { port: 3306, transport: "tcp", probe: "none", retries: 2 },
    { port: 5432, transport: "tcp", probe: "none", retries: 2 },
    { port: 1521, transport: "tcp", probe: "none", retries: 2 },
    { port: 27017, transport: "tcp", probe: "none", retries: 2 },
    { port: 3389, transport: "tcp", probe: "rdp", retries: 2 },
  ],
});

const state = {
  servers: [],
  draftPortTargets: [],
  editingDraftTargetIndex: null,
  templates: [],
  credentialProfiles: [],
  activeCheckEventSource: null,
  checkInProgress: false,
  results: [],
  filteredResults: [],
  resultPaging: {
    page: 1,
    pageSize: 200,
    total: 0,
  },
  trends: [],
  trendAlerts: [],
  resultView: {
    rowHeight: 92,
    overscan: 6,
  },
};

const statusRowClassMap = {
  OPEN: "status-open",
  REFUSED: "status-refused",
  TIMEOUT: "status-timeout",
  FILTERED: "status-timeout",
  NO_ROUTE: "status-unknown",
  HOST_UNREACHABLE: "status-unknown",
  NETWORK_UNREACHABLE: "status-unknown",
  UNKNOWN_HOST: "status-unknown",
  UDP_OPEN_OR_FILTERED: "status-unknown",
  UDP_CLOSED: "status-refused",
  PROBE_TIMEOUT: "status-timeout",
  PROBE_FAILED: "status-error",
  INVALID_RESPONSE: "status-error",
  ERROR: "status-error",
};

const actionGuideMap = {
  OPEN: "Connected successfully",
  REFUSED: "Target reachable but service is not listening",
  TIMEOUT: "Timeout; check firewall/ACL and network path",
  FILTERED: "Likely firewall/policy drop; review security rules",
  NO_ROUTE: "No route; check gateway/route/vSwitch path",
  HOST_UNREACHABLE: "Host unreachable; check server power/NIC state",
  NETWORK_UNREACHABLE: "Network unreachable; check subnet/VLAN routing",
  UNKNOWN_HOST: "Hostname resolve failed; verify DNS or hostname",
  UDP_OPEN_OR_FILTERED: "UDP may be silent; verify using DNS/NTP probe",
  UDP_CLOSED: "UDP port likely closed (ICMP unreachable)",
  PROBE_TIMEOUT: "Application probe timed out",
  PROBE_FAILED: "Application probe failed; check service logs",
  INVALID_RESPONSE: "Application response format is invalid",
  ERROR: "Check reason_code and target logs",
};

const reasonCodeGuideMap = {
  WSAETIMEDOUT: "No response within timeout window.",
  ETIMEDOUT: "No response within timeout window.",
  WSAENETUNREACH: "Network path unreachable from source host.",
  ENETUNREACH: "Network path unreachable from source host.",
  WSAEHOSTUNREACH: "Destination host unreachable.",
  EHOSTUNREACH: "Destination host unreachable.",
  WSAECONNREFUSED: "Connection refused; service is not listening.",
  ECONNREFUSED: "Connection refused; service is not listening.",
  WSAEACCES: "Connection blocked by policy/firewall.",
  EAI_NONAME: "DNS resolution failed for host/hostname.",
  NO_UDP_RESPONSE: "No UDP response; could be open-silent or filtered.",
  HOST_CIRCUIT_BREAKER:
    "Host-level circuit breaker triggered after UNKNOWN_HOST/NO_ROUTE. Check host reachability first.",
  UDP_PROBE_REQUIRED:
    "Policy requires explicit UDP protocol probe to finalize UDP_OPEN_OR_FILTERED result.",
  UDP_PROBE_CONFIRMED: "UDP application probe succeeded; uncertain transport result was promoted to OPEN.",
};

function notify({ type = "info", title = "Info", message = "", timeout = 3600 }) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const notice = document.createElement("article");
  notice.className = `notice notice-${type}`;
  notice.innerHTML = `
    <div class="notice-head">
      <div>
        <p class="notice-title">${title}</p>
        <p class="notice-message">${message}</p>
      </div>
      <button type="button" class="notice-close" aria-label="Close">&times;</button>
    </div>
  `;

  const close = () => notice.remove();
  notice.querySelector(".notice-close").addEventListener("click", close);
  container.appendChild(notice);
  window.setTimeout(close, timeout);
}

function parseHttpError(status, statusText, payload) {
  if (payload && typeof payload === "object" && payload.detail) return String(payload.detail);
  return `${status} ${statusText}`;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
    throw new Error(parseHttpError(response.status, response.statusText, payload));
  }
  if (response.status === 204) return null;
  return response.json();
}

function parsePorts(raw) {
  const values = raw
    .split(",")
    .map((item) => Number.parseInt(item.trim(), 10))
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
  return [...new Set(values)].sort((a, b) => a - b);
}

function parseItems(raw) {
  return [...new Set(raw.split(",").map((item) => item.trim()).filter(Boolean))];
}

function formatDateTime(isoString) {
  if (!isoString) return "-";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  return date.toLocaleString("ko-KR", { hour12: false });
}

function setCheckProgress(percent, message = "") {
  const wrap = document.getElementById("checkProgressWrap");
  const bar = document.getElementById("checkProgressBar");
  const text = document.getElementById("checkProgressText");
  if (!wrap || !bar || !text) return;

  const value = Math.max(0, Math.min(100, Number(percent) || 0));
  wrap.classList.remove("d-none");
  bar.style.width = `${value}%`;
  bar.setAttribute("aria-valuenow", String(value));
  text.textContent = message || `Progress ${value.toFixed(1)}%`;
}

function hideCheckProgress() {
  const wrap = document.getElementById("checkProgressWrap");
  if (!wrap) return;
  wrap.classList.add("d-none");
}

function renderTrends() {
  const tbody = document.getElementById("trendBody");
  const alertText = document.getElementById("trendAlertText");
  if (!tbody || !alertText) return;

  if (!Array.isArray(state.trends) || state.trends.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted py-3">No trend data</td></tr>';
    alertText.textContent = "No alerts";
    return;
  }

  tbody.innerHTML = state.trends
    .map(
      (item) => `
      <tr>
        <td>${item.day}</td>
        <td>${item.run_count}</td>
        <td>${item.total_checks}</td>
        <td>${item.flaky_ratio}%</td>
        <td>${item.error_ratio}%</td>
      </tr>
    `
    )
    .join("");

  if (Array.isArray(state.trendAlerts) && state.trendAlerts.length > 0) {
    alertText.textContent = state.trendAlerts
      .slice(0, 2)
      .map((item) => item.message)
      .join(" | ");
  } else {
    alertText.textContent = "No alerts";
  }
}

async function loadTrendData({ silent = true } = {}) {
  try {
    const payload = await fetchJson("/api/history/trends?days=14");
    state.trends = payload.items || [];
    state.trendAlerts = payload.alerts || [];
    renderTrends();
    if (!silent) {
      notify({
        type: "success",
        title: "Trend Loaded",
        message: `${state.trends.length} day trend entries loaded.`,
      });
    }
  } catch (error) {
    if (!silent) {
      notify({
        type: "error",
        title: "Trend Load Failed",
        message: error.message,
        timeout: 5200,
      });
    }
  }
}

function draftTargetKey(target) {
  const probeParams =
    target && target.probe_params && typeof target.probe_params === "object"
      ? Object.keys(target.probe_params)
          .sort()
          .map((key) => `${key}:${String(target.probe_params[key])}`)
          .join("|")
      : "";
  return `${target.port}/${target.transport}/${target.probe}/${probeParams}`;
}

function normalizeProbe(rawProbe) {
  const probe = String(rawProbe || "auto").toLowerCase();
  if (probe === "dns") return "dns_a";
  return probe;
}

function isProbeAllowedByTransport(probe, transport) {
  if (transport === "tcp") return TCP_PROBE_OPTIONS.has(probe);
  if (transport === "udp") return UDP_PROBE_OPTIONS.has(probe);
  return false;
}

function normalizePortTarget(input) {
  const port = Number.parseInt(input.port, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const transport = String(input.transport || "tcp").toLowerCase();
  const probe = normalizeProbe(input.probe);
  let retries = Number.parseInt(input.retries, 10);
  if (!Number.isInteger(retries)) retries = 2;

  if (!["tcp", "udp"].includes(transport)) return null;
  if (!PROBE_OPTIONS.includes(probe)) return null;
  if (retries < 0 || retries > 5) return null;
  if (!isProbeAllowedByTransport(probe, transport)) return null;
  const probeParams = {};
  if (input && input.probe_params && typeof input.probe_params === "object") {
    Object.entries(input.probe_params).forEach(([key, value]) => {
      if (!key) return;
      if (["string", "number", "boolean"].includes(typeof value)) {
        probeParams[key] = value;
      }
    });
  }
  return { port, transport, probe, retries, probe_params: probeParams };
}

function normalizeServerPortTarget(item) {
  return normalizePortTarget({
    port: item.port,
    transport: item.transport || "tcp",
    probe: item.probe || "auto",
    retries: Number.isInteger(item.retries) ? item.retries : 2,
    probe_params: item.probe_params || {},
  });
}

function sortDraftPortTargets() {
  state.draftPortTargets.sort((a, b) => {
    if (a.port !== b.port) return a.port - b.port;
    if (a.transport !== b.transport) return a.transport.localeCompare(b.transport);
    return a.probe.localeCompare(b.probe);
  });
}

function dedupeDraftPortTargets() {
  const deduped = new Map();
  state.draftPortTargets.forEach((target) => deduped.set(draftTargetKey(target), target));
  state.draftPortTargets = Array.from(deduped.values());
  sortDraftPortTargets();
}

function addOrReplaceDraftPortTarget(target) {
  const key = draftTargetKey(target);
  const idx = state.draftPortTargets.findIndex((item) => draftTargetKey(item) === key);
  if (idx >= 0) {
    state.draftPortTargets[idx] = target;
  } else {
    state.draftPortTargets.push(target);
  }
  sortDraftPortTargets();
}

function setDraftTargetEditMode(index) {
  const button = document.getElementById("addPortTargetBtn");
  const isEditing =
    Number.isInteger(index) && index >= 0 && index < state.draftPortTargets.length;
  state.editingDraftTargetIndex = isEditing ? index : null;
  button.textContent = isEditing ? "수정" : "추가";
}

function renderDraftPortTargets() {
  const tbody = document.getElementById("portTargetBody");
  if (!state.draftPortTargets.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted py-2">고급 타깃이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.draftPortTargets
    .map((target, index) => {
      const isEditing = state.editingDraftTargetIndex === index;
      const editBtnClass = isEditing ? "btn-warning" : "btn-outline-info";
      const editBtnText = isEditing ? "수정중" : "수정";
      return `
        <tr>
          <td>${target.port}</td>
          <td>${target.transport.toUpperCase()}</td>
          <td>${target.probe}</td>
          <td>${target.retries}</td>
          <td>
            <button class="btn btn-sm ${editBtnClass}" data-action="edit-target" data-index="${index}">
              ${editBtnText}
            </button>
          </td>
          <td>
            <button class="btn btn-sm btn-outline-danger" data-action="remove-target" data-index="${index}">
              삭제
            </button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function resetAdvancedPortTargetInputs() {
  document.getElementById("advancedPort").value = "";
  document.getElementById("advancedTransport").value = "tcp";
  document.getElementById("advancedProbe").value = "auto";
  document.getElementById("advancedRetries").value = "2";
  setDraftTargetEditMode(null);
}

function fillAdvancedPortTargetInputs(target) {
  document.getElementById("advancedPort").value = String(target.port);
  document.getElementById("advancedTransport").value = target.transport;
  document.getElementById("advancedProbe").value = target.probe;
  document.getElementById("advancedRetries").value = String(target.retries);
}

function upsertDraftPortTargetFromForm() {
  const raw = {
    port: document.getElementById("advancedPort").value,
    transport: document.getElementById("advancedTransport").value,
    probe: document.getElementById("advancedProbe").value,
    retries: document.getElementById("advancedRetries").value,
  };
  const target = normalizePortTarget(raw);
  if (!target) {
    notify({
      type: "warning",
      title: "고급 타깃 입력 오류",
      message:
        "Port(1~65535), Transport/Probe 조합, Retries(0~5)를 확인해 주세요. TCP와 UDP는 지원 probe가 다릅니다.",
      timeout: 4800,
    });
    return;
  }

  const editingIndex = state.editingDraftTargetIndex;
  if (Number.isInteger(editingIndex)) {
    state.draftPortTargets[editingIndex] = target;
    dedupeDraftPortTargets();
    renderDraftPortTargets();
    resetAdvancedPortTargetInputs();
    notify({
      type: "success",
      title: "고급 타깃 수정 완료",
      message: `${target.port}/${target.transport}/${target.probe} 항목을 수정했습니다.`,
    });
    return;
  }

  addOrReplaceDraftPortTarget(target);
  renderDraftPortTargets();
  resetAdvancedPortTargetInputs();
  notify({
    type: "success",
    title: "고급 타깃 추가",
    message: `${target.port}/${target.transport}/${target.probe} (retries=${target.retries})`,
  });
}

function removeDraftPortTarget(index) {
  if (!Number.isInteger(index) || index < 0 || index >= state.draftPortTargets.length) return;
  const [removed] = state.draftPortTargets.splice(index, 1);

  if (state.editingDraftTargetIndex === index) {
    resetAdvancedPortTargetInputs();
  } else if (
    Number.isInteger(state.editingDraftTargetIndex) &&
    state.editingDraftTargetIndex > index
  ) {
    state.editingDraftTargetIndex -= 1;
  }

  renderDraftPortTargets();
  notify({
    type: "info",
    title: "고급 타깃 삭제",
    message: `${removed.port}/${removed.transport}/${removed.probe} 항목을 삭제했습니다.`,
  });
}

function applyRoleTemplate(roleKey) {
  const template = ROLE_TEMPLATES[roleKey];
  if (!Array.isArray(template) || !template.length) return;

  let added = 0;
  let updated = 0;
  for (const raw of template) {
    const target = normalizePortTarget(raw);
    if (!target) continue;
    const key = draftTargetKey(target);
    const idx = state.draftPortTargets.findIndex((item) => draftTargetKey(item) === key);
    if (idx >= 0) {
      state.draftPortTargets[idx] = target;
      updated += 1;
    } else {
      state.draftPortTargets.push(target);
      added += 1;
    }
  }

  sortDraftPortTargets();
  setDraftTargetEditMode(null);
  renderDraftPortTargets();
  notify({
    type: "success",
    title: `${roleKey} Template Applied`,
    message: `Added ${added}, Updated ${updated}`,
  });
}

function resetTemplateForm() {
  document.getElementById("editingTemplateId").value = "";
  document.getElementById("templateName").value = "";
  document.getElementById("templateDescription").value = "";
  document.getElementById("saveTemplateBtn").textContent = "템플릿 저장";
}

function renderTemplateList() {
  const tbody = document.getElementById("templateListBody");
  if (!state.templates.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-muted py-2">저장된 사용자 템플릿이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.templates
    .map(
      (template) => `
      <tr>
        <td>${template.name}</td>
        <td>${template.description || "-"}</td>
        <td>${(template.port_targets || []).length}</td>
        <td class="d-flex gap-1">
          <button class="btn btn-sm btn-outline-success" data-action="apply-template" data-id="${template.id}">적용</button>
          <button class="btn btn-sm btn-outline-info" data-action="edit-template" data-id="${template.id}">수정</button>
          <button class="btn btn-sm btn-outline-danger" data-action="delete-template" data-id="${template.id}">삭제</button>
        </td>
      </tr>
    `
    )
    .join("");
}

function applyCustomTemplate(template) {
  if (!template || !Array.isArray(template.port_targets)) return;
  let applied = 0;
  for (const item of template.port_targets) {
    const target = normalizeServerPortTarget(item);
    if (!target) continue;
    addOrReplaceDraftPortTarget(target);
    applied += 1;
  }
  renderDraftPortTargets();
  notify({
    type: "success",
    title: "사용자 템플릿 적용",
    message: `${template.name} 템플릿에서 ${applied}개 타깃을 반영했습니다.`,
  });
}

async function saveTemplateFromDraft() {
  const name = document.getElementById("templateName").value.trim();
  const description = document.getElementById("templateDescription").value.trim();
  const editingId = document.getElementById("editingTemplateId").value.trim();

  if (!name) {
    notify({ type: "warning", title: "입력값 확인", message: "템플릿명을 입력해 주세요." });
    return;
  }
  if (!state.draftPortTargets.length) {
    notify({
      type: "warning",
      title: "타깃 없음",
      message: "현재 고급 타깃 목록이 비어 있습니다. 타깃을 추가하거나 불러온 뒤 저장해 주세요.",
    });
    return;
  }

  const payload = {
    name,
    description: description || null,
    port_targets: state.draftPortTargets,
  };

  try {
    if (editingId) {
      await fetchJson(`/api/templates/${editingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "템플릿 수정 완료", message: `${name} 템플릿을 수정했습니다.` });
    } else {
      await fetchJson("/api/templates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "템플릿 저장 완료", message: `${name} 템플릿을 저장했습니다.` });
    }
    resetTemplateForm();
    await loadConfig({ silent: true });
  } catch (error) {
    notify({ type: "error", title: "템플릿 저장 실패", message: error.message, timeout: 5200 });
  }
}

async function onTemplateListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id) return;

  const template = state.templates.find((item) => item.id === id);
  if (!template) return;

  if (action === "apply-template") {
    applyCustomTemplate(template);
    return;
  }

  if (action === "edit-template") {
    document.getElementById("editingTemplateId").value = template.id;
    document.getElementById("templateName").value = template.name || "";
    document.getElementById("templateDescription").value = template.description || "";
    document.getElementById("saveTemplateBtn").textContent = "템플릿 수정";
    state.draftPortTargets = (template.port_targets || [])
      .map(normalizeServerPortTarget)
      .filter((item) => item !== null);
    sortDraftPortTargets();
    renderDraftPortTargets();
    notify({
      type: "info",
      title: "템플릿 편집 모드",
      message: `${template.name} 템플릿 내용을 폼으로 불러왔습니다.`,
    });
    return;
  }

  if (action === "delete-template") {
    const confirmed = window.confirm(`${template.name} 템플릿을 삭제할까요?`);
    if (!confirmed) return;
    try {
      await fetchJson(`/api/templates/${id}`, { method: "DELETE" });
      resetTemplateForm();
      await loadConfig({ silent: true });
      notify({ type: "success", title: "템플릿 삭제 완료", message: `${template.name} 템플릿을 삭제했습니다.` });
    } catch (error) {
      notify({ type: "error", title: "템플릿 삭제 실패", message: error.message, timeout: 5200 });
    }
  }
}

function profileAccountText(profile) {
  if (!profile) return "-";
  if (profile.domain) return `${profile.domain}\\${profile.username}`;
  return profile.username;
}

function renderCredentialProfileOptions(selectedValue = "") {
  const select = document.getElementById("serverCredentialProfile");
  const wanted = selectedValue ?? select.value;
  const options = [
    '<option value="">현재 실행 계정</option>',
    ...state.credentialProfiles.map(
      (profile) =>
        `<option value="${profile.id}">${profile.name} (${profileAccountText(profile)})</option>`
    ),
  ];
  select.innerHTML = options.join("");
  const exists = state.credentialProfiles.some((profile) => profile.id === wanted);
  select.value = exists ? wanted : "";
}

function renderCredentialProfileList() {
  const tbody = document.getElementById("credentialProfileListBody");
  if (!state.credentialProfiles.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted py-2">등록된 프로필이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.credentialProfiles
    .map(
      (profile) => `
      <tr>
        <td>${profile.name}</td>
        <td>${profileAccountText(profile)}</td>
        <td>${profile.secret_provider || "-"}</td>
        <td>${profile.description || "-"}</td>
        <td class="d-flex gap-1">
          <button class="btn btn-sm btn-outline-info" data-action="edit-profile" data-id="${profile.id}">수정</button>
          <button class="btn btn-sm btn-outline-danger" data-action="delete-profile" data-id="${profile.id}">삭제</button>
        </td>
      </tr>
    `
    )
    .join("");
}

function resetCredentialProfileForm() {
  document.getElementById("editingCredentialProfileId").value = "";
  document.getElementById("credentialProfileName").value = "";
  document.getElementById("credentialProfileUsername").value = "";
  document.getElementById("credentialProfileProvider").value = "dpapi";
  document.getElementById("credentialProfileDomain").value = "";
  document.getElementById("credentialProfilePassword").value = "";
  document.getElementById("credentialProfileSecretRef").value = "";
  document.getElementById("credentialProfileDescription").value = "";
}

function fillCredentialProfileForm(profile) {
  document.getElementById("editingCredentialProfileId").value = profile.id;
  document.getElementById("credentialProfileName").value = profile.name || "";
  document.getElementById("credentialProfileUsername").value = profile.username || "";
  document.getElementById("credentialProfileProvider").value = profile.secret_provider || "dpapi";
  document.getElementById("credentialProfileDomain").value = profile.domain || "";
  document.getElementById("credentialProfilePassword").value = "";
  document.getElementById("credentialProfileSecretRef").value = profile.secret_ref || "";
  document.getElementById("credentialProfileDescription").value = profile.description || "";
  onCredentialProviderChange();
}

async function submitCredentialProfileForm(event) {
  event.preventDefault();
  const id = document.getElementById("editingCredentialProfileId").value.trim();
  const name = document.getElementById("credentialProfileName").value.trim();
  const username = document.getElementById("credentialProfileUsername").value.trim();
  const secretProvider = document.getElementById("credentialProfileProvider").value;
  const password = document.getElementById("credentialProfilePassword").value.trim();
  const secretRef = document.getElementById("credentialProfileSecretRef").value.trim();
  const domain = document.getElementById("credentialProfileDomain").value.trim();
  const description = document.getElementById("credentialProfileDescription").value.trim();

  if (!name || !username) {
    notify({
      type: "warning",
      title: "입력값 확인",
      message: "프로필명과 사용자명은 필수입니다.",
    });
    return;
  }
  if (secretProvider === "dpapi" && !id && !password) {
    notify({
      type: "warning",
      title: "입력값 확인",
      message: "dpapi 프로필 생성 시 비밀번호는 필수입니다.",
    });
    return;
  }
  if ((secretProvider === "env" || secretProvider === "azure_key_vault") && !secretRef) {
    notify({
      type: "warning",
      title: "입력값 확인",
      message: `${secretProvider} 프로필은 Secret Ref가 필요합니다.`,
    });
    return;
  }

  const payload = {
    name,
    username,
    secret_provider: secretProvider,
    password: password || null,
    secret_ref: secretRef || null,
    domain: domain || null,
    description: description || null,
  };

  try {
    if (id) {
      await fetchJson(`/api/credential-profiles/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "프로필 수정 완료", message: `${name} 프로필을 수정했습니다.` });
    } else {
      await fetchJson("/api/credential-profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "프로필 저장 완료", message: `${name} 프로필을 저장했습니다.` });
    }

    resetCredentialProfileForm();
    await loadConfig({ silent: true });
  } catch (error) {
    notify({
      type: "error",
      title: "프로필 저장 실패",
      message: error.message,
      timeout: 5200,
    });
  }
}

async function onCredentialProfileListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id) return;

  const profile = state.credentialProfiles.find((item) => item.id === id);
  if (!profile) return;

  if (action === "edit-profile") {
    fillCredentialProfileForm(profile);
    notify({ type: "info", title: "프로필 편집", message: `${profile.name} 프로필을 편집 중입니다.` });
    return;
  }

  if (action === "delete-profile") {
    const confirmed = window.confirm(`${profile.name} 프로필을 삭제할까요?`);
    if (!confirmed) return;
    try {
      await fetchJson(`/api/credential-profiles/${id}`, { method: "DELETE" });
      resetCredentialProfileForm();
      await loadConfig({ silent: true });
      notify({ type: "success", title: "프로필 삭제 완료", message: `${profile.name} 프로필을 삭제했습니다.` });
    } catch (error) {
      notify({ type: "error", title: "프로필 삭제 실패", message: error.message, timeout: 5200 });
    }
  }
}

function getRecommendedAction(row) {
  if (row.recommended_action) return row.recommended_action;
  if (row.reason_code && reasonCodeGuideMap[row.reason_code]) return reasonCodeGuideMap[row.reason_code];
  return actionGuideMap[row.status] || "상세 로그를 확인해 추가 점검을 진행해 주세요.";
}

function formatProbeInfo(item) {
  const probe = item.probe_result || {};
  const probeStatus = probe.probe_status || "SKIPPED";
  const probeDetail = probe.probe_detail || "-";
  const probeMeta = probe.probe_meta || {};
  const metaParts = [];

  if (probeMeta.query_type_name) metaParts.push(`type=${probeMeta.query_type_name}`);
  if (Number.isInteger(probeMeta.rcode)) metaParts.push(`rcode=${probeMeta.rcode}`);
  if (Number.isInteger(probeMeta.answer_count)) metaParts.push(`answers=${probeMeta.answer_count}`);
  if (Number.isInteger(probeMeta.version)) metaParts.push(`version=${probeMeta.version}`);
  if (Number.isInteger(probeMeta.stratum)) metaParts.push(`stratum=${probeMeta.stratum}`);
  if (Number.isInteger(probeMeta.mode)) metaParts.push(`mode=${probeMeta.mode}`);
  if (probeMeta.parse_error) metaParts.push(`parse_error=${probeMeta.parse_error}`);

  const answers = Array.isArray(probeMeta.answers) ? probeMeta.answers : [];
  const answerText = answers
    .slice(0, 2)
    .map((answer) => {
      const typeName = answer.type_name || "TYPE";
      if (typeName === "A") return `A:${answer.address || "-"}`;
      if (typeName === "AAAA") return `AAAA:${answer.address || "-"}`;
      if (typeName === "MX") return `MX:${answer.preference || "-"} ${answer.exchange || "-"}`;
      if (typeName === "TXT") {
        const txtValues = Array.isArray(answer.txt) ? answer.txt.slice(0, 2) : [];
        return `TXT:${txtValues.join("|") || "-"}`;
      }
      if (typeName === "SRV") return `SRV:${answer.port || "-"}->${answer.target || "-"}`;
      if (typeName === "SOA") return `SOA:${answer.mname || "-"}`;
      return `${typeName}:${answer.name || "-"}`;
    })
    .join(", ");
  if (answerText) metaParts.push(answerText);

  if (metaParts.length > 0) {
    return `Probe ${probeStatus}: ${probeDetail} (${metaParts.join(" | ")})`;
  }
  return `Probe ${probeStatus}: ${probeDetail}`;
}

function formatAttemptSummary(item) {
  if (!Array.isArray(item.attempts) || item.attempts.length === 0) return "-";
  return item.attempts.map((attempt) => `${attempt.attempt}:${attempt.status}`).join(" / ");
}

function formatConsistency(item) {
  const label = item.consistency || "UNKNOWN";
  const scoreRaw = Number(item.consistency_score);
  const score = Number.isFinite(scoreRaw) ? scoreRaw.toFixed(0) : "0";
  return `${label} ${score}%`;
}

function consistencyBadgeClass(consistency) {
  if (consistency === "STABLE") return "text-bg-success";
  if (consistency === "FLAKY") return "text-bg-warning";
  return "text-bg-secondary";
}

function updateMetricCards(payload) {
  const local = payload.local_metrics || {};
  const summary = payload.summary || {};
  document.getElementById("cpuMetric").textContent = `${local.cpu_percent ?? "-"}%`;
  document.getElementById("ramMetric").textContent = `${local.memory_percent ?? "-"}%`;
  document.getElementById("diskMetric").textContent = `${local.disk_percent ?? "-"}%`;
  document.getElementById("totalChecksMetric").textContent = summary.total_checks ?? "-";
}

function updateStatusChips(payload) {
  const counts = payload.summary?.status_counts || {};
  const serviceCounts = payload.service_checks?.summary?.status_counts || {};
  const timeoutLike = (counts.TIMEOUT ?? 0) + (counts.FILTERED ?? 0);
  const unreachable =
    (counts.UNKNOWN_HOST ?? 0) +
    (counts.NO_ROUTE ?? 0) +
    (counts.HOST_UNREACHABLE ?? 0) +
    (counts.NETWORK_UNREACHABLE ?? 0);
  const errorLike = (counts.ERROR ?? 0) + (counts.UDP_CLOSED ?? 0);

  document.getElementById("statusOpenCount").textContent = (counts.OPEN ?? 0) + (counts.UDP_OPEN_OR_FILTERED ?? 0);
  document.getElementById("statusRefusedCount").textContent = counts.REFUSED ?? 0;
  document.getElementById("statusTimeoutCount").textContent = timeoutLike;
  document.getElementById("statusUnknownCount").textContent = unreachable;
  document.getElementById("statusErrorCount").textContent = errorLike;
  document.getElementById("serviceStoppedCount").textContent = serviceCounts.STOPPED ?? 0;
}

function renderRemoteMetrics(remoteMetrics) {
  const tbody = document.getElementById("remoteMetricsBody");
  if (!Array.isArray(remoteMetrics) || remoteMetrics.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted py-3">아직 수집된 원격 리소스 데이터가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = remoteMetrics
    .map((item) => {
      const ok = item.status === "OK";
      const cpu = ok ? `${item.cpu_percent}%` : "-";
      const mem = ok ? `${item.memory_percent}%` : "-";
      const detailParts = [ok ? "정상" : item.detail || "오류"];
      if (item.credential_profile) detailParts.push(`계정: ${item.credential_profile}`);
      if (item.credential_source) detailParts.push(`소스: ${item.credential_source}`);
      const detail = detailParts.join(" | ");
      const badgeClass = ok ? "text-bg-success" : "text-bg-danger";
      return `
        <tr>
          <td>${item.server_name ?? "-"}</td>
          <td>${item.host ?? "-"}</td>
          <td>${cpu}</td>
          <td>${mem}</td>
          <td><span class="badge ${badgeClass}">${detail}</span></td>
        </tr>
      `;
    })
    .join("");
}

function renderServiceResults(serviceChecks) {
  const tbody = document.getElementById("serviceResultBody");
  if (!serviceChecks || !Array.isArray(serviceChecks.results) || serviceChecks.results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted py-3">서비스 점검 대상이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = serviceChecks.results
    .map((item) => {
      let badgeClass = "text-bg-secondary";
      if (item.status === "RUNNING") badgeClass = "text-bg-success";
      if (item.status === "STOPPED") badgeClass = "text-bg-danger";
      if (item.status === "NOT_FOUND") badgeClass = "text-bg-warning";
      if (item.status === "ERROR") badgeClass = "text-bg-dark";
      const detailParts = [item.detail || "-"];
      if (item.credential_profile) detailParts.push(`계정: ${item.credential_profile}`);
      if (item.credential_source) detailParts.push(`소스: ${item.credential_source}`);
      return `
        <tr>
          <td>${item.server_name}</td>
          <td>${item.host}</td>
          <td>${item.service_name}</td>
          <td><span class="badge ${badgeClass}">${item.status}</span></td>
          <td>${detailParts.join(" | ")}</td>
        </tr>
      `;
    })
    .join("");
}

function buildResultRowHtml(item) {
  const rowClass = statusRowClassMap[item.status] || "status-error";
  const transport = String(item.transport || "tcp").toUpperCase();
  const probeText = formatProbeInfo(item);
  const consistencyText = formatConsistency(item);
  const attemptsText = formatAttemptSummary(item);
  const consistencyClass = consistencyBadgeClass(item.consistency);
  const detail = `${item.detail || "-"} | Reason: ${item.reason_code || "UNKNOWN"} | ${probeText} | Attempts: ${attemptsText}`;
  return `
    <tr class="${rowClass} virtual-row">
      <td>${item.server_name}</td>
      <td>${item.host}</td>
      <td>${item.port} <span class="text-muted">(${transport})</span></td>
      <td>
        <span class="badge status-badge">${item.status}</span>
        <div class="mt-1"><span class="badge ${consistencyClass}">${consistencyText}</span></div>
      </td>
      <td>${item.latency_ms}</td>
      <td><div class="detail-truncate">${detail}</div></td>
      <td>${getRecommendedAction(item)}</td>
    </tr>
  `;
}

function updateResultFilterMeta() {
  const meta = document.getElementById("resultFilterMeta");
  const total = Number.isFinite(state.resultPaging.total) ? state.resultPaging.total : state.results.length;
  const page = Number.isFinite(state.resultPaging.page) ? state.resultPaging.page : 1;
  meta.textContent = `${state.filteredResults.length} / ${total} (P${page})`;
}

function updateResultPagerButtons() {
  const prevBtn = document.getElementById("resultPrevPageBtn");
  const nextBtn = document.getElementById("resultNextPageBtn");
  if (!prevBtn || !nextBtn) return;

  const page = Math.max(1, state.resultPaging.page || 1);
  const pageSize = Math.max(1, state.resultPaging.pageSize || 200);
  const total = Math.max(0, state.resultPaging.total || 0);
  const maxPage = Math.max(1, Math.ceil(total / pageSize));

  prevBtn.disabled = page <= 1 || state.checkInProgress;
  nextBtn.disabled = page >= maxPage || state.checkInProgress;
}

async function loadLatestResultPage(page = 1) {
  const statusFilter = document.getElementById("resultStatusFilter").value;
  const transportFilter = document.getElementById("resultTransportFilter").value;
  const keyword = document.getElementById("resultSearchInput").value.trim();
  const params = new URLSearchParams();
  params.set("page", String(Math.max(1, page)));
  params.set("page_size", String(state.resultPaging.pageSize || 200));
  if (statusFilter && statusFilter !== "ALL") params.set("status", statusFilter);
  if (transportFilter && transportFilter !== "ALL") params.set("transport", transportFilter);
  if (keyword) params.set("keyword", keyword);

  const payload = await fetchJson(`/api/check/results?${params.toString()}`);
  state.resultPaging.page = Number(payload.page || page);
  state.resultPaging.pageSize = Number(payload.page_size || state.resultPaging.pageSize || 200);
  state.resultPaging.total = Number(payload.total || 0);
  state.results = Array.isArray(payload.items) ? payload.items : [];
  refreshResultView({ resetScroll: true });
  updateResultPagerButtons();
}

function applyResultFilters() {
  const statusFilter = document.getElementById("resultStatusFilter").value;
  const transportFilter = document.getElementById("resultTransportFilter").value;
  const keyword = document.getElementById("resultSearchInput").value.trim().toLowerCase();

  state.filteredResults = state.results.filter((item) => {
    if (statusFilter !== "ALL" && item.status !== statusFilter) return false;
    if (transportFilter !== "ALL" && String(item.transport || "").toLowerCase() !== transportFilter) return false;
    if (!keyword) return true;
    const text = [
      item.server_name,
      item.host,
      item.status,
      item.reason_code,
      item.detail,
      item.recommended_action,
    ]
      .join(" ")
      .toLowerCase();
    return text.includes(keyword);
  });
  updateResultFilterMeta();
}

function renderVirtualResultRows() {
  const tbody = document.getElementById("resultBody");
  const container = document.getElementById("resultTableContainer");
  const total = state.filteredResults.length;
  const colSpan = 7;

  if (total === 0) {
    const emptyMessage =
      state.results.length === 0
        ? "[종합 점검 시작] 버튼을 클릭해 주세요."
        : "조건에 맞는 결과가 없습니다.";
    tbody.innerHTML = `<tr><td colspan="7" class="text-muted py-3">${emptyMessage}</td></tr>`;
    return;
  }

  const rowHeight = state.resultView.rowHeight;
  const overscan = state.resultView.overscan;
  const viewportHeight = Math.max(container.clientHeight, rowHeight * 2);
  const visibleCount = Math.ceil(viewportHeight / rowHeight) + overscan * 2;
  const start = Math.max(0, Math.floor(container.scrollTop / rowHeight) - overscan);
  const end = Math.min(total, start + visibleCount);

  const topHeight = start * rowHeight;
  const bottomHeight = (total - end) * rowHeight;
  const rows = state.filteredResults.slice(start, end).map(buildResultRowHtml).join("");

  const topSpacer =
    topHeight > 0
      ? `<tr class="spacer-row"><td colspan="${colSpan}" style="height:${topHeight}px;"></td></tr>`
      : "";
  const bottomSpacer =
    bottomHeight > 0
      ? `<tr class="spacer-row"><td colspan="${colSpan}" style="height:${bottomHeight}px;"></td></tr>`
      : "";
  tbody.innerHTML = `${topSpacer}${rows}${bottomSpacer}`;
}

function refreshResultView({ resetScroll = false } = {}) {
  applyResultFilters();
  const container = document.getElementById("resultTableContainer");
  if (resetScroll) container.scrollTop = 0;
  renderVirtualResultRows();
}

function updateSummary(payload) {
  const summary = payload.summary || {};
  const counts = summary.status_counts || {};
  const probeCounts = summary.probe_status_counts || {};
  const transportCounts = summary.transport_counts || {};
  const consistencyCounts = summary.consistency_counts || {};
  const svc = payload.service_checks?.summary?.status_counts || {};
  const duration = Number(summary.duration_ms || 0).toFixed(2);

  document.getElementById("summaryText").textContent =
    `완료 ${summary.total_checks ?? 0}건 | TCP ${transportCounts.tcp ?? 0} | UDP ${transportCounts.udp ?? 0} | ` +
    `FILTERED ${counts.FILTERED ?? 0} | NO_ROUTE ${counts.NO_ROUTE ?? 0} | PROBE_OK ${probeCounts.PROBE_OK ?? 0} | ` +
    `STABLE ${consistencyCounts.STABLE ?? 0} | FLAKY ${consistencyCounts.FLAKY ?? 0} | ` +
    `서비스 STOPPED ${svc.STOPPED ?? 0} | ${duration}ms`;
}

function summarizeAdvancedTargets(portTargets) {
  if (!Array.isArray(portTargets) || !portTargets.length) return "-";
  const text = portTargets
    .slice(0, 2)
    .map((target) => `${target.port}/${String(target.transport).toUpperCase()}/${target.probe}`)
    .join(", ");
  return portTargets.length > 2 ? `${text} +${portTargets.length - 2}` : text;
}

function renderServerList() {
  const tbody = document.getElementById("serverListBody");
  if (!state.servers.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted py-3">등록된 서버가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.servers
    .map(
      (server) => `
      <tr>
        <td>${server.name}</td>
        <td>${server.host}</td>
        <td>${(server.ports || []).join(", ") || "-"}</td>
        <td>${summarizeAdvancedTargets(server.port_targets)}</td>
        <td>${(server.services || []).join(", ") || "-"}</td>
        <td>${server.enable_remote_metrics ? "Y" : "N"}</td>
        <td class="d-flex gap-2">
          <button class="btn btn-sm btn-outline-info" data-action="edit" data-id="${server.id}">수정</button>
          <button class="btn btn-sm btn-outline-danger" data-action="delete" data-id="${server.id}">삭제</button>
        </td>
      </tr>
    `
    )
    .join("");
}

function resetServerForm() {
  document.getElementById("editingServerId").value = "";
  document.getElementById("serverName").value = "";
  document.getElementById("serverHost").value = "";
  document.getElementById("serverPorts").value = "";
  document.getElementById("serverServices").value = "";
  document.getElementById("remoteMetricsEnabled").checked = true;
  renderCredentialProfileOptions("");
  state.draftPortTargets = [];
  renderDraftPortTargets();
  resetAdvancedPortTargetInputs();
}

function fillServerForm(server) {
  document.getElementById("editingServerId").value = server.id;
  document.getElementById("serverName").value = server.name;
  document.getElementById("serverHost").value = server.host;
  document.getElementById("serverPorts").value = (server.ports || []).join(",");
  document.getElementById("serverServices").value = (server.services || []).join(",");
  document.getElementById("remoteMetricsEnabled").checked = !!server.enable_remote_metrics;
  renderCredentialProfileOptions(server.credential_profile_id || "");
  state.draftPortTargets = (server.port_targets || [])
    .map(normalizeServerPortTarget)
    .filter((target) => target !== null);
  sortDraftPortTargets();
  renderDraftPortTargets();
  resetAdvancedPortTargetInputs();
}

async function loadConfig({ silent = false } = {}) {
  const config = await fetchJson("/api/config");
  state.servers = config.servers || [];
  state.templates = config.templates || [];
  state.credentialProfiles = config.credential_profiles || [];
  state.resultPaging.pageSize = Number(config.default_page_size || state.resultPaging.pageSize || 200);
  renderServerList();
  renderTemplateList();
  renderCredentialProfileList();
  renderCredentialProfileOptions(document.getElementById("serverCredentialProfile").value || "");
  if (!silent) {
    notify({
      type: "success",
      title: "Config Loaded",
      message: `Servers ${state.servers.length}, Templates ${state.templates.length}, Profiles ${state.credentialProfiles.length}`,
    });
  }
}
async function handleRunCheck() {
  const button = document.getElementById("checkBtn");
  const spinner = document.getElementById("checkSpinner");
  if (state.activeCheckEventSource) {
    try {
      state.activeCheckEventSource.close();
    } catch (_error) {
      // ignore
    }
    state.activeCheckEventSource = null;
  }
  state.checkInProgress = true;
  updateResultPagerButtons();
  button.disabled = true;
  spinner.classList.remove("d-none");
  setCheckProgress(0, "Progress 0%");
  notify({
    type: "info",
    title: "Check Started",
    message: "Running async infrastructure checks. Progress will update live.",
  });
  try {
    const payload = await new Promise((resolve, reject) => {
      const es = new EventSource("/api/check/stream");
      state.activeCheckEventSource = es;
      let finished = false;
      const cleanup = () => {
        if (state.activeCheckEventSource === es) {
          state.activeCheckEventSource = null;
        }
        es.close();
      };
      es.addEventListener("progress", (event) => {
        try {
          const data = JSON.parse(event.data || "{}");
          const percent = Number(data.progress_percent || 0);
          const processed = Number(data.processed || 0);
          const total = Number(data.total || 0);
          const last = data.last || {};
          const msg = `Progress ${percent.toFixed(1)}% (${processed}/${total}) ${last.server_name || ""} ${last.port || ""} ${last.status || ""}`.trim();
          setCheckProgress(percent, msg);
        } catch (_error) {
          // ignore parse errors
        }
      });
      es.addEventListener("done", (event) => {
        finished = true;
        try {
          const data = JSON.parse(event.data || "{}");
          cleanup();
          resolve(data);
        } catch (error) {
          cleanup();
          reject(error);
        }
      });
      es.addEventListener("error", (event) => {
        if (finished) return;
        try {
          if (event && event.data) {
            const parsed = JSON.parse(event.data);
            cleanup();
            reject(new Error(parsed.message || "Streaming check failed."));
            return;
          }
        } catch (_error) {
          // ignore parse error
        }
        cleanup();
        reject(new Error("Streaming check disconnected or failed."));
      });
    });
    updateMetricCards(payload);
    updateStatusChips(payload);
    renderRemoteMetrics(payload.remote_metrics);
    renderServiceResults(payload.service_checks);
    try {
      await loadLatestResultPage(1);
    } catch (_error) {
      state.results = Array.isArray(payload.port_checks?.results) ? payload.port_checks.results : [];
      state.resultPaging.page = 1;
      state.resultPaging.total = state.results.length;
      refreshResultView({ resetScroll: true });
      updateResultPagerButtons();
    }
    updateSummary(payload);
    document.getElementById("lastChecked").textContent = `Latest Check: ${formatDateTime(payload.checked_at)}`;
    setCheckProgress(100, "Progress 100% - Completed");
    window.setTimeout(() => hideCheckProgress(), 1200);
    await loadTrendData({ silent: true });
    notify({
      type: "success",
      title: "Check Completed",
      message: `Total ${payload.summary.total_checks} checks completed (${Number(payload.summary.duration_ms || 0).toFixed(2)}ms).`,
    });
  } catch (error) {
    hideCheckProgress();
    notify({
      type: "error",
      title: "Check Failed",
      message: error.message,
      timeout: 5200,
    });
  } finally {
    state.checkInProgress = false;
    updateResultPagerButtons();
    button.disabled = false;
    spinner.classList.add("d-none");
    if (state.activeCheckEventSource) {
      try {
        state.activeCheckEventSource.close();
      } catch (_error) {
        // ignore
      }
      state.activeCheckEventSource = null;
    }
  }
}
function getDownloadFileName(response) {
  const contentDisposition = response.headers.get("content-disposition");
  if (!contentDisposition) return "infrastructure-check-report.xlsx";
  const match = contentDisposition.match(/filename="?(.*?)"?$/i);
  return match && match[1] ? match[1] : "infrastructure-check-report.xlsx";
}

async function handleDownloadReport() {
  notify({
    type: "info",
    title: "Preparing Report",
    message: "Generating downloadable Excel report from the latest check result.",
  });

  try {
    const response = await fetch("/api/report/download");
    if (!response.ok) {
      let detail = `${response.status} ${response.statusText}`;
      try {
        const payload = await response.json();
        if (payload.detail) detail = payload.detail;
      } catch (_error) {
        // ignore parse error
      }
      throw new Error(detail);
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = getDownloadFileName(response);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);

    notify({
      type: "success",
      title: "Download Complete",
      message: "Report download started.",
    });
  } catch (error) {
    notify({
      type: "error",
      title: "Download Failed",
      message: error.message,
      timeout: 5200,
    });
  }
}

async function submitServerForm(event) {
  event.preventDefault();
  const editingId = document.getElementById("editingServerId").value.trim();
  const name = document.getElementById("serverName").value.trim();
  const host = document.getElementById("serverHost").value.trim();
  const ports = parsePorts(document.getElementById("serverPorts").value);
  const services = parseItems(document.getElementById("serverServices").value);
  const enableRemoteMetrics = document.getElementById("remoteMetricsEnabled").checked;
  const credentialProfileId = document.getElementById("serverCredentialProfile").value || null;

  if (!name || !host) {
    notify({ type: "warning", title: "입력값 확인", message: "서버명과 IP/Host는 필수입니다." });
    return;
  }
  if (ports.length === 0 && state.draftPortTargets.length === 0) {
    notify({
      type: "warning",
      title: "포트 대상 없음",
      message: "기본 포트 목록 또는 고급 포트 타깃 중 하나 이상을 입력해 주세요.",
    });
    return;
  }

  const payload = {
    name,
    host,
    ports,
    port_targets: state.draftPortTargets,
    services,
    enable_remote_metrics: enableRemoteMetrics,
    credential_profile_id: credentialProfileId,
  };

  try {
    if (editingId) {
      await fetchJson(`/api/servers/${editingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "수정 완료", message: `${name} 서버 설정을 업데이트했습니다.` });
    } else {
      await fetchJson("/api/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({ type: "success", title: "등록 완료", message: `${name} 서버가 점검 대상에 추가되었습니다.` });
    }

    resetServerForm();
    await loadConfig({ silent: true });
  } catch (error) {
    notify({ type: "error", title: "저장 실패", message: error.message, timeout: 5200 });
  }
}

async function onServerListClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id) return;

  const server = state.servers.find((item) => item.id === id);
  if (!server) return;

  if (action === "edit") {
    fillServerForm(server);
    notify({ type: "info", title: "수정 모드", message: `${server.name} 항목을 수정 중입니다.` });
    return;
  }

  if (action === "delete") {
    const confirmed = window.confirm(`${server.name} (${server.host}) 항목을 삭제할까요?`);
    if (!confirmed) return;

    try {
      await fetchJson(`/api/servers/${id}`, { method: "DELETE" });
      if (document.getElementById("editingServerId").value === id) resetServerForm();
      await loadConfig({ silent: true });
      notify({ type: "success", title: "삭제 완료", message: `${server.name} 항목을 삭제했습니다.` });
    } catch (error) {
      notify({ type: "error", title: "삭제 실패", message: error.message, timeout: 5200 });
    }
  }
}

function onDraftTargetTableClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const action = target.dataset.action;
  const index = Number.parseInt(target.dataset.index || "", 10);
  if (!Number.isInteger(index)) return;

  if (action === "remove-target") {
    removeDraftPortTarget(index);
    return;
  }

  if (action === "edit-target") {
    const draftTarget = state.draftPortTargets[index];
    if (!draftTarget) return;
    fillAdvancedPortTargetInputs(draftTarget);
    setDraftTargetEditMode(index);
    renderDraftPortTargets();
    notify({ type: "info", title: "타깃 편집", message: `${draftTarget.port}/${draftTarget.transport}/${draftTarget.probe} 항목을 편집 중입니다.` });
  }
}

function onAdvancedTransportChange() {
  const transport = document.getElementById("advancedTransport").value;
  const probeSelect = document.getElementById("advancedProbe");
  const selectedProbe = normalizeProbe(probeSelect.value);
  const allowed = transport === "udp" ? UDP_PROBE_OPTIONS : TCP_PROBE_OPTIONS;

  if (!allowed.has(selectedProbe)) {
    probeSelect.value = "auto";
  } else if (selectedProbe !== probeSelect.value) {
    probeSelect.value = selectedProbe;
  }
}

async function onResultFiltersChanged() {
  try {
    await loadLatestResultPage(1);
  } catch (error) {
    notify({
      type: "error",
      title: "Result Query Failed",
      message: error.message,
      timeout: 5200,
    });
  }
}

function onResultTableScroll() {
  renderVirtualResultRows();
}

async function onResultPageNavigate(direction) {
  const current = Math.max(1, Number(state.resultPaging.page || 1));
  const pageSize = Math.max(1, Number(state.resultPaging.pageSize || 200));
  const maxPage = Math.max(1, Math.ceil(Math.max(0, Number(state.resultPaging.total || 0)) / pageSize));
  const targetPage = Math.max(1, Math.min(maxPage, current + direction));
  if (targetPage === current) return;
  try {
    await loadLatestResultPage(targetPage);
  } catch (error) {
    notify({
      type: "error",
      title: "Page Load Failed",
      message: error.message,
      timeout: 5200,
    });
  }
}

function onCredentialProviderChange() {
  const provider = document.getElementById("credentialProfileProvider").value;
  const passwordInput = document.getElementById("credentialProfilePassword");
  const secretRefInput = document.getElementById("credentialProfileSecretRef");

  if (provider === "dpapi") {
    passwordInput.disabled = false;
    secretRefInput.disabled = true;
    secretRefInput.value = "";
    return;
  }

  passwordInput.disabled = true;
  passwordInput.value = "";
  secretRefInput.disabled = false;
}

async function bootstrap() {
  document.getElementById("checkBtn").addEventListener("click", handleRunCheck);
  document.getElementById("downloadBtn").addEventListener("click", handleDownloadReport);
  document.getElementById("serverForm").addEventListener("submit", submitServerForm);
  document.getElementById("serverListBody").addEventListener("click", onServerListClick);
  document.getElementById("addPortTargetBtn").addEventListener("click", upsertDraftPortTargetFromForm);
  document.getElementById("portTargetBody").addEventListener("click", onDraftTargetTableClick);
  document.getElementById("advancedTransport").addEventListener("change", onAdvancedTransportChange);
  document.getElementById("tplAdBtn").addEventListener("click", () => applyRoleTemplate("AD"));
  document.getElementById("tplWebBtn").addEventListener("click", () => applyRoleTemplate("WEB"));
  document.getElementById("tplDbBtn").addEventListener("click", () => applyRoleTemplate("DB"));
  document.getElementById("templateListBody").addEventListener("click", onTemplateListClick);
  document.getElementById("saveTemplateBtn").addEventListener("click", saveTemplateFromDraft);
  document.getElementById("resetTemplateFormBtn").addEventListener("click", () => {
    resetTemplateForm();
    notify({ type: "info", title: "Template Form Reset", message: "Template form fields were reset." });
  });
  document.getElementById("credentialProfileForm").addEventListener("submit", submitCredentialProfileForm);
  document.getElementById("credentialProfileListBody").addEventListener("click", onCredentialProfileListClick);
  document.getElementById("credentialProfileProvider").addEventListener("change", onCredentialProviderChange);
  document.getElementById("resetCredentialProfileFormBtn").addEventListener("click", () => {
    resetCredentialProfileForm();
    onCredentialProviderChange();
    notify({ type: "info", title: "Profile Form Reset", message: "Credential profile form fields were reset." });
  });
  document.getElementById("resultSearchInput").addEventListener("input", onResultFiltersChanged);
  document.getElementById("resultStatusFilter").addEventListener("change", onResultFiltersChanged);
  document.getElementById("resultTransportFilter").addEventListener("change", onResultFiltersChanged);
  document.getElementById("resultTableContainer").addEventListener("scroll", onResultTableScroll);
  document.getElementById("resultPrevPageBtn").addEventListener("click", () => onResultPageNavigate(-1));
  document.getElementById("resultNextPageBtn").addEventListener("click", () => onResultPageNavigate(1));
  document.getElementById("trendRefreshBtn").addEventListener("click", () => loadTrendData({ silent: false }));
  document.getElementById("resetFormBtn").addEventListener("click", () => {
    resetServerForm();
    notify({ type: "info", title: "Form Reset", message: "Server form was reset to defaults." });
  });
  renderDraftPortTargets();
  renderTemplateList();
  renderCredentialProfileList();
  renderCredentialProfileOptions("");
  onCredentialProviderChange();
  refreshResultView({ resetScroll: true });
  updateResultPagerButtons();
  renderTrends();
  try {
    await loadConfig({ silent: false });
    await loadTrendData({ silent: true });
  } catch (error) {
    notify({ type: "error", title: "Initial Load Failed", message: error.message, timeout: 5200 });
  }
}
bootstrap();



