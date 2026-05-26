const state = {
  servers: [],
  draftPortTargets: [],
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
  OPEN: "정상 통신 가능",
  REFUSED: "서비스가 포트를 리슨 중인지 확인",
  TIMEOUT: "방화벽/ACL 드롭 가능성 확인",
  FILTERED: "인바운드/아웃바운드 방화벽 정책 확인",
  NO_ROUTE: "게이트웨이/라우팅/vSwitch 경로 확인",
  HOST_UNREACHABLE: "대상 서버 전원/네트워크 상태 확인",
  NETWORK_UNREACHABLE: "서브넷/VLAN/라우팅 테이블 확인",
  UNKNOWN_HOST: "DNS 설정 또는 호스트명 오타 확인",
  UDP_OPEN_OR_FILTERED: "UDP 특성상 무응답일 수 있음, DNS/NTP 프로브 권장",
  UDP_CLOSED: "UDP 포트 닫힘 또는 ICMP Port Unreachable",
  PROBE_TIMEOUT: "앱 프로브 타임아웃, 서비스 자체 응답 지연 확인",
  PROBE_FAILED: "프로브 핸드셰이크 실패, 앱 로그 확인",
  INVALID_RESPONSE: "앱 프로토콜 응답 형식 확인",
  ERROR: "reason_code와 서버 로그 추가 확인",
};

function notify({ type = "info", title = "안내", message = "", timeout = 3600 }) {
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
      <button type="button" class="notice-close" aria-label="닫기">&times;</button>
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

function normalizePortTarget(input) {
  const port = Number.parseInt(input.port, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const transport = String(input.transport || "tcp").toLowerCase();
  const probe = String(input.probe || "auto").toLowerCase();
  const retries = Number.parseInt(input.retries, 10);
  if (!["tcp", "udp"].includes(transport)) return null;
  if (!["auto", "none", "http", "https", "rdp", "dns", "ntp"].includes(probe)) return null;
  if (!Number.isInteger(retries) || retries < 0 || retries > 5) return null;
  return { port, transport, probe, retries };
}

function addOrReplaceDraftPortTarget(target) {
  const key = `${target.port}/${target.transport}/${target.probe}`;
  const idx = state.draftPortTargets.findIndex(
    (item) => `${item.port}/${item.transport}/${item.probe}` === key
  );
  if (idx >= 0) {
    state.draftPortTargets[idx] = target;
  } else {
    state.draftPortTargets.push(target);
  }
  state.draftPortTargets.sort((a, b) => a.port - b.port);
}

function renderDraftPortTargets() {
  const tbody = document.getElementById("portTargetBody");
  if (!state.draftPortTargets.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-muted py-2">고급 타깃이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.draftPortTargets
    .map(
      (target, index) => `
      <tr>
        <td>${target.port}</td>
        <td>${target.transport.toUpperCase()}</td>
        <td>${target.probe}</td>
        <td>${target.retries}</td>
        <td>
          <button class="btn btn-sm btn-outline-danger" data-action="remove-target" data-index="${index}">
            삭제
          </button>
        </td>
      </tr>
    `
    )
    .join("");
}

function resetAdvancedPortTargetInputs() {
  document.getElementById("advancedPort").value = "";
  document.getElementById("advancedTransport").value = "tcp";
  document.getElementById("advancedProbe").value = "auto";
  document.getElementById("advancedRetries").value = "2";
}

function addDraftPortTargetFromForm() {
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
      title: "고급 타깃 입력값 오류",
      message: "Port(1~65535), Transport, Probe, Retries(0~5)를 확인해 주세요.",
      timeout: 4800,
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
  renderDraftPortTargets();
  notify({
    type: "info",
    title: "고급 타깃 삭제",
    message: `${removed.port}/${removed.transport}/${removed.probe} 항목을 삭제했습니다.`,
  });
}

function getRecommendedAction(row) {
  if (row.recommended_action) return row.recommended_action;
  return actionGuideMap[row.status] || "상세 로그를 확인해 추가 점검해 주세요.";
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
    tbody.innerHTML =
      '<tr><td colspan="5" class="text-muted py-3">아직 수집된 원격 리소스 데이터가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = remoteMetrics
    .map((item) => {
      const ok = item.status === "OK";
      const cpu = ok ? `${item.cpu_percent}%` : "-";
      const mem = ok ? `${item.memory_percent}%` : "-";
      const detail = ok ? "정상" : item.detail || "오류";
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

function renderCheckResults(results) {
  const tbody = document.getElementById("resultBody");
  if (!Array.isArray(results) || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted py-3">점검 결과가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = results
    .map((item) => {
      const rowClass = statusRowClassMap[item.status] || "status-error";
      const transport = String(item.transport || "tcp").toUpperCase();
      const probe = item.probe_result || {};
      const probeText =
        probe.probe_status && probe.probe_status !== "SKIPPED"
          ? `Probe ${probe.probe_status}: ${probe.probe_detail || "-"}`
          : "Probe SKIPPED";
      const detail = `${item.detail || "-"} | Reason: ${item.reason_code || "UNKNOWN"} | ${probeText}`;
      return `
        <tr class="${rowClass}">
          <td>${item.server_name}</td>
          <td>${item.host}</td>
          <td>${item.port} <span class="text-muted">(${transport})</span></td>
          <td><span class="badge status-badge">${item.status}</span></td>
          <td>${item.latency_ms}</td>
          <td>${detail}</td>
          <td>${getRecommendedAction(item)}</td>
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
      return `
        <tr>
          <td>${item.server_name}</td>
          <td>${item.host}</td>
          <td>${item.service_name}</td>
          <td><span class="badge ${badgeClass}">${item.status}</span></td>
          <td>${item.detail || "-"}</td>
        </tr>
      `;
    })
    .join("");
}

function updateSummary(payload) {
  const summary = payload.summary || {};
  const counts = summary.status_counts || {};
  const probeCounts = summary.probe_status_counts || {};
  const transportCounts = summary.transport_counts || {};
  const svc = payload.service_checks?.summary?.status_counts || {};
  const duration = Number(summary.duration_ms || 0).toFixed(2);
  document.getElementById("summaryText").textContent =
    `완료 ${summary.total_checks ?? 0}건 | TCP ${transportCounts.tcp ?? 0} | UDP ${transportCounts.udp ?? 0} | ` +
    `FILTERED ${counts.FILTERED ?? 0} | NO_ROUTE ${counts.NO_ROUTE ?? 0} | PROBE_OK ${probeCounts.PROBE_OK ?? 0} | ` +
    `서비스 STOPPED ${svc.STOPPED ?? 0} | ${duration}ms`;
}

function resetServerForm() {
  document.getElementById("editingServerId").value = "";
  document.getElementById("serverName").value = "";
  document.getElementById("serverHost").value = "";
  document.getElementById("serverPorts").value = "";
  document.getElementById("serverServices").value = "";
  document.getElementById("remoteMetricsEnabled").checked = true;
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
  state.draftPortTargets = (server.port_targets || []).map((item) => ({
    port: item.port,
    transport: item.transport || "tcp",
    probe: item.probe || "auto",
    retries: Number.isInteger(item.retries) ? item.retries : 2,
  }));
  renderDraftPortTargets();
}

function summarizeAdvancedTargets(portTargets) {
  if (!Array.isArray(portTargets) || !portTargets.length) return "-";
  const text = portTargets
    .slice(0, 2)
    .map((t) => `${t.port}/${String(t.transport).toUpperCase()}/${t.probe}`)
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

async function loadConfig({ silent = false } = {}) {
  const config = await fetchJson("/api/config");
  state.servers = config.servers || [];
  renderServerList();
  if (!silent) {
    notify({
      type: "success",
      title: "설정 로드 완료",
      message: `등록된 점검 대상 ${state.servers.length}개를 불러왔습니다.`,
    });
  }
}

async function handleRunCheck() {
  const button = document.getElementById("checkBtn");
  const spinner = document.getElementById("checkSpinner");

  button.disabled = true;
  spinner.classList.remove("d-none");
  notify({
    type: "info",
    title: "점검 시작",
    message: "비동기 병렬 점검을 실행합니다. 완료되면 결과가 자동 갱신됩니다.",
  });

  try {
    const payload = await fetchJson("/api/check");
    updateMetricCards(payload);
    updateStatusChips(payload);
    renderRemoteMetrics(payload.remote_metrics);
    renderCheckResults(payload.port_checks.results);
    renderServiceResults(payload.service_checks);
    updateSummary(payload);
    document.getElementById("lastChecked").textContent = `최근 점검: ${formatDateTime(payload.checked_at)}`;

    notify({
      type: "success",
      title: "점검 완료",
      message: `총 ${payload.summary.total_checks}건 점검 완료 (${Number(payload.summary.duration_ms || 0).toFixed(2)}ms).`,
    });
  } catch (error) {
    notify({
      type: "error",
      title: "점검 실패",
      message: error.message,
      timeout: 5200,
    });
  } finally {
    button.disabled = false;
    spinner.classList.add("d-none");
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
    title: "리포트 생성 중",
    message: "최근 점검 결과를 엑셀 파일로 준비하고 있습니다.",
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
      title: "다운로드 완료",
      message: "엑셀 리포트 파일이 다운로드되었습니다.",
    });
  } catch (error) {
    notify({
      type: "error",
      title: "다운로드 실패",
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

  if (!name || !host) {
    notify({
      type: "warning",
      title: "입력값 확인",
      message: "서버명과 IP/Host는 필수입니다.",
      timeout: 4600,
    });
    return;
  }
  if (ports.length === 0 && state.draftPortTargets.length === 0) {
    notify({
      type: "warning",
      title: "포트 대상 없음",
      message: "기본 포트 목록 또는 고급 포트 타깃 중 하나 이상을 입력해 주세요.",
      timeout: 4600,
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
  };

  try {
    if (editingId) {
      await fetchJson(`/api/servers/${editingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({
        type: "success",
        title: "수정 완료",
        message: `${name} 서버 설정이 업데이트되었습니다.`,
      });
    } else {
      await fetchJson("/api/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      notify({
        type: "success",
        title: "등록 완료",
        message: `${name} 서버가 점검 대상에 추가되었습니다.`,
      });
    }

    resetServerForm();
    await loadConfig({ silent: true });
  } catch (error) {
    notify({
      type: "error",
      title: "저장 실패",
      message: error.message,
      timeout: 5200,
    });
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
    notify({
      type: "info",
      title: "수정 모드",
      message: `${server.name} 항목을 수정 중입니다. 값 변경 후 저장해 주세요.`,
    });
    return;
  }

  if (action === "delete") {
    const confirmed = window.confirm(`${server.name} (${server.host}) 항목을 삭제할까요?`);
    if (!confirmed) return;

    try {
      await fetchJson(`/api/servers/${id}`, { method: "DELETE" });
      if (document.getElementById("editingServerId").value === id) resetServerForm();
      await loadConfig({ silent: true });
      notify({
        type: "success",
        title: "삭제 완료",
        message: `${server.name} 항목을 삭제했습니다.`,
      });
    } catch (error) {
      notify({
        type: "error",
        title: "삭제 실패",
        message: error.message,
      });
    }
  }
}

function onDraftTargetTableClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const action = target.dataset.action;
  if (action !== "remove-target") return;
  const index = Number.parseInt(target.dataset.index || "", 10);
  removeDraftPortTarget(index);
}

function onAdvancedTransportChange() {
  const transport = document.getElementById("advancedTransport").value;
  const probeSelect = document.getElementById("advancedProbe");
  if (transport === "udp" && ["http", "https", "rdp"].includes(probeSelect.value)) {
    probeSelect.value = "auto";
  }
  if (transport === "tcp" && ["dns", "ntp"].includes(probeSelect.value)) {
    probeSelect.value = "auto";
  }
}

async function bootstrap() {
  document.getElementById("checkBtn").addEventListener("click", handleRunCheck);
  document.getElementById("downloadBtn").addEventListener("click", handleDownloadReport);
  document.getElementById("serverForm").addEventListener("submit", submitServerForm);
  document.getElementById("serverListBody").addEventListener("click", onServerListClick);
  document.getElementById("addPortTargetBtn").addEventListener("click", addDraftPortTargetFromForm);
  document.getElementById("portTargetBody").addEventListener("click", onDraftTargetTableClick);
  document.getElementById("advancedTransport").addEventListener("change", onAdvancedTransportChange);
  document.getElementById("resetFormBtn").addEventListener("click", () => {
    resetServerForm();
    notify({
      type: "info",
      title: "초기화 완료",
      message: "입력 폼을 초기 상태로 되돌렸습니다.",
    });
  });

  renderDraftPortTargets();
  try {
    await loadConfig({ silent: false });
  } catch (error) {
    notify({
      type: "error",
      title: "초기 로드 실패",
      message: error.message,
      timeout: 5200,
    });
  }
}

bootstrap();

