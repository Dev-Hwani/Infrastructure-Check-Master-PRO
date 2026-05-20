const state = {
  servers: [],
};

const statusRowClassMap = {
  OPEN: "status-open",
  REFUSED: "status-refused",
  TIMEOUT: "status-timeout",
  UNKNOWN_HOST: "status-unknown",
  ERROR: "status-error",
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

  const close = () => {
    notice.remove();
  };

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

  document.getElementById("statusOpenCount").textContent = counts.OPEN ?? 0;
  document.getElementById("statusRefusedCount").textContent = counts.REFUSED ?? 0;
  document.getElementById("statusTimeoutCount").textContent = counts.TIMEOUT ?? 0;
  document.getElementById("statusUnknownCount").textContent = counts.UNKNOWN_HOST ?? 0;
  document.getElementById("statusErrorCount").textContent = counts.ERROR ?? 0;
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
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted py-3">점검 결과가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = results
    .map((item) => {
      const rowClass = statusRowClassMap[item.status] || "status-error";
      return `
        <tr class="${rowClass}">
          <td>${item.server_name}</td>
          <td>${item.host}</td>
          <td>${item.port}</td>
          <td><span class="badge status-badge">${item.status}</span></td>
          <td>${item.latency_ms}</td>
          <td>${item.detail || "-"}</td>
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
  const svc = payload.service_checks?.summary?.status_counts || {};
  const duration = Number(summary.duration_ms || 0).toFixed(2);
  document.getElementById("summaryText").textContent =
    `완료 ${summary.total_checks ?? 0}건 | OPEN ${counts.OPEN ?? 0} | REFUSED ${counts.REFUSED ?? 0} | ` +
    `TIMEOUT ${counts.TIMEOUT ?? 0} | UNKNOWN_HOST ${counts.UNKNOWN_HOST ?? 0} | 서비스 STOPPED ${svc.STOPPED ?? 0} | ${duration}ms`;
}

function resetServerForm() {
  document.getElementById("editingServerId").value = "";
  document.getElementById("serverName").value = "";
  document.getElementById("serverHost").value = "";
  document.getElementById("serverPorts").value = "";
  document.getElementById("serverServices").value = "";
  document.getElementById("remoteMetricsEnabled").checked = true;
}

function fillServerForm(server) {
  document.getElementById("editingServerId").value = server.id;
  document.getElementById("serverName").value = server.name;
  document.getElementById("serverHost").value = server.host;
  document.getElementById("serverPorts").value = server.ports.join(",");
  document.getElementById("serverServices").value = (server.services || []).join(",");
  document.getElementById("remoteMetricsEnabled").checked = !!server.enable_remote_metrics;
}

function renderServerList() {
  const tbody = document.getElementById("serverListBody");
  if (!state.servers.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted py-3">등록된 서버가 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = state.servers
    .map(
      (server) => `
      <tr>
        <td>${server.name}</td>
        <td>${server.host}</td>
        <td>${server.ports.join(", ")}</td>
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

  if (!name || !host || ports.length === 0) {
    notify({
      type: "warning",
      title: "입력값 확인",
      message: "서버명, IP/Host, 유효한 포트 목록을 모두 입력해 주세요.",
      timeout: 4600,
    });
    return;
  }

  const payload = {
    name,
    host,
    ports,
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

async function bootstrap() {
  document.getElementById("checkBtn").addEventListener("click", handleRunCheck);
  document.getElementById("downloadBtn").addEventListener("click", handleDownloadReport);
  document.getElementById("serverForm").addEventListener("submit", submitServerForm);
  document.getElementById("serverListBody").addEventListener("click", onServerListClick);
  document.getElementById("resetFormBtn").addEventListener("click", () => {
    resetServerForm();
    notify({
      type: "info",
      title: "초기화 완료",
      message: "입력 폼을 초기 상태로 되돌렸습니다.",
    });
  });

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

