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

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const error = await response.json();
      if (error.detail) detail = error.detail;
    } catch (_e) {
      // ignore parse error
    }
    throw new Error(detail);
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

function updateMetricCards(payload) {
  const local = payload.local_metrics || {};
  const summary = payload.summary || {};

  document.getElementById("cpuMetric").textContent = `${local.cpu_percent ?? "-"}%`;
  document.getElementById("ramMetric").textContent = `${local.memory_percent ?? "-"}%`;
  document.getElementById("diskMetric").textContent = `${local.disk_percent ?? "-"}%`;
  document.getElementById("totalChecksMetric").textContent = summary.total_checks ?? "-";
}

function renderRemoteMetrics(remoteMetrics) {
  const tbody = document.getElementById("remoteMetricsBody");
  if (!Array.isArray(remoteMetrics) || remoteMetrics.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-muted py-3">표시할 원격 리소스가 없습니다.</td></tr>`;
    return;
  }

  tbody.innerHTML = remoteMetrics
    .map((item) => {
      const status = item.status || "UNKNOWN";
      const cpu = status === "OK" ? `${item.cpu_percent}%` : "-";
      const mem = status === "OK" ? `${item.memory_percent}%` : "-";
      const detail = status === "OK" ? "정상" : item.detail || "오류";
      return `
        <tr>
          <td>${item.server_name ?? "-"}</td>
          <td>${item.host ?? "-"}</td>
          <td>${cpu}</td>
          <td>${mem}</td>
          <td><span class="badge text-bg-${status === "OK" ? "success" : "danger"}">${detail}</span></td>
        </tr>
      `;
    })
    .join("");
}

function renderCheckResults(results) {
  const tbody = document.getElementById("resultBody");
  if (!Array.isArray(results) || results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-muted py-3">점검 결과가 없습니다.</td></tr>`;
    return;
  }

  const rows = results
    .map((item) => {
      const rowClass = statusRowClassMap[item.status] || "status-error";
      const detail = item.detail || "-";
      return `
        <tr class="${rowClass}">
          <td>${item.server_name}</td>
          <td>${item.host}</td>
          <td>${item.port}</td>
          <td><span class="badge status-badge">${item.status}</span></td>
          <td>${item.latency_ms}</td>
          <td>${detail}</td>
        </tr>
      `;
    })
    .join("");

  tbody.innerHTML = rows;
}

function renderServiceResults(serviceChecks) {
  const tbody = document.getElementById("serviceResultBody");
  if (!serviceChecks || !Array.isArray(serviceChecks.results) || serviceChecks.results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-muted py-3">서비스 점검 대상이 없습니다.</td></tr>`;
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
          <td>${item.detail ?? "-"}</td>
        </tr>
      `;
    })
    .join("");
}

function updateSummary(payload) {
  const summary = payload.summary || {};
  const counts = summary.status_counts || {};
  const svc = payload.service_checks?.summary?.status_counts || {};
  document.getElementById("summaryText").textContent =
    `완료 ${summary.total_checks ?? 0}건 | OPEN ${counts.OPEN ?? 0} | REFUSED ${counts.REFUSED ?? 0} | ` +
    `TIMEOUT ${counts.TIMEOUT ?? 0} | UNKNOWN_HOST ${counts.UNKNOWN_HOST ?? 0} | 서비스 STOPPED ${svc.STOPPED ?? 0} | ${(summary.duration_ms ?? 0).toFixed(2)}ms`;
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
    tbody.innerHTML = `<tr><td colspan="6" class="text-muted py-3">등록된 서버가 없습니다.</td></tr>`;
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
          <button class="btn btn-sm btn-outline-primary" data-action="edit" data-id="${server.id}">수정</button>
          <button class="btn btn-sm btn-outline-danger" data-action="delete" data-id="${server.id}">삭제</button>
        </td>
      </tr>
    `
    )
    .join("");
}

async function loadConfig() {
  const config = await fetchJson("/api/config");
  state.servers = config.servers || [];
  renderServerList();
}

async function handleRunCheck() {
  const button = document.getElementById("checkBtn");
  const spinner = document.getElementById("checkSpinner");

  button.disabled = true;
  spinner.classList.remove("d-none");
  try {
    const payload = await fetchJson("/api/check");
    updateMetricCards(payload);
    renderRemoteMetrics(payload.remote_metrics);
    renderCheckResults(payload.port_checks.results);
    renderServiceResults(payload.service_checks);
    updateSummary(payload);
    document.getElementById("lastChecked").textContent = `최근 점검: ${payload.checked_at}`;
  } catch (error) {
    alert(`점검 중 오류가 발생했습니다.\n${error.message}`);
  } finally {
    button.disabled = false;
    spinner.classList.add("d-none");
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
    alert("서버명, 호스트, 유효한 포트 목록을 입력하세요.");
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
    } else {
      await fetchJson("/api/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }

    resetServerForm();
    await loadConfig();
  } catch (error) {
    alert(`저장 실패: ${error.message}`);
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
    return;
  }

  if (action === "delete") {
    const confirmed = window.confirm(`${server.name} (${server.host}) 항목을 삭제하시겠습니까?`);
    if (!confirmed) return;

    try {
      await fetchJson(`/api/servers/${id}`, { method: "DELETE" });
      if (document.getElementById("editingServerId").value === id) resetServerForm();
      await loadConfig();
    } catch (error) {
      alert(`삭제 실패: ${error.message}`);
    }
  }
}

async function bootstrap() {
  document.getElementById("checkBtn").addEventListener("click", handleRunCheck);
  document.getElementById("serverForm").addEventListener("submit", submitServerForm);
  document.getElementById("serverListBody").addEventListener("click", onServerListClick);
  document.getElementById("resetFormBtn").addEventListener("click", resetServerForm);

  try {
    await loadConfig();
  } catch (error) {
    alert(`초기 설정 로드 실패: ${error.message}`);
  }
}

bootstrap();
