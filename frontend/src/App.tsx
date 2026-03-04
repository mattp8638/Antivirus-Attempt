import { ReactNode, useEffect, useMemo, useState } from "react";
import {
  AlertOut,
  AgentHeartbeatOut,
  FimViolationOut,
  HuntExample,
  ResponseActionOut,
  ResponsePlaybookOut,
  ThreatIndicatorOut,
  edrApi
} from "./api";

type TabKey =
  | "overview"
  | "alerts"
  | "agents"
  | "fim"
  | "intel"
  | "response"
  | "hunt";

export function App() {
  const [tab, setTab] = useState<TabKey>("overview");
  const [loading, setLoading] = useState(false);
  const [resolvingAlertId, setResolvingAlertId] = useState<number | null>(null);
  const [issuingAction, setIssuingAction] = useState(false);
  const [error, setError] = useState<string>("");
  const [successMessage, setSuccessMessage] = useState<string>("");

  const [remoteActionType, setRemoteActionType] = useState("quick_scan");
  const [remoteTarget, setRemoteTarget] = useState("");
  const [remoteEndpointId, setRemoteEndpointId] = useState("1");
  const [selectedEndpointId, setSelectedEndpointId] = useState("all");
  const [devicePageEndpointId, setDevicePageEndpointId] = useState<string | null>(null);

  const [alerts, setAlerts] = useState<AlertOut[]>([]);
  const [agents, setAgents] = useState<AgentHeartbeatOut[]>([]);
  const [fim, setFim] = useState<FimViolationOut[]>([]);
  const [intel, setIntel] = useState<ThreatIndicatorOut[]>([]);
  const [actions, setActions] = useState<ResponseActionOut[]>([]);
  const [playbooks, setPlaybooks] = useState<ResponsePlaybookOut[]>([]);
  const [huntExamples, setHuntExamples] = useState<HuntExample[]>([]);

  const refresh = async () => {
    setLoading(true);
    setError("");
    setSuccessMessage("");
    try {
      const [
        alertsData,
        agentsData,
        fimData,
        intelData,
        actionsData,
        playbooksData,
        huntData
      ] = await Promise.all([
        edrApi.fetchAlerts(50),
        edrApi.fetchAgents(50),
        edrApi.fetchFimViolations(50),
        edrApi.fetchThreatIndicators(50),
        edrApi.fetchResponseActions(50),
        edrApi.fetchResponsePlaybooks(50),
        edrApi.fetchHuntExamples()
      ]);
      setAlerts(alertsData);
      setAgents(agentsData);
      setFim(fimData);
      setIntel(intelData);
      setActions(actionsData);
      setPlaybooks(playbooksData);
      setHuntExamples(huntData.examples || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const resolveAlert = async (alertId: number) => {
    setResolvingAlertId(alertId);
    setError("");
    try {
      const updated = await edrApi.resolveAlert(alertId);
      setAlerts((prev) => prev.map((item) => (item.id === alertId ? updated : item)));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setResolvingAlertId(null);
    }
  };

  const issueRemoteAction = async () => {
    const endpointId = Number.parseInt(remoteEndpointId, 10);
    if (Number.isNaN(endpointId) || endpointId <= 0) {
      setError("Endpoint ID must be a positive number.");
      return;
    }

    setIssuingAction(true);
    setError("");
    setSuccessMessage("");
    try {
      const created = await edrApi.createResponseAction({
        action_type: remoteActionType,
        endpoint_id: endpointId,
        parameters: {
          target: remoteTarget.trim() || null,
          requested_via: "frontend_console"
        },
        details: {
          requested_at: new Date().toISOString(),
          source: "TamsilCMS Frontend"
        }
      });
      setActions((prev) => [created, ...prev]);
      setSuccessMessage(`Queued action #${created.id} (${created.action_type}) for endpoint ${created.endpoint_id}.`);
      setRemoteTarget("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIssuingAction(false);
    }
  };

  const scopeLabel = selectedEndpointId === "all" ? "All Endpoints" : `Endpoint ${selectedEndpointId}`;

  const selectedAgent = useMemo(() => {
    if (selectedEndpointId === "all") {
      return null;
    }
    return agents.find((item) => String(item.endpoint_id) === selectedEndpointId) ?? null;
  }, [agents, selectedEndpointId]);

  const devicePageAgent = useMemo(() => {
    if (!devicePageEndpointId) {
      return null;
    }
    return agents.find((item) => String(item.endpoint_id) === devicePageEndpointId) ?? null;
  }, [agents, devicePageEndpointId]);

  const devicePageAlerts = useMemo(() => {
    if (!devicePageEndpointId) {
      return [];
    }
    return alerts.filter((item) => String(item.endpoint_id) === devicePageEndpointId);
  }, [alerts, devicePageEndpointId]);

  const devicePageFim = useMemo(() => {
    if (!devicePageEndpointId) {
      return [];
    }
    return fim.filter((item) => String(item.endpoint_id) === devicePageEndpointId);
  }, [fim, devicePageEndpointId]);

  const devicePageActions = useMemo(() => {
    if (!devicePageEndpointId) {
      return [];
    }
    return actions.filter((item) => String(item.endpoint_id) === devicePageEndpointId);
  }, [actions, devicePageEndpointId]);

  const scopedAgents = useMemo(
    () => (selectedEndpointId === "all" ? agents : agents.filter((item) => String(item.endpoint_id) === selectedEndpointId)),
    [agents, selectedEndpointId]
  );

  const scopedAlerts = useMemo(
    () => (selectedEndpointId === "all" ? alerts : alerts.filter((item) => String(item.endpoint_id) === selectedEndpointId)),
    [alerts, selectedEndpointId]
  );

  const scopedFim = useMemo(
    () => (selectedEndpointId === "all" ? fim : fim.filter((item) => String(item.endpoint_id) === selectedEndpointId)),
    [fim, selectedEndpointId]
  );

  const scopedActions = useMemo(
    () => (selectedEndpointId === "all" ? actions : actions.filter((item) => String(item.endpoint_id) === selectedEndpointId)),
    [actions, selectedEndpointId]
  );

  const scopedPlaybooks = useMemo(
    () =>
      selectedEndpointId === "all"
        ? playbooks
        : playbooks.filter((item) => String(item.endpoint_id) === selectedEndpointId),
    [playbooks, selectedEndpointId]
  );

  const scopedIntel = intel;

  const staleAgents = useMemo(
    () =>
      scopedAgents.filter((item) => {
        const ts = new Date(item.last_seen).getTime();
        if (Number.isNaN(ts)) {
          return false;
        }
        return Date.now() - ts > 5 * 60 * 1000;
      }),
    [scopedAgents]
  );

  const actionBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of scopedActions) {
      const key = item.status.toLowerCase();
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [scopedActions]);

  const topAlertRules = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of scopedAlerts) {
      const key = item.title || "unknown";
      counts[key] = (counts[key] || 0) + 1;
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [scopedAlerts]);

  const triageQueue = useMemo(
    () =>
      scopedAlerts
        .filter((item) => item.status.toLowerCase() !== "resolved")
        .sort((a, b) => {
          const score = (v: string) => {
            const s = v.toLowerCase();
            if (s === "critical") return 4;
            if (s === "high") return 3;
            if (s === "medium") return 2;
            return 1;
          };
          return score(b.severity) - score(a.severity);
        })
        .slice(0, 8),
    [scopedAlerts]
  );

  const recentTimeline = useMemo(() => {
    const items: { id: string; kind: string; label: string; when: string; severity: string }[] = [];
    for (const alert of scopedAlerts.slice(0, 12)) {
      items.push({
        id: `alert-${alert.id}`,
        kind: "Alert",
        label: `${alert.title} (EP ${alert.endpoint_id})`,
        when: alert.timestamp,
        severity: alert.severity
      });
    }
    for (const change of scopedFim.slice(0, 12)) {
      items.push({
        id: `fim-${change.id}`,
        kind: "FIM",
        label: `${change.violation_type}: ${change.path}`,
        when: change.detected_at,
        severity: "medium"
      });
    }
    for (const action of scopedActions.slice(0, 12)) {
      items.push({
        id: `action-${action.id}`,
        kind: "Response",
        label: `${action.action_type} (${action.status})`,
        when: action.created_at,
        severity: action.status.toLowerCase() === "failed" ? "high" : "low"
      });
    }
    return items
      .sort((a, b) => new Date(b.when).getTime() - new Date(a.when).getTime())
      .slice(0, 12);
  }, [scopedAlerts, scopedFim, scopedActions]);

  const counts = useMemo(
    () => ({
      alerts: scopedAlerts.length,
      agents: scopedAgents.length,
      fim: scopedFim.length,
      intel: scopedIntel.length,
      response: scopedActions.length + scopedPlaybooks.length,
      hunt: huntExamples.length
    }),
    [
      scopedAlerts.length,
      scopedAgents.length,
      scopedFim.length,
      scopedIntel.length,
      scopedActions.length,
      scopedPlaybooks.length,
      huntExamples.length
    ]
  );

  const openAlerts = useMemo(
    () => scopedAlerts.filter((item) => item.status.toLowerCase() !== "resolved").length,
    [scopedAlerts]
  );

  const criticalAlerts = useMemo(
    () => scopedAlerts.filter((item) => item.severity.toLowerCase() === "critical").length,
    [scopedAlerts]
  );

  const endpointCoverage = useMemo(() => {
    if (agents.length === 0) {
      return "0 online";
    }
    const online = agents.filter((item) => item.status.toLowerCase() === "online").length;
    return `${online}/${agents.length} online`;
  }, [agents]);

  useEffect(() => {
    if (!agents.length) {
      return;
    }

    if (selectedEndpointId !== "all") {
      setRemoteEndpointId(selectedEndpointId);
      return;
    }

    const current = Number.parseInt(remoteEndpointId, 10);
    if (Number.isNaN(current) || current <= 0) {
      setRemoteEndpointId(String(agents[0].endpoint_id));
    }
  }, [agents, remoteEndpointId, selectedEndpointId]);

  useEffect(() => {
    if (!devicePageEndpointId) {
      return;
    }
    setRemoteEndpointId(devicePageEndpointId);
  }, [devicePageEndpointId]);

  const openDevicePage = (endpointId: string) => {
    setSelectedEndpointId(endpointId);
    setRemoteEndpointId(endpointId);
    setDevicePageEndpointId(endpointId);
  };

  return (
    <div className="app">
      <header className="topbar panelLike">
        <div className="topbarCopy">
          <p className="kicker">TamsilCMS Sentinel</p>
          <h1>Security Operations Dashboard</h1>
          <p>Connected to {edrApi.baseUrl}</p>
        </div>
        <div className="topbarActions">
          <StatusPill label={loading ? "Syncing" : "Live"} tone={loading ? "warning" : "success"} />
          <button className="primaryBtn" onClick={() => void refresh()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh Data"}
          </button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {successMessage && <div className="success">{successMessage}</div>}

      <section className="panelSub deviceScope">
        <div className="deviceScopeTop">
          <label>
            Active Device Scope
            <select
              value={selectedEndpointId}
              onChange={(event) => {
                const value = event.target.value;
                setSelectedEndpointId(value);
                if (value === "all") {
                  setDevicePageEndpointId(null);
                }
              }}
            >
              <option value="all">All Endpoints</option>
              {agents.map((item) => (
                <option key={item.id} value={String(item.endpoint_id)}>
                  Endpoint {item.endpoint_id} · {item.hostname}
                </option>
              ))}
            </select>
          </label>
          <div className="deviceScopeMeta">
            {selectedAgent ? (
              <>
                <p>
                  <strong>{selectedAgent.hostname}</strong> · v{selectedAgent.agent_version}
                </p>
                <p>
                  Last Seen {formatTimestamp(selectedAgent.last_seen)} · {withBadge(selectedAgent.status, `status-${selectedAgent.status.toLowerCase()}`)}
                </p>
                <button className="ghostBtn" onClick={() => openDevicePage(String(selectedAgent.endpoint_id))}>
                  Open Device Telemetry Page
                </button>
              </>
            ) : (
              <p>Fleet-wide telemetry view. Select a device to inspect and control a single endpoint.</p>
            )}
          </div>
        </div>
      </section>

      <section className="statsGrid">
        <MetricCard label={`${scopeLabel} Open Alerts`} value={String(openAlerts)} accent="danger" />
        <MetricCard label={`${scopeLabel} Critical`} value={String(criticalAlerts)} accent="danger" />
        <MetricCard label="Agent Coverage" value={selectedEndpointId === "all" ? endpointCoverage : (selectedAgent ? selectedAgent.status : "offline")} accent="neutral" />
        <MetricCard label="Hunt Queries" value={String(counts.hunt)} accent="info" />
      </section>

      {devicePageAgent && (
        <section className="panel devicePage">
          <div className="devicePageHeader">
            <div>
              <h2>Device Telemetry: Endpoint {devicePageAgent.endpoint_id}</h2>
              <p>
                {devicePageAgent.hostname} · v{devicePageAgent.agent_version} · Last Seen {formatTimestamp(devicePageAgent.last_seen)}
              </p>
            </div>
            <button className="ghostBtn" onClick={() => setDevicePageEndpointId(null)}>Close Device Page</button>
          </div>

          <section className="panelSub remoteActions">
            <h3>Device Commands</h3>
            <p>Run remote actions directly against this endpoint.</p>
            <div className="remoteActionsGrid">
              <label>
                Endpoint ID
                <input value={String(devicePageAgent.endpoint_id)} disabled />
              </label>
              <label>
                Action
                <select value={remoteActionType} onChange={(event) => setRemoteActionType(event.target.value)}>
                  <option value="quick_scan">Quick Scan</option>
                  <option value="full_scan">Full Scan</option>
                  <option value="scan_file">Scan File</option>
                  <option value="isolate_endpoint">Isolate Endpoint</option>
                  <option value="collect_forensics">Collect Forensics</option>
                  <option value="unisolate_endpoint">Unisolate Endpoint</option>
                </select>
              </label>
              <label className="span2">
                Target (optional path/process/hash)
                <input
                  value={remoteTarget}
                  onChange={(event) => setRemoteTarget(event.target.value)}
                  placeholder="C:\\Users\\Public\\suspicious.exe"
                />
              </label>
            </div>
            <button className="primaryBtn" onClick={() => void issueRemoteAction()} disabled={issuingAction}>
              {issuingAction ? "Queueing..." : "Queue Command For This Device"}
            </button>
          </section>

          <h3>Alerts</h3>
          <Table
            columns={["ID", "Severity", "Title", "Status", "Timestamp"]}
            rows={devicePageAlerts.map((item) => [
              String(item.id),
              withBadge(item.severity, `severity-${item.severity.toLowerCase()}`),
              item.title,
              withBadge(item.status, `status-${item.status.toLowerCase()}`),
              formatTimestamp(item.timestamp)
            ])}
          />

          <h3>FIM Violations</h3>
          <Table
            columns={["ID", "Type", "Path", "Detected"]}
            rows={devicePageFim.map((item) => [
              String(item.id),
              item.violation_type,
              item.path,
              formatTimestamp(item.detected_at)
            ])}
          />

          <h3>Response Actions</h3>
          <Table
            columns={["ID", "Type", "Status", "Target", "Created", "Completed"]}
            rows={devicePageActions.map((item) => [
              String(item.id),
              item.action_type,
              withBadge(item.status, `status-${item.status.toLowerCase()}`),
              getActionTarget(item),
              formatTimestamp(item.created_at),
              item.completed_at ? formatTimestamp(item.completed_at) : "—"
            ])}
          />
        </section>
      )}

      <nav className="tabs" aria-label="Dashboard sections">
        <TabButton label="Overview" count={undefined} active={tab === "overview"} onClick={() => setTab("overview")} />
        <TabButton label="Alerts" count={counts.alerts} active={tab === "alerts"} onClick={() => setTab("alerts")} />
        <TabButton label="Agents" count={counts.agents} active={tab === "agents"} onClick={() => setTab("agents")} />
        <TabButton label="FIM" count={counts.fim} active={tab === "fim"} onClick={() => setTab("fim")} />
        <TabButton label="Intel" count={counts.intel} active={tab === "intel"} onClick={() => setTab("intel")} />
        <TabButton label="Response" count={counts.response} active={tab === "response"} onClick={() => setTab("response")} />
        <TabButton label="Hunt" count={counts.hunt} active={tab === "hunt"} onClick={() => setTab("hunt")} />
      </nav>

      <main className="panel">
        {tab === "overview" && (
          <div className="overviewGrid">
            <section className="panelSub">
              <h3>Threat Posture</h3>
              <div className="miniStats">
                <div>
                  <span>Unresolved</span>
                  <strong>{openAlerts}</strong>
                </div>
                <div>
                  <span>Critical</span>
                  <strong>{criticalAlerts}</strong>
                </div>
                <div>
                  <span>Stale Agents</span>
                  <strong>{staleAgents.length}</strong>
                </div>
                <div>
                  <span>Actions In Flight</span>
                  <strong>{(actionBreakdown.queued || 0) + (actionBreakdown.dispatched || 0)}</strong>
                </div>
              </div>
            </section>

            <section className="panelSub">
              <h3>Response Pipeline</h3>
              <div className="pipelineRow">
                <PipelineBadge label="Queued" value={actionBreakdown.queued || 0} cls="status-pending" />
                <PipelineBadge label="Dispatched" value={actionBreakdown.dispatched || 0} cls="status-running" />
                <PipelineBadge label="Completed" value={actionBreakdown.completed || 0} cls="status-completed" />
                <PipelineBadge label="Failed" value={actionBreakdown.failed || 0} cls="status-failed" />
              </div>
            </section>

            <section className="panelSub span2">
              <h3>Triage Queue</h3>
              <Table
                columns={["Severity", "Alert", "Endpoint", "Status", "Detected"]}
                rows={triageQueue.map((item) => [
                  withBadge(item.severity, `severity-${item.severity.toLowerCase()}`),
                  item.title,
                  String(item.endpoint_id),
                  withBadge(item.status, `status-${item.status.toLowerCase()}`),
                  formatTimestamp(item.timestamp)
                ])}
              />
            </section>

            <section className="panelSub">
              <h3>Top Detection Signals</h3>
              <ul className="insightList">
                {topAlertRules.map(([name, count]) => (
                  <li key={name}>
                    <span>{name}</span>
                    <strong>{count}</strong>
                  </li>
                ))}
                {topAlertRules.length === 0 && <li>No alert patterns yet.</li>}
              </ul>
            </section>

            <section className="panelSub">
              <h3>Recent Timeline</h3>
              <ul className="timelineList">
                {recentTimeline.map((item) => (
                  <li key={item.id}>
                    <span className="timelineMeta">{item.kind} · {timeAgo(item.when)}</span>
                    <span>{item.label}</span>
                    <span>{withBadge(item.severity, `severity-${item.severity.toLowerCase()}`)}</span>
                  </li>
                ))}
                {recentTimeline.length === 0 && <li>No recent telemetry.</li>}
              </ul>
            </section>
          </div>
        )}
        {tab === "alerts" && (
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scopedAlerts.length === 0 && (
                  <tr>
                    <td colSpan={7}>No data</td>
                  </tr>
                )}
                {scopedAlerts.map((item) => {
                  const isResolved = item.status.toLowerCase() === "resolved";
                  const isBusy = resolvingAlertId === item.id;
                  return (
                    <tr key={item.id}>
                      <td>{item.id}</td>
                      <td>
                        <span className={`badge severity-${item.severity.toLowerCase()}`}>{item.severity}</span>
                      </td>
                      <td>{item.title}</td>
                      <td>{item.endpoint_id}</td>
                      <td>
                        <span className={`badge status-${item.status.toLowerCase()}`}>{item.status}</span>
                      </td>
                      <td>{formatTimestamp(item.timestamp)}</td>
                      <td>
                        <button
                          className="ghostBtn"
                          onClick={() => void resolveAlert(item.id)}
                          disabled={isResolved || isBusy}
                        >
                          {isResolved ? "Resolved" : isBusy ? "Resolving..." : "Resolve"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {tab === "agents" && (
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Hostname</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th>Control</th>
                </tr>
              </thead>
              <tbody>
                {scopedAgents.length === 0 && (
                  <tr>
                    <td colSpan={6}>No data</td>
                  </tr>
                )}
                {scopedAgents.map((item) => {
                  const isSelected = selectedEndpointId !== "all" && String(item.endpoint_id) === selectedEndpointId;
                  return (
                    <tr key={item.id}>
                      <td>{item.endpoint_id}</td>
                      <td>{item.hostname}</td>
                      <td>{item.agent_version}</td>
                      <td>{withBadge(item.status, `status-${item.status.toLowerCase()}`)}</td>
                      <td>{formatTimestamp(item.last_seen)}</td>
                      <td>
                        <button
                          className="ghostBtn"
                          onClick={() => openDevicePage(String(item.endpoint_id))}
                          disabled={isSelected}
                        >
                          {isSelected ? "Selected" : "Open Device Page"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {tab === "fim" && (
          <Table
            columns={["ID", "Endpoint", "Type", "Path", "Detected"]}
            rows={scopedFim.map((item) => [
              String(item.id),
              String(item.endpoint_id),
              item.violation_type,
              item.path,
              formatTimestamp(item.detected_at)
            ])}
          />
        )}
        {tab === "intel" && (
          <Table
            columns={["ID", "Type", "Value", "Severity", "Source", "Last Seen"]}
            rows={scopedIntel.map((item) => [
              String(item.id),
              item.indicator_type,
              item.value,
              withBadge(item.severity, `severity-${item.severity.toLowerCase()}`),
              item.source,
              formatTimestamp(item.last_seen)
            ])}
          />
        )}
        {tab === "response" && (
          <>
            <section className="panelSub remoteActions">
              <h3>Remote Response Actions</h3>
              <p>Queue actions to endpoint agents through the backend command pipeline.</p>
              <div className="remoteActionsGrid">
                <label>
                  Endpoint ID
                  <select
                    value={remoteEndpointId}
                    onChange={(event) => setRemoteEndpointId(event.target.value)}
                    disabled={selectedEndpointId !== "all"}
                  >
                    {agents.map((agent) => (
                      <option key={agent.id} value={String(agent.endpoint_id)}>
                        {agent.endpoint_id} · {agent.hostname}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Action
                  <select value={remoteActionType} onChange={(event) => setRemoteActionType(event.target.value)}>
                    <option value="quick_scan">Quick Scan</option>
                    <option value="full_scan">Full Scan</option>
                    <option value="scan_file">Scan File</option>
                    <option value="isolate_endpoint">Isolate Endpoint</option>
                    <option value="collect_forensics">Collect Forensics</option>
                    <option value="unisolate_endpoint">Unisolate Endpoint</option>
                  </select>
                </label>
                <label className="span2">
                  Target (optional path/process/hash)
                  <input
                    value={remoteTarget}
                    onChange={(event) => setRemoteTarget(event.target.value)}
                    placeholder="C:\\Users\\Public\\suspicious.exe"
                  />
                </label>
              </div>
              <button className="primaryBtn" onClick={() => void issueRemoteAction()} disabled={issuingAction}>
                {issuingAction ? "Queueing..." : "Queue Remote Action"}
              </button>
            </section>
            <h3>Actions</h3>
            <Table
              columns={["ID", "Type", "Endpoint", "Status", "Target", "Created", "Completed"]}
              rows={scopedActions.map((item) => [
                String(item.id),
                item.action_type,
                String(item.endpoint_id),
                withBadge(item.status, `status-${item.status.toLowerCase()}`),
                getActionTarget(item),
                formatTimestamp(item.created_at),
                item.completed_at ? formatTimestamp(item.completed_at) : "—"
              ])}
            />
            <h3>Playbooks</h3>
            <Table
              columns={["ID", "Name", "Endpoint", "Status", "Created"]}
              rows={scopedPlaybooks.map((item) => [
                String(item.id),
                item.name,
                String(item.endpoint_id),
                withBadge(item.status, `status-${item.status.toLowerCase()}`),
                formatTimestamp(item.created_at)
              ])}
            />
          </>
        )}
        {tab === "hunt" && (
          <div className="cards">
            {huntExamples.map((item) => (
              <article key={item.name} className="card">
                <h3>{item.name}</h3>
                <p>{item.description}</p>
                <pre>{item.query}</pre>
              </article>
            ))}
            {huntExamples.length === 0 && <div className="emptyState">No hunt examples available.</div>}
          </div>
        )}
      </main>
    </div>
  );
}

function TabButton(props: { label: string; count?: number; active: boolean; onClick: () => void }) {
  return (
    <button className={props.active ? "tab active" : "tab"} onClick={props.onClick}>
      <span>{props.label}</span>
      {typeof props.count === "number" && <span className="tabCount">{props.count}</span>}
    </button>
  );
}

function Table(props: { columns: string[]; rows: ReactNode[][] }) {
  return (
    <div className="tableWrap">
      <table>
        <thead>
          <tr>
            {props.columns.map((col) => (
              <th key={col}>{col}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {props.rows.length === 0 && (
            <tr>
              <td colSpan={props.columns.length}>No data</td>
            </tr>
          )}
          {props.rows.map((row, idx) => (
            <tr key={idx}>
              {row.map((cell, i) => (
                <td key={i}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MetricCard(props: { label: string; value: string; accent: "danger" | "neutral" | "info" }) {
  return (
    <article className={`metricCard metric-${props.accent}`}>
      <p>{props.label}</p>
      <h2>{props.value}</h2>
    </article>
  );
}

function StatusPill(props: { label: string; tone: "success" | "warning" }) {
  return <span className={`statusPill pill-${props.tone}`}>{props.label}</span>;
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function withBadge(value: string, cls: string): ReactNode {
  return <span className={`badge ${cls}`}>{value}</span>;
}

function getActionTarget(item: ResponseActionOut): string {
  const target = item.parameters?.target;
  if (typeof target === "string" && target.trim().length > 0) {
    return target;
  }
  return "—";
}

function PipelineBadge(props: { label: string; value: number; cls: string }) {
  return (
    <div className="pipelineBadge">
      <span>{props.label}</span>
      <strong>{props.value}</strong>
      <span className={`badge ${props.cls}`}>{props.label}</span>
    </div>
  );
}

function timeAgo(value: string): string {
  const parsed = new Date(value).getTime();
  if (Number.isNaN(parsed)) {
    return value;
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}
