const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const API_KEY = import.meta.env.VITE_API_KEY || "";

export type AlertOut = {
  id: number;
  title: string;
  description: string;
  severity: string;
  endpoint_id: number;
  timestamp: string;
  status: string;
};

export type AgentHeartbeatOut = {
  id: number;
  endpoint_id: number;
  hostname: string;
  agent_version: string;
  status: string;
  last_seen: string;
};

export type FimViolationOut = {
  id: number;
  path: string;
  violation_type: string;
  endpoint_id: number;
  detected_at: string;
};

export type ThreatIndicatorOut = {
  id: number;
  indicator_type: string;
  value: string;
  source: string;
  severity: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
};

export type ResponseActionOut = {
  id: number;
  action_type: string;
  status: string;
  endpoint_id: number;
  parameters: Record<string, unknown>;
  created_at: string;
  executed_at?: string | null;
  completed_at?: string | null;
  details?: Record<string, unknown>;
};

export type ResponseActionCreateIn = {
  action_type: string;
  endpoint_id: number;
  parameters?: Record<string, unknown>;
  details?: Record<string, unknown>;
};

export type ResponsePlaybookOut = {
  id: number;
  name: string;
  status: string;
  endpoint_id: number;
  created_at: string;
};

export type HuntExample = {
  name: string;
  description: string;
  query: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...headers,
      ...(init?.headers || {})
    }
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`API ${response.status}: ${body}`);
  }
  return response.json() as Promise<T>;
}

export const edrApi = {
  baseUrl: API_BASE_URL,
  fetchAlerts: (limit = 50) => request<AlertOut[]>(`/edr/alerts?limit=${limit}`),
  resolveAlert: (alertId: number) => request<AlertOut>(`/edr/alerts/${alertId}/resolve`, { method: "POST" }),
  fetchAgents: (limit = 50) => request<AgentHeartbeatOut[]>(`/edr/agents?limit=${limit}`),
  fetchFimViolations: (limit = 50) => request<FimViolationOut[]>(`/edr/fim/violations?limit=${limit}`),
  fetchThreatIndicators: (limit = 50) => request<ThreatIndicatorOut[]>(`/edr/threat-intel/indicators?limit=${limit}`),
  fetchResponseActions: (limit = 50) => request<ResponseActionOut[]>(`/edr/response/actions?limit=${limit}`),
  createResponseAction: (payload: ResponseActionCreateIn) =>
    request<ResponseActionOut>(`/edr/response/actions`, { method: "POST", body: JSON.stringify(payload) }),
  fetchResponsePlaybooks: (limit = 50) => request<ResponsePlaybookOut[]>(`/edr/response/playbooks?limit=${limit}`),
  fetchHuntExamples: () => request<{ examples: HuntExample[]; count: number }>(`/edr/hunt/examples`)
};
