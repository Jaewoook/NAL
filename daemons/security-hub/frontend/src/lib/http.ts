import axios, { type AxiosRequestConfig } from 'axios';
import type {
  DashboardResponse,
  NodeTestResponse,
  PendingUpdateRequest,
  SessionResponse,
} from '../types';

let fallbackCsrfToken = '';

/**
 * Sets the fallback CSRF token returned by `/api/auth/session` when cookies are not directly readable.
 */
export function setCsrfToken(token: string): void {
  fallbackCsrfToken = token || '';
}

/**
 * Resolves the active CSRF token from `nal_csrf_token` cookie or in-memory fallback.
 */
export function getCsrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)nal_csrf_token=([^;]+)/);
  if (m) {
    try {
      return decodeURIComponent(m[1]);
    } catch {
      return m[1];
    }
  }
  return fallbackCsrfToken;
}

/**
 * Shared Axios client that automatically attaches `X-CSRF-Token` on state-mutating requests.
 */
export const apiClient = axios.create({
  withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
  const method = String(config.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const tok = getCsrfToken();
    if (tok) {
      config.headers = config.headers ?? new axios.AxiosHeaders();
      config.headers.set('X-CSRF-Token', tok);
    }
  }
  return config;
});

/**
 * Returns true if an Axios error represents an HTTP 401 Unauthorized response.
 */
export function isAxiosUnauthorized(err: unknown): boolean {
  return axios.isAxiosError(err) && err.response?.status === 401;
}

/**
 * Extracts a human-readable error message from an Axios error or generic exception.
 */
export function getAxiosErrorMessage(err: unknown, fallback = 'Request failed'): string {
  if (axios.isAxiosError(err)) {
    const data = err.response?.data as { error?: string } | undefined;
    if (data && typeof data === 'object' && typeof data.error === 'string' && data.error) {
      return data.error;
    }
    if (err.response?.statusText) {
      return err.response.statusText;
    }
    if (err.response?.status) {
      return `HTTP ${err.response.status}`;
    }
    return err.message || fallback;
  }
  return err instanceof Error ? err.message : String(err || fallback);
}

export type { AxiosRequestConfig };

export interface PasskeyRegisterBeginResp {
  challenge: string;
  rp_id?: string;
  user: string;
}

export interface PasskeyLoginBeginResp {
  challenge: string;
  rp_id?: string;
  allow_credentials?: string[] | null;
}

export interface ScanTriggerResp {
  task_id?: string;
  scanning_nodes?: string[];
}

/**
 * Centralized API endpoint definitions and request builders for the Security Hub backend.
 */
export const hubApi = {
  getSession: () => apiClient.get<SessionResponse>('/api/auth/session'),
  logout: () => apiClient.post('/api/auth/logout'),
  beginPasskeyRegister: () =>
    apiClient.post<PasskeyRegisterBeginResp>('/api/auth/passkey/register/begin'),
  finishPasskeyRegister: (payload: {
    credential_id: string;
    label: string;
    attestation_object: string;
    client_data_json: string;
  }) => apiClient.post('/api/auth/passkey/register/finish', payload),
  beginPasskeyLogin: () => apiClient.post<PasskeyLoginBeginResp>('/api/auth/passkey/login/begin'),
  finishPasskeyLogin: (payload: {
    credential_id: string;
    authenticator_data: string;
    client_data_json: string;
    signature: string;
  }) => apiClient.post('/api/auth/passkey/login/finish', payload),
  getDashboard: () => apiClient.get<DashboardResponse>('/api/dashboard'),
  triggerScan: (targetNode?: string) =>
    apiClient.post<ScanTriggerResp>('/api/scan', targetNode ? { node: targetNode } : undefined, {
      validateStatus: (s) => (s >= 200 && s < 300) || s === 409,
    }),
  testNodeConnection: (url: string, token: string, signal?: AbortSignal) =>
    apiClient.post<NodeTestResponse>('/api/nodes/test', { url, token }, { signal }),
  updateConfig: (
    req: PendingUpdateRequest,
    runBackup: boolean,
    enableDeadMan: boolean
  ): AxiosRequestConfig => ({
    url: '/api/update',
    method: 'POST',
    data: {
      node: req.node,
      target_type: req.target_type,
      target_name: req.target_name,
      target_version: req.target_version,
      broken_linkage: req.broken_linkage,
      stateful: req.stateful,
      run_backup: runBackup,
      enable_dead_man: enableDeadMan,
    },
  }),
  rollbackConfig: (node: string, serviceName: string): AxiosRequestConfig => ({
    url: '/api/rollback',
    method: 'POST',
    data: { node, service_name: serviceName },
  }),
  skipConfig: (
    node: string,
    targetType: string,
    targetName: string,
    version: string
  ): AxiosRequestConfig => ({
    url: '/api/skip',
    method: 'POST',
    data: { node, target_type: targetType, target_name: targetName, version },
  }),
  unskipConfig: (node: string, targetType: string, targetName: string): AxiosRequestConfig => ({
    url: '/api/skip',
    method: 'DELETE',
    params: { node, target_type: targetType, target_name: targetName },
  }),
  approveNodeConfig: (name: string): AxiosRequestConfig => ({
    url: '/api/nodes/approve',
    method: 'POST',
    params: { name },
  }),
  rejectNodeConfig: (name: string): AxiosRequestConfig => ({
    url: '/api/nodes/reject',
    method: 'POST',
    params: { name },
  }),
  saveNodeConfig: (name: string, url: string, token: string): AxiosRequestConfig => ({
    url: '/api/nodes',
    method: 'POST',
    data: { name, url, token },
  }),
  deleteNodeConfig: (name: string): AxiosRequestConfig => ({
    url: '/api/nodes',
    method: 'DELETE',
    params: { name },
  }),
  taskStreamUrl: (taskId: string) => `/api/tasks/${encodeURIComponent(taskId)}/stream`,
  taskDownloadUrl: (taskId: string) => `/api/tasks/${encodeURIComponent(taskId)}/download`,
};
