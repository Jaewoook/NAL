import axios, { type AxiosRequestConfig } from 'axios';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { ManagedItem } from './types';

let fallbackCsrfToken = '';

/**
 * Merges conditional Tailwind class lists without utility conflicts.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

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

/**
 * Validates that an external link uses an HTTP/HTTPS URL scheme.
 */
export function isSafeHttpUrl(u?: string): boolean {
  return /^https?:\/\//i.test(String(u || '').trim());
}

/**
 * Determines whether a task ID represents a persisted DB task whose logs can be streamed via SSE.
 */
export function isStreamableScanTaskId(taskId: string | undefined, failedStreamTaskIds: Set<string>): boolean {
  if (!taskId) return false;
  const id = String(taskId);
  if (id.startsWith('scan_') || id.startsWith('task_')) return false;
  return !failedStreamTaskIds.has(id);
}

/**
 * Checks case-insensitively whether a node name appears in the active scanning node list.
 */
export function isNodeScanningName(scanningNodes: string[], nodeName: string): boolean {
  const target = String(nodeName || '').trim().toLowerCase();
  if (!target) return false;
  return scanningNodes.some((n) => String(n).trim().toLowerCase() === target);
}

/**
 * Removes a node name (case-insensitively) from a scanning list, returning the same array reference if unchanged.
 */
export function removeScanningNodeName(scanningNodes: string[], nodeName: string): string[] {
  const target = String(nodeName || '').trim().toLowerCase();
  if (!target) return scanningNodes;
  const next = scanningNodes.filter((n) => String(n).trim().toLowerCase() !== target);
  return next.length === scanningNodes.length ? scanningNodes : next;
}

/**
 * Returns the sort priority rank (lower is more severe) for items table ordering.
 */
export function getItemSortRank(item: ManagedItem): number {
  if (item.crit_count > 0 || item.broken_linkage || (item.eol && item.eol.status === 'expired')) {
    return 0;
  }
  if (item.high_count > 0 || (item.eol && item.eol.status === 'expiring_soon')) {
    return 1;
  }
  if (item.outdated) {
    return 2;
  }
  return 3;
}

/**
 * Builds a stable identifier key for an item across a node and target type.
 */
export function getItemKey(item: ManagedItem, hubNode: string): string {
  const nodeName = item.node || hubNode || 'local';
  return `${nodeName}:${item.target_type}:${item.name}`;
}
