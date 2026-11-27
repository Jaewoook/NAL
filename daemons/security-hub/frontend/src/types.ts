export type TargetType = 'docker' | 'brew' | 'apt' | 'daemon' | 'macos' | string;

export type TabType = 'docker' | 'brew' | 'daemons' | 'logs';

export interface SessionResponse {
  authenticated: boolean;
  subject?: string;
  username?: string;
  method?: string;
  has_passkeys?: boolean;
  oidc_configured?: boolean;
  csrf_token?: string;
}

export interface Vulnerability {
  id: string;
  summary: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  fixed_version?: string;
  url?: string;
}

export interface EoLInfo {
  product?: string;
  cycle?: string;
  status: 'supported' | 'expiring_soon' | 'expired' | 'unknown' | string;
  eol_date?: string;
  days_remaining?: number;
  message?: string;
}

export interface NodeInfo {
  name: string;
  url?: string;
  role: 'hub' | 'agent' | string;
  status?: 'approved' | 'pending' | 'rejected' | string;
  online: boolean;
  last_seen_at?: string;
  last_error?: string;
  os_version?: string;
  version?: string;
}

export interface ManagedItem {
  node?: string;
  target_type: TargetType;
  name: string;
  service_key?: string;
  image_ref?: string;
  current_version: string;
  current_digest?: string;
  latest_version: string;
  remote_digest?: string;
  available_tags?: string[];
  outdated: boolean;
  skipped: boolean;
  skipped_version?: string;
  security_override?: boolean;
  critical_path?: boolean;
  stateful?: boolean;
  broken_linkage: boolean;
  linkage_details?: string;
  release_notes_url?: string;
  vulnerabilities?: Vulnerability[];
  crit_count: number;
  high_count: number;
  med_count?: number;
  low_count?: number;
  eol?: EoLInfo;
  service_status?: 'running' | 'stopped' | string;
  has_rollback?: boolean;
  rollback_version?: string;
  last_checked_at?: string;
}

export interface ScanResult {
  scanned_at: string;
  nodes?: NodeInfo[] | null;
  items: ManagedItem[] | null;
  total_crit_cves?: number;
  total_high_cves?: number;
  total_eol_issues?: number;
  total_outdated?: number;
  total_skipped?: number;
  total_broken_brew?: number;
}

export interface Task {
  id: string;
  node?: string;
  task_type: string;
  target_type: string;
  target_name: string;
  from_version?: string;
  to_version?: string;
  triggered_by?: string;
  status: string;
  error_msg?: string;
  started_at?: string;
  finished_at?: string;
  duration_ms?: number;
}

export interface TaskLogLine {
  task_id?: string;
  seq?: number;
  logged_at: string;
  stream: string;
  line: string;
}

export interface DashboardResponse {
  hub_node: string;
  hub_version?: string;
  nodes: NodeInfo[] | null;
  scan: ScanResult | null;
  recent_tasks: Task[] | null;
  snapshots_count?: number;
  scanning: boolean;
  active_scan_task_id?: string;
  scanning_nodes: string[] | null;
}

export interface PendingUpdateRequest {
  node: string;
  target_type: TargetType;
  target_name: string;
  current_version: string;
  target_version: string;
  broken_linkage: boolean;
  stateful: boolean;
}

export interface NodeTestResponse {
  ok: boolean;
  latency_ms?: number;
  os_version?: string;
  info?: NodeInfo;
  error?: string;
}

export interface RenderedLogEntry {
  key: string;
  loggedAt?: string;
  stream?: string;
  line: string;
  rawText?: boolean;
}
