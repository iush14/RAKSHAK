import { auth } from '@/firebase';
import { type Finding } from '@/data/findings';

// Normalize FastAPI Backend URL configuration
let envRawUrl = import.meta.env.VITE_API_BASE_URL || (typeof window !== 'undefined' && window.location.hostname.includes('onrender.com') ? 'https://rakshak-backend-22wr.onrender.com' : 'http://127.0.0.1:8000');
if (typeof envRawUrl === 'string' && envRawUrl.includes('rakshak-backend.onrender.com') && !envRawUrl.includes('22wr')) {
  envRawUrl = 'https://rakshak-backend-22wr.onrender.com';
}
export const RAW_URL = (envRawUrl.startsWith('http://') || envRawUrl.startsWith('https://'))
  ? envRawUrl
  : `https://${envRawUrl}`;
export const CLEAN_BASE = RAW_URL.replace(/\/api\/?$/, '').replace(/\/+$/, '');
export const API_BASE_URL = `${CLEAN_BASE}/api`;
export const HEALTH_URL = `${CLEAN_BASE}/health`;

/**
 * Retrieve current Firebase ID token and return Authorization Bearer header.
 */
export async function getAuthHeader(): Promise<Record<string, string>> {
  try {
    const currentUser = auth.currentUser;
    if (currentUser) {
      const token = await currentUser.getIdToken();
      if (token) {
        return { 'Authorization': `Bearer ${token}` };
      }
    }
  } catch (err) {
    console.warn('[Rakshak API] Unable to get Firebase ID token:', err);
  }
  return {};
}

/**
 * Fetch wrapper that attaches Firebase ID token as Bearer token and credentials: include.
 */
export async function fetchWithAuth(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const authHeader = await getAuthHeader();
  const headers = new Headers(init?.headers || {});
  for (const [key, val] of Object.entries(authHeader)) {
    if (!headers.has(key)) {
      headers.set(key, val);
    }
  }
  return fetch(input, {
    ...init,
    headers,
    credentials: init?.credentials ?? 'include',
  });
}

export interface ApiSummaryResponse {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  overall_risk_score?: number;
  overall_risk?: number;
  security_health_score?: number;
  ai_remediations?: number;
  scan_id?: string;
  status?: string;
  new_findings?: number;
  open_findings?: number;
  fixed_findings?: number;
  reopened_findings?: number;
}

export interface BackendFinding {
  id?: number;
  finding_id?: number;
  scan_id?: string;
  vulnerability_id?: string;
  title: string;
  description?: string;
  severity: string;
  priority: string;
  risk_score: number;
  tool: string;
  target?: string;
  affected_packages?: string[];
  affected_package_count?: number;
  fixed_version?: string;
  fix_available?: boolean;
  exploitability?: number | string;
  production?: boolean;
  ai_explanation?: string;
  potential_impact?: string;
  recommended_action?: string;
  risk_summary?: string;
  finding_key?: string;
  scanner_type?: string;
  lifecycle_status?: 'new' | 'open' | 'fixed' | 'reopened';
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  fixed_at?: string | null;
  reopened_at?: string | null;
  occurrence_count?: number;
}

export interface ApiFindingsResponse {
  total?: number;
  findings?: BackendFinding[];
}

export interface ApiScanRequest {
  /** Required by the backend; defaults to "." (the configured scan root). */
  target_path?: string;
  code_scanning: boolean;
  dependency_scanning: boolean;
  secret_detection: boolean;
  container_scanning: boolean;
}

export interface ApiScanResponse {
  scan_id: string;
  target_path?: string;
  repository?: string | null;
  selected_scans?: {
    code_scanning: boolean;
    dependency_scanning: boolean;
    secret_detection: boolean;
    container_scanning: boolean;
  };
  status: string;
  findings?: BackendFinding[];
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  overall_risk_score: number;
  overall_risk?: number;
  errors?: Array<{ scanner: string; message: string }>;
}

export interface AIAnalysisResult {
  explanation: string;
  potentialImpact: string;
  recommendedAction: string;
  riskSummary: string;
}

/**
 * Create an Error carrying the HTTP status so callers (e.g. SecurityContext)
 * can distinguish authentication/session failures (401) from empty datasets
 * or connectivity problems. Phase 11A workspace isolation.
 */
export function createApiError(message: string, status?: number): Error & { status?: number } {
  const err = new Error(message) as Error & { status?: number };
  err.status = status;
  return err;
}

// GitHub OAuth & Repository Interfaces
export interface GitHubUser {
  id: number;
  login: string;
  name: string | null;
  avatar_url: string;
  html_url: string;
}

export interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  description: string | null;
  html_url: string;
  clone_url: string;
  default_branch: string;
  language: string | null;
  updated_at: string;
  owner: string;
}

export interface GitHubReposResponse {
  total: number;
  repositories: GitHubRepo[];
}

export interface GitHubScanRequest {
  owner: string;
  repo: string;
  ref?: string | null;
  code_scanning: boolean;
  dependency_scanning: boolean;
  secret_detection: boolean;
  container_scanning: boolean;
  container_image?: string | null;
}

export interface GitHubScanResponse {
  scan_id: string;
  status: string;
  repository: string;
  ref: string;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  overall_risk: number;
  code_scanning: boolean;
  dependency_scanning: boolean;
  secret_detection: boolean;
  container_scanning: boolean;
}

export interface ScanHistoryItem {
  scan_id: string;
  repository: string | null;
  target_path: string;
  status: string;
  event_type: string;
  ref: string | null;
  commit_sha: string | null;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
  started_at: string | null;
  completed_at: string | null;
  security_gate_status: 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR' | null;
  security_gate_reason: string | null;
}

export interface ScanFinding extends BackendFinding {
  id: number;
  scan_id: string;
}

export interface ScanDetail extends ScanHistoryItem {
  overall_risk: number;
  code_scanning: boolean;
  dependency_scanning: boolean;
  secret_detection: boolean;
  container_scanning: boolean;
  findings: ScanFinding[];
}

/**
 * Format scanner tool name for presentation
 */
function normalizeToolName(tool?: string): string {
  if (!tool) return 'Code Scanner';
  const t = tool.toLowerCase();
  if (t.includes('gitleaks') || t.includes('secret')) return 'Secret Detection';
  if (t.includes('container') || t.includes('docker') || t.includes('image')) return 'Container Scan';
  if (t.includes('code') || t.includes('ast') || t.includes('bandit')) return 'Code Scanner';
  if (t.includes('trivy')) return 'Trivy SCA';
  return tool;
}

/**
 * Convert backend finding data structure to frontend Finding model
 */
export function mapBackendFindingToFrontend(bf: BackendFinding, index: number = 0): Finding {
  const vulnerabilityId = bf.vulnerability_id?.trim() || undefined;
  const sevLower = (bf.severity || 'low').toLowerCase();
  const validSeverity: Finding['severity'] = 
    sevLower === 'critical' || sevLower === 'high' || sevLower === 'medium' ? sevLower : 'low';

  const prioUpper = (bf.priority || 'Low').toLowerCase();
  const validPriority: Finding['priority'] =
    prioUpper === 'critical' ? 'Critical' :
    prioUpper === 'high' ? 'High' :
    prioUpper === 'medium' ? 'Medium' : 'Low';

  const packageNames = bf.affected_packages && bf.affected_packages.length > 0 
    ? bf.affected_packages.join(', ')
    : (bf.target || 'General Package');

  const files = bf.target ? [bf.target] : (bf.affected_packages && bf.affected_packages.length > 0 ? bf.affected_packages : []);

  const hasFix = Boolean(bf.fix_available || (bf.fixed_version && bf.fixed_version.trim() !== '' && bf.fixed_version.toLowerCase() !== 'no fix available'));

  return {
    id: bf.id !== undefined ? `f-${bf.id}` : (vulnerabilityId ? `f-${vulnerabilityId}-${index}` : `f-${index}-${Date.now()}`),
    backendId: bf.id,
    scanId: bf.scan_id,
    target: bf.target,
    vulnerabilityId,
    cve: vulnerabilityId || 'Unavailable',
    title: bf.title || 'Security Vulnerability Finding',
    description: bf.description || bf.title || 'No detailed description provided.',
    severity: validSeverity,
    priority: validPriority,
    riskScore: typeof bf.risk_score === 'number' ? bf.risk_score : 0,
    exploitability: bf.exploitability !== undefined ? String(bf.exploitability) : '0.50',
    tool: normalizeToolName(bf.tool),
    scannerType: bf.scanner_type,
    package: packageNames,
    fixedVersion: bf.fixed_version && bf.fixed_version.trim() !== '' ? bf.fixed_version : (hasFix ? 'Fix Available' : 'No fix available'),
    productionStatus: bf.production !== false ? 'Yes' : 'No',
    status: hasFix ? 'Fix Available' : 'Active',
    lifecycleStatus: bf.lifecycle_status,
    occurrenceCount: bf.occurrence_count,
    affectedFiles: files,
    aiExplanation: bf.ai_explanation,
    potentialImpact: bf.potential_impact,
    recommendedAction: bf.recommended_action,
    riskSummary: bf.risk_summary,
    recommendedFix: bf.recommended_action || (hasFix ? `Upgrade ${packageNames} to ${bf.fixed_version || 'latest patch'}.` : undefined),
  };
}

// ============================================================
// AUTH & GITHUB API CLIENT METHODS
// ============================================================

/**
 * Fetch current authenticated user info from GET /api/auth/me
 */
export async function getAuthMe(): Promise<{ authenticated: boolean; user: GitHubUser | null }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/auth/me`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`Failed to check authentication: HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Log out GitHub session via POST /api/auth/logout
 */
export async function logoutAuth(): Promise<{ success: boolean; message: string }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/auth/logout`, {
    method: 'POST',
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`Logout failed: HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Fetch user repositories from GET /api/github/repos
 */
export async function getGitHubRepos(): Promise<GitHubReposResponse> {
  const res = await fetchWithAuth(`${API_BASE_URL}/github/repos`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (res.status === 401) {
    throw new Error('GitHub authentication required');
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch GitHub repositories: HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Fetch a single GitHub repository from GET /api/github/repos/{owner}/{repo}
 */
export async function getGitHubRepoDetail(owner: string, repo: string): Promise<{ repository: GitHubRepo }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/github/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch repository details: HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Scan a GitHub repository via POST /api/github/scan
 */
export async function scanGitHubRepository(req: GitHubScanRequest): Promise<GitHubScanResponse> {
  const payload = {
    owner: req.owner,
    repo: req.repo,
    ref: req.ref || null,
    code_scanning: Boolean(req.code_scanning),
    dependency_scanning: Boolean(req.dependency_scanning),
    secret_detection: Boolean(req.secret_detection),
    container_scanning: Boolean(req.container_scanning),
    container_image: req.container_scanning ? (req.container_image || null) : null,
  };

  const res = await fetchWithAuth(`${API_BASE_URL}/github/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let errorDetail = '';
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || '';
    } catch {
      errorDetail = await res.text().catch(() => '');
    }

    if (res.status === 401) {
      throw new Error('GitHub authentication required');
    }
    if (res.status === 404) {
      throw new Error(`Repository not found: ${req.owner}/${req.repo}`);
    }
    if (res.status >= 500) {
      throw new Error(`Repository scan failed: ${errorDetail || res.statusText}`);
    }
    throw new Error(`Scan request failed: HTTP ${res.status} - ${errorDetail || res.statusText}`);
  }

  return res.json();
}

// ============================================================
// DASHBOARD, SUMMARY & FINDINGS API CLIENT METHODS
// ============================================================

export async function getScans(filters?: {
  repository?: string;
  status?: string;
  event_type?: string;
  limit?: number;
  offset?: number;
}): Promise<{ items: ScanHistoryItem[]; total: number; limit: number; offset: number }> {
  const url = new URL(`${API_BASE_URL}/scans`);
  if (filters?.repository) url.searchParams.set('repository', filters.repository);
  if (filters?.status) url.searchParams.set('status', filters.status);
  if (filters?.event_type) url.searchParams.set('event_type', filters.event_type);
  if (filters?.limit !== undefined) url.searchParams.set('limit', String(filters.limit));
  if (filters?.offset !== undefined) url.searchParams.set('offset', String(filters.offset));

  const res = await fetch(url.toString(), { headers: { 'Accept': 'application/json' }, credentials: 'include' });
  if (!res.ok) throw createApiError(`Failed to fetch scan history: HTTP ${res.status}`, res.status);
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const res = await fetchWithAuth(`${API_BASE_URL}/scans/${encodeURIComponent(scanId)}`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) throw createApiError(res.status === 404 ? 'Scan not found' : `Failed to fetch scan: HTTP ${res.status}`, res.status);
  return res.json();
}

export async function getSecurityGate(scanId: string): Promise<{
  scan_id: string;
  status: 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR';
  reason: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}> {
  const res = await fetchWithAuth(`${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/security-gate`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) throw createApiError(`Failed to fetch security gate: HTTP ${res.status}`, res.status);
  return res.json();
}

/**
 * Fetch summary statistics from GET /api/summary
 */
export async function getSummary(): Promise<ApiSummaryResponse> {
  const res = await fetchWithAuth(`${API_BASE_URL}/summary`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw createApiError(`Failed to fetch summary: HTTP ${res.status} ${res.statusText}`, res.status);
  }
  const data = await res.json();
  const risk = typeof data.overall_risk === 'number' ? data.overall_risk : (data.overall_risk_score ?? 0);
  return {
    total_findings: data.total_findings ?? 0,
    critical: data.critical ?? 0,
    high: data.high ?? 0,
    medium: data.medium ?? 0,
    low: data.low ?? 0,
    overall_risk: risk,
    overall_risk_score: risk,
    security_health_score: data.security_health_score ?? Math.max(0, 100 - risk),
    ai_remediations: data.ai_remediations ?? 0,
    scan_id: data.scan_id,
    status: data.status,
  };
}

/**
 * Fetch findings from GET /api/findings with optional filters
 */
/**
 * Fetch findings.
 *
 * `scope` is explicit: 'latest' (default) returns the current scan's findings,
 * which is the same scan /api/summary describes, so the dashboard totals and
 * the Findings list agree. 'all' returns the full workspace history, and
 * `scan_id` pins the result to one scan.
 */
export async function getFindings(filters?: {
  severity?: string;
  priority?: string;
  tool?: string;
  search?: string;
  scope?: 'latest' | 'all';
  scanId?: string;
}): Promise<{ total: number; findings: Finding[] }> {
  const url = new URL(`${API_BASE_URL}/findings`);
  if (filters?.scope) {
    url.searchParams.set('scope', filters.scope);
  }
  if (filters?.scanId) {
    url.searchParams.set('scan_id', filters.scanId);
  }
  if (filters?.severity && filters.severity !== 'all') {
    url.searchParams.set('severity', filters.severity);
  }
  if (filters?.priority && filters.priority !== 'all') {
    url.searchParams.set('priority', filters.priority);
  }
  if (filters?.tool && filters.tool !== 'all') {
    url.searchParams.set('tool', filters.tool);
  }
  if (filters?.search && filters.search.trim()) {
    url.searchParams.set('search', filters.search.trim());
  }

  const res = await fetch(url.toString(), {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw createApiError(`Failed to fetch findings: HTTP ${res.status} ${res.statusText}`, res.status);
  }

  const data = await res.json();
  const rawFindings: BackendFinding[] = Array.isArray(data) ? data : (data.findings || []);
  const mappedFindings = rawFindings.map((bf, idx) => mapBackendFindingToFrontend(bf, idx));

  return {
    total: Array.isArray(data) ? rawFindings.length : (data.total ?? mappedFindings.length),
    findings: mappedFindings,
  };
}

/**
 * Fetch a single finding by vulnerability_id from GET /api/findings/{vulnerability_id}
 */
export async function getFindingDetail(vulnerabilityId: string): Promise<Finding> {
  const res = await fetchWithAuth(`${API_BASE_URL}/findings/${encodeURIComponent(vulnerabilityId)}`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    throw createApiError(`Failed to fetch finding ${vulnerabilityId}: HTTP ${res.status}`, res.status);
  }
  const data: BackendFinding = await res.json();
  return mapBackendFindingToFrontend(data, 0);
}

/**
 * Trigger AI analysis for a single finding via POST /api/findings/{vulnerability_id}/analyze
 */
export async function analyzeFindingWithAI(
  vulnerabilityId: string,
  findingId?: number,
): Promise<AIAnalysisResult & { fullFinding: Finding; findingId?: number }> {
  const normalizedVulnerabilityId = vulnerabilityId.trim();
  if (!normalizedVulnerabilityId || normalizedVulnerabilityId.toUpperCase() === 'UNKNOWN') {
    throw createApiError('Cannot analyze a finding without a valid vulnerability ID.');
  }
  // finding_id identifies the EXACT finding. Without it the backend falls back
  // to the newest finding sharing this vulnerability ID, which may be a
  // different file or package.
  const url = new URL(`${API_BASE_URL}/findings/${encodeURIComponent(normalizedVulnerabilityId)}/analyze`);
  if (findingId !== undefined) {
    url.searchParams.set('finding_id', String(findingId));
  }
  const res = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'Accept': 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw createApiError(`AI Analysis failed for ${vulnerabilityId}: HTTP ${res.status} ${errText || res.statusText}`, res.status);
  }
  const data: BackendFinding = await res.json();
  const explanation = data.ai_explanation?.trim();
  const potentialImpact = data.potential_impact?.trim();
  const recommendedAction = data.recommended_action?.trim();
  const riskSummary = data.risk_summary?.trim();
  if (!explanation || !potentialImpact || !recommendedAction || !riskSummary) {
    throw createApiError(`AI Analysis returned incomplete structured data for ${vulnerabilityId}`, res.status);
  }
  const fullFinding = mapBackendFindingToFrontend(data, 0);

  return {
    explanation,
    potentialImpact,
    recommendedAction,
    riskSummary,
    fullFinding,
    findingId: data.id,
  };
}

/**
 * Execute orchestrated security scan via POST /api/scan
 */
export async function performScan(req: ApiScanRequest): Promise<ApiScanResponse & { mappedFindings: Finding[] }> {
  const payload = {
    // "." is the configured scan root on the backend host. A hard-coded
    // 'test-project' default scanned whatever happened to sit at that name.
    target_path: req.target_path || '.',
    code_scanning: Boolean(req.code_scanning),
    dependency_scanning: Boolean(req.dependency_scanning),
    secret_detection: Boolean(req.secret_detection),
    container_scanning: Boolean(req.container_scanning),
  };

  const res = await fetchWithAuth(`${API_BASE_URL}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorText = await res.text().catch(() => '');
    throw new Error(`Scan orchestration failed: HTTP ${res.status} - ${errorText || res.statusText}`);
  }

  const data: ApiScanResponse = await res.json();
  const mappedFindings = (data.findings || []).map((bf, idx) => mapBackendFindingToFrontend(bf, idx));

  return {
    ...data,
    mappedFindings,
  };
}

/**
 * Health check to verify FastAPI connection
 */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(HEALTH_URL, {
      method: 'GET',
      credentials: 'include',
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Verify email address with token
 */
export async function verifyEmail(token: string): Promise<{ message: string; user?: any }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/auth/verify-email?token=${encodeURIComponent(token)}`, {
    method: 'GET',
    credentials: 'include',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw createApiError(data.detail || 'Email verification failed.', res.status);
  }
  return res.json();
}

/**
 * Resend email verification link
 */
export async function resendVerification(email: string): Promise<{ message: string }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/auth/resend-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
    credentials: 'include',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw createApiError(data.detail || 'Failed to resend verification email.', res.status);
  }
  return res.json();
}



export interface NotificationItem {
  id: number;
  user_id: number;
  scan_id?: string | null;
  finding_id?: number | null;
  notification_type: string;
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  is_read: boolean;
  created_at?: string | null;
}

export interface NotificationsResponse {
  notifications: NotificationItem[];
  unread_count: number;
}

/**
 * Fetch workspace notifications for current user from GET /api/notifications
 */
export async function getNotifications(limit: number = 50): Promise<NotificationsResponse> {
  const res = await fetchWithAuth(`${API_BASE_URL}/notifications?limit=${limit}`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) {
    throw createApiError(`Failed to fetch notifications: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

/**
 * Mark a single notification as read via POST /api/notifications/{id}/read
 */
export async function markNotificationAsRead(id: number): Promise<{ status: string; notification_id: number; is_read: boolean; unread_count: number }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/notifications/${id}/read`, {
    method: 'POST',
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) {
    throw createApiError(`Failed to mark notification as read: HTTP ${res.status}`, res.status);
  }
  return res.json();
}

/**
 * Mark all notifications as read via POST /api/notifications/read-all
 */
export async function markAllNotificationsAsRead(): Promise<{ status: string; message: string; unread_count: number }> {
  const res = await fetchWithAuth(`${API_BASE_URL}/notifications/read-all`, {
    method: 'POST',
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) {
    throw createApiError(`Failed to mark all notifications as read: HTTP ${res.status}`, res.status);
  }
  return res.json();
}
