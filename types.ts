/**
 * Type definitions for pi-opa extension
 * 
 * Defines interfaces for OPA integration, authorization,
 * policies, audit logging, and configuration.
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * OPA server configuration
 */
export interface OPAServerConfig {
  binaryPath: string;
  serverPort: number;
  serverHost: string;
  autoStart: boolean;
  logLevel: "debug" | "info" | "warn" | "error";
  configPath?: string;
  tls?: {
    cert: string;
    key: string;
    ca?: string;
  };
}

/**
 * Policy management configuration
 */
export interface PolicyConfig {
  directory: string;
  defaultPackage: string;
  autoReload: boolean;
  testOnLoad: boolean;
  bundlePath?: string;
}

/**
 * Authorization engine configuration
 */
export interface AuthorizationConfig {
  defaultDecision: "allow" | "deny";
  cacheDecisions: boolean;
  cacheTTL: number;
  maxContextDepth: number;
  requireAuthentication: boolean;
  decisionLogPath?: string;
}

/**
 * Audit logging configuration
 */
export interface AuditConfig {
  enabled: boolean;
  logDirectory: string;
  retentionDays: number;
  logSuccessful: boolean;
  logFailed: boolean;
  includeContext: boolean;
  format: "json" | "csv" | "both";
}

/**
 * A2A integration configuration
 */
export interface A2AIntegrationConfig {
  a2aEnabled: boolean;
  a2aExtension: string;
  interceptA2A: boolean;
  requireOPAForA2A: boolean;
}

/**
 * Complete OPA configuration
 */
export interface OPAConfig {
  opa: OPAServerConfig;
  policies: PolicyConfig;
  authorization: AuthorizationConfig;
  audit: AuditConfig;
  integration: A2AIntegrationConfig;
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTHORIZATION TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Identity information for authorization
 */
export interface AgentIdentity {
  id: string;
  name: string;
  type?: "human" | "service" | "bot" | "system";
  roles?: string[];
  groups?: string[];
  organization?: string;
  team?: string;
  authenticationMethod?: "token" | "mTLS" | "oauth" | "apikey";
  trustLevel?: "low" | "medium" | "high" | "critical";
}

/**
 * Action being performed
 */
export interface Action {
  type: string;
  name: string;
  category?: "read" | "write" | "delete" | "execute" | "admin";
  sensitivity?: "low" | "medium" | "high" | "critical";
  scope?: string;
}

/**
 * Resource being accessed
 */
export interface Resource {
  id: string;
  type: string;
  path?: string;
  owner?: string;
  classification?: "public" | "internal" | "confidential" | "secret";
  sensitivity?: "low" | "medium" | "high" | "critical";
  tags?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Contextual information for authorization
 */
export interface AuthorizationContext {
  timestamp: string;
  ip?: string;
  userAgent?: string;
  location?: {
    country?: string;
    region?: string;
    city?: string;
  };
  network?: {
    zone?: "internal" | "dmz" | "external";
    vpn?: boolean;
    tor?: boolean;
  };
  time?: {
    hour?: number;
    dayOfWeek?: number;
    isBusinessHours?: boolean;
    isMaintenanceWindow?: boolean;
  };
  request?: {
    id: string;
    method?: string;
    path?: string;
    headers?: Record<string, string>;
  };
  environment?: {
    production?: boolean;
    staging?: boolean;
    development?: boolean;
    emergency?: boolean;
  };
  custom?: Record<string, unknown>;
}

/**
 * Complete authorization request
 */
export interface AuthorizationRequest {
  agent: string | AgentIdentity;
  action: string | Action;
  resource: string | Resource;
  context: AuthorizationContext | Record<string, unknown>;
}

/**
 * Policy violation details
 */
export interface PolicyViolation {
  policy: string;
  rule: string;
  message: string;
  severity?: "info" | "warning" | "error" | "critical";
}

/**
 * Authorization response
 */
export interface AuthorizationResponse {
  allowed: boolean;
  decision: "allow" | "deny" | "conditional";
  reason?: string;
  violations?: PolicyViolation[];
  conditions?: Array<{
    type: string;
    description: string;
    required: boolean;
  }>;
  policyPath?: string;
  rulePath?: string;
  duration: number;
  timestamp: string;
  requestId: string;
  cached?: boolean;
  metadata?: {
    evaluatedPolicies?: string[];
    contextUsed?: string[];
    externalDataQueried?: string[];
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// POLICY TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * OPA Policy definition
 */
export interface Policy {
  id: string;
  name: string;
  description: string;
  path: string;
  package: string;
  version: string;
  rules: PolicyRule[];
  data?: Record<string, unknown>;
  tests?: PolicyTest[];
  metadata?: {
    author?: string;
    created?: string;
    updated?: string;
    tags?: string[];
    category?: string;
    scope?: "global" | "organization" | "team" | "project";
  };
}

/**
 * Individual policy rule
 */
export interface PolicyRule {
  name: string;
  description?: string;
  query: string;
  default: boolean;
  scope?: string;
  priority?: number;
}

/**
 * Policy test case
 */
export interface PolicyTest {
  name: string;
  description?: string;
  input: AuthorizationRequest;
  expected: {
    allowed: boolean;
    violations?: string[];
  };
}

/**
 * Policy validation result
 */
export interface PolicyValidationResult {
  valid: boolean;
  file: string;
  errors: string[];
  warnings?: string[];
  ast?: unknown;
}

/**
 * Policy test result
 */
export interface PolicyTestResult {
  name: string;
  file?: string;
  result: "PASS" | "FAIL" | "ERROR" | "SKIP";
  duration?: number;
  message?: string;
  expected?: unknown;
  actual?: unknown;
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Audit log entry
 */
export interface AuditEntry {
  id?: string;
  timestamp: string;
  requestId: string;
  agent: string;
  action: string;
  resource: string;
  decision: string;
  allowed: boolean;
  reason?: string;
  violations?: PolicyViolation[];
  policyPath?: string;
  rulePath?: string;
  context?: AuthorizationContext;
  duration: number;
  cached?: boolean;
  ip?: string;
  userAgent?: string;
  sessionId?: string;
  traceId?: string;
}

/**
 * Audit query filters
 */
export interface AuditQuery {
  startTime?: string;
  endTime?: string;
  agent?: string;
  action?: string;
  resource?: string;
  decision?: "allow" | "deny";
  allowed?: boolean;
  policy?: string;
  limit?: number;
  offset?: number;
}

/**
 * Audit statistics
 */
export interface AuditStats {
  totalEntries: number;
  allowed: number;
  denied: number;
  byAgent: Record<string, number>;
  byAction: Record<string, number>;
  byResource: Record<string, number>;
  byPolicy: Record<string, number>;
  averageDuration: number;
  cacheHitRate?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// OPA SERVER TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * OPA server status
 */
export interface OPAServerStatus {
  running: boolean;
  version?: string;
  revision?: string;
  uptime?: number;
  bundles?: string[];
  plugins?: string[];
  lastSuccessfulActivation?: string;
}

/**
 * OPA bundle information
 */
export interface OPABundle {
  name: string;
  revision: string;
  activeRevision: string;
  lastSuccessfulActivation: string;
  lastSuccessfulDownload: string;
  lastSuccessfulRequest: string;
  size: number;
}

/**
 * OPA decision log entry
 */
export interface OPADecisionLog {
  labels: Record<string, string>;
  decision_id: string;
  path: string;
  input: unknown;
  result: unknown;
  timestamp: string;
  metrics?: {
    timer_rego_module_compile_ns?: number;
    timer_rego_query_eval_ns?: number;
    timer_rego_query_parse_ns?: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRATION TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A2A agent information for authorization
 */
export interface A2AAgentInfo {
  url: string;
  name: string;
  identity?: AgentIdentity;
  capabilities?: string[];
  trustLevel?: "untrusted" | "basic" | "verified" | "enterprise";
  lastHealthCheck?: string;
  healthStatus?: "healthy" | "unhealthy" | "unknown";
}

/**
 * A2A request context for authorization
 */
export interface A2ARequestContext {
  agent: A2AAgentInfo;
  message?: unknown;
  task?: unknown;
  streaming?: boolean;
  async?: boolean;
}

/**
 * Cache entry for authorization decisions
 */
export interface AuthorizationCacheEntry {
  key: string;
  request: AuthorizationRequest;
  response: AuthorizationResponse;
  timestamp: number;
  ttl: number;
  hits: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Configuration change event
 */
export interface ConfigChangeEvent {
  key: string;
  oldValue: unknown;
  newValue: unknown;
  timestamp: string;
}

/**
 * Policy reload event
 */
export interface PolicyReloadEvent {
  policies: string[];
  errors?: string[];
  timestamp: string;
  duration: number;
}

/**
 * Error types
 */
export enum OPAErrorCode {
  SERVER_NOT_RUNNING = "SERVER_NOT_RUNNING",
  POLICY_NOT_FOUND = "POLICY_NOT_FOUND",
  POLICY_INVALID = "POLICY_INVALID",
  EVALUATION_ERROR = "EVALUATION_ERROR",
  CONFIG_ERROR = "CONFIG_ERROR",
  NETWORK_ERROR = "NETWORK_ERROR",
  TIMEOUT = "TIMEOUT",
  UNKNOWN = "UNKNOWN",
}

/**
 * OPA error
 */
export interface OPAError {
  code: OPAErrorCode;
  message: string;
  details?: unknown;
  timestamp: string;
}
