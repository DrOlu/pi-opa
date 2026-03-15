/**
 * Authorization Engine Module
 * 
 * Core authorization logic that integrates with OPA for policy evaluation.
 * Handles caching, context enrichment, and decision management.
 */

import type { OPACLient } from "./opa-client.js";
import type {
  AuthorizationConfig,
  AuthorizationRequest,
  AuthorizationResponse,
  AuthorizationCacheEntry,
  AuthorizationContext,
  AgentIdentity,
  Action,
  Resource,
} from "./types.js";

/**
 * Authorization Engine class
 */
export class AuthzEngine {
  private config: AuthorizationConfig;
  private opaClient: OPACLient;
  private cache: Map<string, AuthorizationCacheEntry> = new Map();
  private defaultPolicy = "pi.authz";

  constructor(config: AuthorizationConfig, opaClient: OPACLient) {
    this.config = config;
    this.opaClient = opaClient;
  }

  /**
   * Evaluate authorization request
   */
  async evaluate(request: AuthorizationRequest): Promise<AuthorizationResponse> {
    const startTime = Date.now();
    const requestId = this.generateId();

    try {
      // Normalize request
      const normalizedRequest = this.normalizeRequest(request);

      // Enrich context
      const enrichedRequest = this.enrichContext(normalizedRequest);

      // Check cache
      if (this.config.cacheDecisions) {
        const cached = this.getCachedDecision(enrichedRequest);
        if (cached) {
          return {
            ...cached,
            cached: true,
            duration: Date.now() - startTime,
            requestId,
          };
        }
      }

      // Evaluate through OPA
      const result = await this.opaClient.evaluate(this.defaultPolicy, enrichedRequest);

      // Process result
      const decision = this.processDecision(result, enrichedRequest);

      // Cache decision
      if (this.config.cacheDecisions) {
        this.cacheDecision(enrichedRequest, decision);
      }

      return {
        ...decision,
        duration: Date.now() - startTime,
        requestId,
      };
    } catch (error) {
      // Fail closed - deny on error
      return {
        allowed: false,
        decision: "deny",
        reason: `Authorization evaluation error: ${error}`,
        duration: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        requestId,
        policyPath: this.defaultPolicy,
      };
    }
  }

  /**
   * Evaluate multiple requests in batch
   */
  async evaluateBatch(requests: AuthorizationRequest[]): Promise<AuthorizationResponse[]> {
    return Promise.all(requests.map((req) => this.evaluate(req)));
  }

  /**
   * Check if action is allowed (simplified interface)
   */
  async isAllowed(
    agent: string,
    action: string,
    resource: string,
    context?: Record<string, unknown>
  ): Promise<boolean> {
    const request: AuthorizationRequest = {
      agent,
      action,
      resource,
      context: context || {},
    };

    const result = await this.evaluate(request);
    return result.allowed;
  }

  /**
   * Get authorization with detailed explanation
   */
  async explain(request: AuthorizationRequest): Promise<{
    allowed: boolean;
    explanation: string;
    policiesEvaluated: string[];
    violations: string[];
  }> {
    const result = await this.evaluate(request);

    const explanation = this.buildExplanation(result);
    const violations = result.violations?.map((v) => v.message) || [];
    const policiesEvaluated = result.metadata?.evaluatedPolicies || [this.defaultPolicy];

    return {
      allowed: result.allowed,
      explanation,
      policiesEvaluated,
      violations,
    };
  }

  /**
   * Clear decision cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): {
    size: number;
    hitRate: number;
    oldestEntry: number;
  } {
    const now = Date.now();
    let hits = 0;
    let total = 0;
    let oldest = now;

    for (const entry of this.cache.values()) {
      total++;
      hits += entry.hits;
      if (entry.timestamp < oldest) {
        oldest = entry.timestamp;
      }
    }

    return {
      size: this.cache.size,
      hitRate: total > 0 ? hits / total : 0,
      oldestEntry: oldest,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Normalize authorization request
   */
  private normalizeRequest(request: AuthorizationRequest): AuthorizationRequest {
    return {
      agent: this.normalizeAgent(request.agent),
      action: this.normalizeAction(request.action),
      resource: this.normalizeResource(request.resource),
      context: this.normalizeContext(request.context),
    };
  }

  /**
   * Normalize agent identity
   */
  private normalizeAgent(agent: string | AgentIdentity): AgentIdentity {
    if (typeof agent === "string") {
      return {
        id: agent,
        name: agent,
        type: "service",
        trustLevel: "medium",
      };
    }
    return agent;
  }

  /**
   * Normalize action
   */
  private normalizeAction(action: string | Action): Action {
    if (typeof action === "string") {
      return {
        type: action,
        name: action,
        category: this.inferCategory(action),
        sensitivity: "medium",
      };
    }
    return action;
  }

  /**
   * Normalize resource
   */
  private normalizeResource(resource: string | Resource): Resource {
    if (typeof resource === "string") {
      return {
        id: resource,
        type: "unknown",
        path: resource,
        classification: "internal",
        sensitivity: "medium",
      };
    }
    return resource;
  }

  /**
   * Normalize context
   */
  private normalizeContext(
    context: AuthorizationContext | Record<string, unknown>
  ): AuthorizationContext {
    const now = new Date();
    const hour = now.getHours();
    const dayOfWeek = now.getDay();

    const baseContext: AuthorizationContext = {
      timestamp: now.toISOString(),
      time: {
        hour,
        dayOfWeek,
        isBusinessHours: hour >= 9 && hour < 17 && dayOfWeek >= 1 && dayOfWeek <= 5,
        isMaintenanceWindow: false,
      },
      environment: {
        production: false,
        staging: false,
        development: true,
        emergency: false,
      },
    };

    return {
      ...baseContext,
      ...context,
    };
  }

  /**
   * Enrich context with additional information
   */
  private enrichContext(request: AuthorizationRequest): AuthorizationRequest {
    const enriched = { ...request };

    // Add computed fields
    if (typeof enriched.context === "object") {
      enriched.context = {
        ...enriched.context,
        requestId: this.generateId(),
      };
    }

    return enriched;
  }

  /**
   * Infer action category from action name
   */
  private inferCategory(action: string): "read" | "write" | "delete" | "execute" | "admin" {
    const action_lower = action.toLowerCase();
    
    if (action_lower.includes("read") || action_lower.includes("get") || action_lower.includes("list")) {
      return "read";
    }
    if (action_lower.includes("write") || action_lower.includes("create") || action_lower.includes("update")) {
      return "write";
    }
    if (action_lower.includes("delete") || action_lower.includes("remove")) {
      return "delete";
    }
    if (action_lower.includes("execute") || action_lower.includes("run") || action_lower.includes("bash")) {
      return "execute";
    }
    if (action_lower.includes("admin") || action_lower.includes("config")) {
      return "admin";
    }
    
    return "read";
  }

  /**
   * Generate cache key from request
   */
  private generateCacheKey(request: AuthorizationRequest): string {
    const agent = typeof request.agent === "string" ? request.agent : request.agent.id;
    const action = typeof request.action === "string" ? request.action : request.action.name;
    const resource = typeof request.resource === "string" ? request.resource : request.resource.id;
    
    return `${agent}:${action}:${resource}`;
  }

  /**
   * Get cached decision
   */
  private getCachedDecision(request: AuthorizationRequest): AuthorizationResponse | null {
    const key = this.generateCacheKey(request);
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check if expired
    const now = Date.now();
    if (now - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    // Increment hit count
    entry.hits++;

    return entry.response;
  }

  /**
   * Cache decision
   */
  private cacheDecision(
    request: AuthorizationRequest,
    response: AuthorizationResponse
  ): void {
    const key = this.generateCacheKey(request);
    
    const entry: AuthorizationCacheEntry = {
      key,
      request,
      response,
      timestamp: Date.now(),
      ttl: this.config.cacheTTL,
      hits: 0,
    };

    this.cache.set(key, entry);

    // Cleanup old entries if cache is too large
    if (this.cache.size > 1000) {
      this.cleanupCache();
    }
  }

  /**
   * Cleanup expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    
    for (const [key, entry] of this.cache) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Process OPA decision result
   */
  private processDecision(
    result: AuthorizationResponse,
    request: AuthorizationRequest
  ): AuthorizationResponse {
    // Apply default decision if needed
    if (!result.decision) {
      result.decision = this.config.defaultDecision;
      result.allowed = this.config.defaultDecision === "allow";
    }

    // Add metadata
    result.metadata = {
      ...result.metadata,
      evaluatedPolicies: [this.defaultPolicy],
      contextUsed: Object.keys(request.context || {}),
    };

    return result;
  }

  /**
   * Build human-readable explanation
   */
  private buildExplanation(result: AuthorizationResponse): string {
    const parts: string[] = [];

    parts.push(`Decision: ${result.allowed ? "ALLOWED" : "DENIED"}`);

    if (result.reason) {
      parts.push(`Reason: ${result.reason}`);
    }

    if (result.violations && result.violations.length > 0) {
      parts.push("Policy violations:");
      result.violations.forEach((v) => {
        parts.push(`  - ${v.policy}: ${v.message}`);
      });
    }

    if (result.conditions && result.conditions.length > 0) {
      parts.push("Conditions:");
      result.conditions.forEach((c) => {
        parts.push(`  - ${c.description} (${c.required ? "required" : "optional"})`);
      });
    }

    return parts.join("\n");
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }
}
