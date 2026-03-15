/**
 * pi-opa Extension
 * 
 * Enterprise-grade Open Policy Agent (OPA) integration for pi coding agent.
 * Provides comprehensive authorization, authentication, and policy enforcement
 * for multi-agent systems using the OPA CLI.
 * 
 * Features:
 * - OPA CLI integration for policy evaluation
 * - Comprehensive authorization decisions (WHO, WHAT, WHEN, WHERE, WHY)
 * - Policy management (load, test, validate)
 * - Audit logging and decision tracking
 * - Multi-dimensional access control
 * - Integration with pi-a2a-communication for agent authorization
 * 
 * @module pi-opa
 * @version 1.0.0
 * @author pi-extensions
 * @license MIT
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { OPACLient } from "./opa-client.js";
import { PolicyManager } from "./policy-manager.js";
import { AuthzEngine } from "./authz-engine.js";
import { AuditLogger } from "./audit-logger.js";
import { ConfigManager } from "./config.js";
import type { 
  OPAConfig, 
  AuthorizationRequest, 
  AuthorizationResponse,
  Policy,
  AuditEntry 
} from "./types.js";

// Global extension state
let opaClient: OPACLient | null = null;
let policyManager: PolicyManager | null = null;
let authzEngine: AuthzEngine | null = null;
let auditLogger: AuditLogger | null = null;
let configManager: ConfigManager | null = null;

/**
 * Default OPA configuration
 */
const DEFAULT_CONFIG: Partial<OPAConfig> = {
  opa: {
    binaryPath: "opa",
    serverPort: 8181,
    serverHost: "localhost",
    autoStart: true,
    logLevel: "info",
  },
  policies: {
    directory: "~/.pi/agent/opa/policies",
    defaultPackage: "pi.authz",
    autoReload: true,
    testOnLoad: true,
  },
  authorization: {
    defaultDecision: "deny",
    cacheDecisions: true,
    cacheTTL: 300000, // 5 minutes
    maxContextDepth: 10,
    requireAuthentication: true,
  },
  audit: {
    enabled: true,
    logDirectory: "~/.pi/agent/opa/audit",
    retentionDays: 90,
    logSuccessful: true,
    logFailed: true,
    includeContext: true,
    format: "json",
  },
  integration: {
    a2aEnabled: false,
    a2aExtension: "pi-a2a-communication",
    interceptA2A: true,
    requireOPAForA2A: true,
  },
};

export default function (pi: ExtensionAPI) {
  // Initialize configuration
  configManager = new ConfigManager(DEFAULT_CONFIG);

  /**
   * Initialize OPA components on session start
   */
  pi.on("session_start", async (event, ctx) => {
    const config = configManager!.getConfig();

    // Initialize OPA client
    opaClient = new OPACLient(config.opa, ctx);

    // Initialize policy manager
    policyManager = new PolicyManager(config.policies, opaClient);

    // Initialize authorization engine
    authzEngine = new AuthzEngine(config.authorization, opaClient);

    // Initialize audit logger
    auditLogger = new AuditLogger(config.audit);

    // Start OPA server if configured
    if (config.opa.autoStart) {
      try {
        await opaClient.startServer();
        ctx.ui?.notify?.(`OPA server started on ${config.opa.serverHost}:${config.opa.serverPort}`, "info");
      } catch (error) {
        ctx.ui?.notify?.(`OPA server failed to start: ${error}`, "warning");
      }
    }

    // Load policies
    try {
      await policyManager.loadPolicies();
      const policyCount = policyManager.getPolicyCount();
      ctx.ui?.notify?.(`Loaded ${policyCount} OPA policies`, "info");
    } catch (error) {
      ctx.ui?.notify?.(`Failed to load policies: ${error}`, "warning");
    }

    ctx.ui?.notify?.("pi-opa authorization initialized", "info");
  });

  /**
   * Cleanup on session end
   */
  pi.on("session_end", async () => {
    if (opaClient) {
      await opaClient.stopServer();
      opaClient = null;
    }
    policyManager = null;
    authzEngine = null;
    auditLogger = null;
    configManager = null;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // COMMANDS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check authorization for an action
   * Usage: /opa-check <agent> <action> <resource> [--context <json>]
   */
  pi.registerCommand("opa-check", {
    description: "Check if an action is authorized",
    handler: async (args, ctx) => {
      if (!authzEngine || !auditLogger) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      // Parse arguments
      const parts = args.trim().split(/\s+/);
      if (parts.length < 3) {
        ctx.ui?.notify?.("Usage: /opa-check <agent> <action> <resource> [--context <json>]", "warning");
        return;
      }

      const agent = parts[0];
      const action = parts[1];
      const resource = parts[2];

      // Parse optional context
      let context: Record<string, unknown> = {};
      const contextIndex = args.indexOf("--context");
      if (contextIndex !== -1) {
        const contextStr = args.substring(contextIndex + 10).trim();
        try {
          context = JSON.parse(contextStr);
        } catch {
          ctx.ui?.notify?.("Invalid context JSON", "error");
          return;
        }
      }

      // Build authorization request
      const request: AuthorizationRequest = {
        agent,
        action,
        resource,
        context: {
          ...context,
          timestamp: new Date().toISOString(),
          ip: "manual-check",
        },
      };

      try {
        ctx.ui?.notify?.(`Checking authorization...`, "info");

        // Evaluate authorization
        const result = await authzEngine.evaluate(request);

        // Log the decision
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          requestId: result.requestId,
          agent,
          action,
          resource,
          decision: result.decision,
          allowed: result.allowed,
          reason: result.reason || "",
          violations: result.violations,
          policyPath: result.policyPath,
          duration: result.duration,
        });

        // Display result
        const status = result.allowed ? "✅ ALLOWED" : "❌ DENIED";
        const message = [
          `${status}`,
          `Agent: ${agent}`,
          `Action: ${action}`,
          `Resource: ${resource}`,
          `Reason: ${result.reason || "N/A"}`,
        ];

        if (result.violations && result.violations.length > 0) {
          message.push("Violations:");
          result.violations.forEach((v: { policy: string; message: string }) => {
            message.push(`  - ${v.policy}: ${v.message}`);
          });
        }

        ctx.ui?.notify?.(message.join("\n"), result.allowed ? "success" : "warning");
      } catch (error) {
        ctx.ui?.notify?.(`Authorization check failed: ${error}`, "error");
      }
    },
  });

  /**
   * Start OPA server
   * Usage: /opa-start [port]
   */
  pi.registerCommand("opa-start", {
    description: "Start the OPA server",
    handler: async (args, ctx) => {
      if (!opaClient) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      const port = args.trim() ? parseInt(args.trim(), 10) : 8181;

      try {
        await opaClient.startServer(port);
        ctx.ui?.notify?.(`OPA server started on port ${port}`, "success");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to start OPA server: ${error}`, "error");
      }
    },
  });

  /**
   * Stop OPA server
   * Usage: /opa-stop
   */
  pi.registerCommand("opa-stop", {
    description: "Stop the OPA server",
    handler: async (_args, ctx) => {
      if (!opaClient) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      try {
        await opaClient.stopServer();
        ctx.ui?.notify?.("OPA server stopped", "success");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to stop OPA server: ${error}`, "error");
      }
    },
  });

  /**
   * Load policies
   * Usage: /opa-load [directory]
   */
  pi.registerCommand("opa-load", {
    description: "Load OPA policies from directory",
    handler: async (args, ctx) => {
      if (!policyManager) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      const directory = args.trim() || undefined;

      try {
        ctx.ui?.notify?.("Loading policies...", "info");
        await policyManager.loadPolicies(directory);
        const count = policyManager.getPolicyCount();
        ctx.ui?.notify?.(`Loaded ${count} policies`, "success");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to load policies: ${error}`, "error");
      }
    },
  });

  /**
   * Test policies
   * Usage: /opa-test [policy-file]
   */
  pi.registerCommand("opa-test", {
    description: "Test OPA policies",
    handler: async (args, ctx) => {
      if (!policyManager) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      const policyFile = args.trim() || undefined;

      try {
        ctx.ui?.notify?.("Testing policies...", "info");
        const results = await policyManager.testPolicies(policyFile);

        const passed = results.filter((r: { result: string }) => r.result === "PASS").length;
        const failed = results.filter((r: { result: string }) => r.result === "FAIL").length;

        ctx.ui?.notify?.(`Test results: ${passed} passed, ${failed} failed`, failed > 0 ? "warning" : "success");

        if (failed > 0) {
          const failures = results
            .filter((r: any) => r.result === "FAIL")
            .map((r: any) => `  - ${r.name}: ${r.message || "No message"}`)
            .join("\n");
          ctx.ui?.notify?.(`Failures:\n${failures}`, "error");
        }
      } catch (error) {
        ctx.ui?.notify?.(`Policy testing failed: ${error}`, "error");
      }
    },
  });

  /**
   * Validate policy syntax
   * Usage: /opa-validate <policy-file>
   */
  pi.registerCommand("opa-validate", {
    description: "Validate OPA policy syntax",
    handler: async (args, ctx) => {
      if (!policyManager) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      const policyFile = args.trim();
      if (!policyFile) {
        ctx.ui?.notify?.("Usage: /opa-validate <policy-file>", "warning");
        return;
      }

      try {
        const result = await policyManager.validatePolicy(policyFile);
        if (result.valid) {
          ctx.ui?.notify?.(`Policy is valid: ${policyFile}`, "success");
        } else {
          ctx.ui?.notify?.(`Policy has errors:\n${result.errors.join("\n")}`, "error");
        }
      } catch (error) {
        ctx.ui?.notify?.(`Validation failed: ${error}`, "error");
      }
    },
  });

  /**
   * Show audit log
   * Usage: /opa-audit [count]
   */
  pi.registerCommand("opa-audit", {
    description: "Show authorization audit log",
    handler: async (args, ctx) => {
      if (!auditLogger) {
        ctx.ui?.notify?.("Audit logger not initialized", "error");
        return;
      }

      const count = args.trim() ? parseInt(args.trim(), 10) : 10;

      try {
        const entries = await auditLogger.getRecentEntries(count);
        
        if (entries.length === 0) {
          ctx.ui?.notify?.("No audit entries found", "info");
          return;
        }

        const lines = entries.map((entry: AuditEntry) => {
          const status = entry.allowed ? "✅" : "❌";
          return `${status} ${entry.timestamp} | ${entry.agent} | ${entry.action} | ${entry.resource} | ${entry.decision}`;
        });

        ctx.ui?.notify?.(`Recent ${entries.length} audit entries:\n${lines.join("\n")}`, "info");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to get audit log: ${error}`, "error");
      }
    },
  });

  /**
   * Export audit log
   * Usage: /opa-export-audit <format> [output-file]
   */
  pi.registerCommand("opa-export-audit", {
    description: "Export audit log (json|csv)",
    handler: async (args, ctx) => {
      if (!auditLogger) {
        ctx.ui?.notify?.("Audit logger not initialized", "error");
        return;
      }

      const parts = args.trim().split(/\s+/);
      if (parts.length < 1) {
        ctx.ui?.notify?.("Usage: /opa-export-audit <json|csv> [output-file]", "warning");
        return;
      }

      const format = parts[0] as "json" | "csv";
      const outputFile = parts[1] || `audit-export-${Date.now()}.${format}`;

      try {
        await auditLogger.export(format, outputFile);
        ctx.ui?.notify?.(`Audit log exported to ${outputFile}`, "success");
      } catch (error) {
        ctx.ui?.notify?.(`Export failed: ${error}`, "error");
      }
    },
  });

  /**
   * Create policy template
   * Usage: /opa-template <policy-name>
   */
  pi.registerCommand("opa-template", {
    description: "Generate a policy template",
    handler: async (args, ctx) => {
      if (!policyManager) {
        ctx.ui?.notify?.("Policy manager not initialized", "error");
        return;
      }

      const policyName = args.trim();
      if (!policyName) {
        ctx.ui?.notify?.("Usage: /opa-template <policy-name>", "warning");
        return;
      }

      try {
        const filePath = await policyManager.createTemplate(policyName);
        ctx.ui?.notify?.(`Policy template created: ${filePath}`, "success");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to create template: ${error}`, "error");
      }
    },
  });

  /**
   * Show OPA status
   * Usage: /opa-status
   */
  pi.registerCommand("opa-status", {
    description: "Show OPA server status",
    handler: async (_args, ctx) => {
      if (!opaClient || !policyManager) {
        ctx.ui?.notify?.("OPA not initialized", "error");
        return;
      }

      try {
        const serverStatus = await opaClient.getStatus();
        const policyCount = policyManager.getPolicyCount();
        const policies = policyManager.getPolicyNames();

        const status = [
          `OPA Server: ${serverStatus.running ? "🟢 Running" : "🔴 Stopped"}`,
          `Server URL: ${opaClient.getServerUrl()}`,
          `Version: ${serverStatus.version || "Unknown"}`,
          `Policies Loaded: ${policyCount}`,
          `Policy Files: ${policies.join(", ") || "None"}`,
        ];

        ctx.ui?.notify?.(status.join("\n"), "info");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to get status: ${error}`, "error");
      }
    },
  });

  /**
   * Configure OPA settings
   * Usage: /opa-config <key> <value>
   */
  pi.registerCommand("opa-config", {
    description: "Configure OPA settings",
    handler: async (args, ctx) => {
      const parts = args.trim().split(/\s+/);
      if (parts.length < 2) {
        ctx.ui?.notify?.("Usage: /opa-config <key> <value>", "warning");
        return;
      }

      const key = parts[0];
      const value = parts.slice(1).join(" ");

      try {
        configManager!.set(key, value);
        ctx.ui?.notify?.(`Configuration updated: ${key} = ${value}`, "success");
      } catch (error) {
        ctx.ui?.notify?.(`Failed to update config: ${error}`, "error");
      }
    },
  });

  /**
   * Show help
   * Usage: /opa-help
   */
  pi.registerCommand("opa-help", {
    description: "Show pi-opa help",
    handler: async (_args, ctx) => {
      const help = `
pi-opa Extension Commands:

Authorization:
  /opa-check <agent> <action> <resource>  Check authorization

Server Management:
  /opa-start [port]                       Start OPA server
  /opa-stop                               Stop OPA server
  /opa-status                             Show OPA status

Policy Management:
  /opa-load [directory]                   Load policies
  /opa-test [policy-file]                 Test policies
  /opa-validate <policy-file>             Validate policy
  /opa-template <policy-name>             Create policy template

Audit & Logging:
  /opa-audit [count]                      Show audit log
  /opa-export-audit <format> [file]       Export audit log

Configuration:
  /opa-config <key> <value>               Configure settings
  /opa-help                               Show this help

Examples:
  /opa-check ci-bot deploy production --context {"time":"09:00"}
  /opa-load ./my-policies
  /opa-test pi_authz.rego
  /opa-export-audit json ./audit.json
      `.trim();

      ctx.ui?.notify?.(help, "info");
    },
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // TOOLS REGISTRATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Register opa_evaluate tool for programmatic authorization
   */
  pi.registerTool({
    name: "opa_evaluate",
    label: "OPA Evaluate",
    description: "Evaluate authorization using OPA policies",
    parameters: {
      type: "object",
      properties: {
        agent: {
          type: "string",
          description: "Agent identity",
        },
        action: {
          type: "string",
          description: "Action to authorize",
        },
        resource: {
          type: "string",
          description: "Resource being accessed",
        },
        context: {
          type: "object",
          description: "Additional context for decision",
          default: {},
        },
      },
      required: ["agent", "action", "resource"],
    },
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (!authzEngine || !auditLogger) {
        return {
          content: [{ type: "text", text: "OPA not initialized" }],
          isError: true,
        };
      }

      try {
        const request: AuthorizationRequest = {
          agent: params.agent as string,
          action: params.action as string,
          resource: params.resource as string,
          context: (params.context as Record<string, unknown>) || {},
        };

        const result = await authzEngine.evaluate(request);

        // Log the decision
        const agentStr = typeof request.agent === "string" ? request.agent : request.agent.id || "unknown";
        const actionStr = typeof request.action === "string" ? request.action : request.action.name || "unknown";
        const resourceStr = typeof request.resource === "string" ? request.resource : request.resource.id || "unknown";
        
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          requestId: result.requestId,
          agent: agentStr,
          action: actionStr,
          resource: resourceStr,
          decision: result.decision,
          allowed: result.allowed,
          reason: result.reason || "",
          violations: result.violations,
          policyPath: result.policyPath,
          duration: result.duration,
        });

        const output = [
          `Decision: ${result.allowed ? "ALLOWED" : "DENIED"}`,
          `Reason: ${result.reason || "N/A"}`,
          `Policy: ${result.policyPath || "N/A"}`,
          `Duration: ${result.duration}ms`,
        ];

        if (result.violations && result.violations.length > 0) {
          output.push("Violations:");
          result.violations.forEach((v: { policy: string; message: string }) => {
            output.push(`  - ${v.policy}: ${v.message}`);
          });
        }

        return {
          content: [{ type: "text", text: output.join("\n") }],
          details: result,
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: `Authorization error: ${error}` }],
          isError: true,
        };
      }
    },
  });

  /**
   * Register opa_check_policy tool
   */
  pi.registerTool({
    name: "opa_check_policy",
    label: "OPA Check Policy",
    description: "Validate OPA policy syntax and structure",
    parameters: {
      type: "object",
      properties: {
        policy_file: {
          type: "string",
          description: "Path to policy file",
        },
      },
      required: ["policy_file"],
    },
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (!policyManager) {
        return {
          content: [{ type: "text", text: "Policy manager not initialized" }],
          isError: true,
        };
      }

      try {
        const result = await policyManager.validatePolicy(params.policy_file as string);
        if (result.valid) {
          return {
            content: [{ type: "text", text: `Policy is valid: ${params.policy_file}` }],
          };
        } else {
          return {
            content: [{ type: "text", text: `Policy errors:\n${result.errors.join("\n")}` }],
            isError: true,
          };
        }
      } catch (error) {
        return {
          content: [{ type: "text", text: `Validation error: ${error}` }],
          isError: true,
        };
      }
    },
  });
}

// Export components for external use
export { OPACLient, PolicyManager, AuthzEngine, AuditLogger, ConfigManager };
export type { OPAConfig, AuthorizationRequest, AuthorizationResponse, Policy, AuditEntry };
