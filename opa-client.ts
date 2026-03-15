/**
 * OPA Client Module
 * 
 * Handles communication with OPA CLI and OPA server.
 * Manages OPA process lifecycle, policy evaluation, and server operations.
 */

import { spawn, exec } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as util from "node:util";
import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type {
  OPAServerConfig,
  OPAServerStatus,
  OPABundle,
  AuthorizationRequest,
  AuthorizationResponse,
  OPAError,
} from "./types.js";
import { OPAErrorCode } from "./types.js";

const execAsync = util.promisify(exec);

/**
 * OPA Client class
 */
export class OPACLient {
  private config: OPAServerConfig;
  private ctx: ExtensionContext;
  private serverProcess: ReturnType<typeof spawn> | null = null;
  private serverUrl: string;
  private isRunning = false;

  constructor(config: OPAServerConfig, ctx: ExtensionContext) {
    this.config = config;
    this.ctx = ctx;
    this.serverUrl = `http${config.tls ? "s" : ""}://${config.serverHost}:${config.serverPort}`;
  }

  /**
   * Start OPA server
   */
  async startServer(port?: number): Promise<void> {
    if (this.isRunning) {
      throw new Error("OPA server is already running");
    }

    const serverPort = port || this.config.serverPort;
    const args = [
      "run",
      "--server",
      "--addr", `${this.config.serverHost}:${serverPort}`,
      "--log-level", this.config.logLevel,
    ];

    // Add TLS if configured
    if (this.config.tls) {
      args.push(
        "--tls-cert-file", this.config.tls.cert,
        "--tls-private-key-file", this.config.tls.key
      );
      if (this.config.tls.ca) {
        args.push("--tls-ca-cert-file", this.config.tls.ca);
      }
    }

    // Add config file if specified
    if (this.config.configPath && fs.existsSync(this.config.configPath)) {
      args.push("--config-file", this.config.configPath);
    }

    return new Promise((resolve, reject) => {
      this.serverProcess = spawn(this.config.binaryPath, args, {
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
      });

      let started = false;

      // Wait for server to be ready
      this.serverProcess.stdout?.on("data", (data: Buffer) => {
        const output = data.toString();
        if (output.includes("Server initialized") || output.includes("Server is initialized") || output.includes("Listening")) {
          if (!started) {
            started = true;
            this.isRunning = true;
            resolve();
          }
        }
      });

      this.serverProcess.stderr?.on("data", (data: Buffer) => {
        const output = data.toString();
        // OPA logs to stderr - check for server ready signal
        if (!started && (output.includes("Server initialized") || output.includes("Server is initialized") || output.includes("Listening"))) {
          started = true;
          this.isRunning = true;
          resolve();
        }
        if (!started && output.includes("error")) {
          reject(new Error(`OPA server failed to start: ${output}`));
        }
      });

      this.serverProcess.on("error", (error) => {
        if (!started) {
          reject(new Error(`Failed to start OPA server: ${error.message}`));
        }
      });

      this.serverProcess.on("exit", (code) => {
        if (!started) {
          reject(new Error(`OPA server exited with code ${code}`));
        } else {
          this.isRunning = false;
          this.serverProcess = null;
        }
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (!started) {
          this.serverProcess?.kill();
          reject(new Error("OPA server start timeout"));
        }
      }, 30000);
    });
  }

  /**
   * Stop OPA server
   */
  async stopServer(): Promise<void> {
    if (!this.serverProcess || !this.isRunning) {
      return;
    }

    return new Promise((resolve) => {
      this.serverProcess?.on("exit", () => {
        this.isRunning = false;
        this.serverProcess = null;
        resolve();
      });

      this.serverProcess?.kill("SIGTERM");

      // Force kill after 5 seconds
      setTimeout(() => {
        if (this.serverProcess) {
          this.serverProcess.kill("SIGKILL");
        }
      }, 5000);
    });
  }

  /**
   * Get OPA server status
   */
  async getStatus(): Promise<OPAServerStatus> {
    try {
      const response = await fetch(`${this.serverUrl}/health`);
      
      if (response.ok) {
        return {
          running: true,
          version: await this.getVersion(),
        };
      }
    } catch {
      // Server not responding
    }

    return {
      running: false,
    };
  }

  /**
   * Get OPA version
   */
  async getVersion(): Promise<string | undefined> {
    try {
      const { stdout } = await execAsync(`${this.config.binaryPath} version`);
      const match = stdout.match(/Version:\s*(.+)/);
      return match ? match[1].trim() : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Evaluate policy
   */
  async evaluate(
    policyPath: string,
    input: AuthorizationRequest
  ): Promise<AuthorizationResponse> {
    const startTime = Date.now();
    const requestId = this.generateId();

    try {
      // Build the query path
      const queryPath = policyPath.startsWith("/") 
        ? policyPath 
        : `/v1/data/${policyPath.replace(/\./g, "/")}`;

      // Call OPA server
      const response = await fetch(`${this.serverUrl}${queryPath}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ input }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw this.createError(
          OPAErrorCode.EVALUATION_ERROR,
          `OPA evaluation failed: ${response.status} ${errorText}`
        );
      }

      const result = await response.json();
      const duration = Date.now() - startTime;

      // Parse OPA response into AuthorizationResponse
      return this.parseOPAResponse(result, requestId, duration, policyPath);
    } catch (error) {
      const duration = Date.now() - startTime;
      
      if (error instanceof Error && error.message.includes("ECONNREFUSED")) {
        throw this.createError(
          OPAErrorCode.SERVER_NOT_RUNNING,
          "OPA server is not running"
        );
      }

      // Return deny on error (fail closed)
      return {
        allowed: false,
        decision: "deny",
        reason: `Evaluation error: ${error}`,
        duration,
        timestamp: new Date().toISOString(),
        requestId,
        policyPath,
      };
    }
  }

  /**
   * Evaluate policy using OPA CLI (for offline/batch evaluation)
   */
  async evaluateCLI(
    policyPath: string,
    input: AuthorizationRequest
  ): Promise<AuthorizationResponse> {
    const startTime = Date.now();
    const requestId = this.generateId();

    try {
      // Write input to temp file
      const tempInput = path.join(
        process.env.TMPDIR || "/tmp",
        `opa-input-${requestId}.json`
      );
      fs.writeFileSync(tempInput, JSON.stringify({ input }), { mode: 0o600 });

      // Build query
      const query = policyPath.startsWith("data.")
        ? policyPath
        : `data.${policyPath}`;

      // Execute OPA eval
      const { stdout, stderr } = await execAsync(
        `${this.config.binaryPath} eval --data ${policyPath} --input ${tempInput} "${query}"`
      );

      // Cleanup temp file
      fs.unlinkSync(tempInput);

      if (stderr) {
        throw new Error(stderr);
      }

      const result = JSON.parse(stdout);
      const duration = Date.now() - startTime;

      return this.parseOPAResponse(result, requestId, duration, policyPath);
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        allowed: false,
        decision: "deny",
        reason: `CLI evaluation error: ${error}`,
        duration,
        timestamp: new Date().toISOString(),
        requestId,
        policyPath,
      };
    }
  }

  /**
   * Load policy into OPA server
   */
  async loadPolicy(policyPath: string, content: string): Promise<void> {
    try {
      const response = await fetch(`${this.serverUrl}/v1/policies/${policyPath}`, {
        method: "PUT",
        headers: {
          "Content-Type": "text/plain",
        },
        body: content,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw this.createError(
          OPAErrorCode.POLICY_INVALID,
          `Failed to load policy: ${errorText}`
        );
      }
    } catch (error) {
      throw this.createError(
        OPAErrorCode.NETWORK_ERROR,
        `Failed to load policy: ${error}`
      );
    }
  }

  /**
   * Delete policy from OPA server
   */
  async deletePolicy(policyPath: string): Promise<void> {
    try {
      const response = await fetch(`${this.serverUrl}/v1/policies/${policyPath}`, {
        method: "DELETE",
      });

      if (!response.ok && response.status !== 404) {
        const errorText = await response.text();
        throw this.createError(
          OPAErrorCode.POLICY_NOT_FOUND,
          `Failed to delete policy: ${errorText}`
        );
      }
    } catch (error) {
      throw this.createError(
        OPAErrorCode.NETWORK_ERROR,
        `Failed to delete policy: ${error}`
      );
    }
  }

  /**
   * List loaded policies
   */
  async listPolicies(): Promise<string[]> {
    try {
      const response = await fetch(`${this.serverUrl}/v1/policies`);
      
      if (!response.ok) {
        return [];
      }

      const data = await response.json() as { result?: string[] };
      return data.result || [];
    } catch {
      return [];
    }
  }

  /**
   * Check if OPA server is running
   */
  isServerRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Get server URL
   */
  getServerUrl(): string {
    return this.serverUrl;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Parse OPA response into AuthorizationResponse
   */
  private parseOPAResponse(
    result: unknown,
    requestId: string,
    duration: number,
    policyPath: string
  ): AuthorizationResponse {
    const response = result as {
      result?: {
        allow?: boolean;
        decision?: string;
        reason?: string;
        violations?: Array<{ policy: string; rule: string; message: string }>;
        conditions?: Array<{ type: string; description: string; required: boolean }>;
      };
    };

    const opaResult = response.result || { allow: false };

    return {
      allowed: opaResult.allow ?? false,
      decision: (opaResult.decision as "allow" | "deny" | "conditional") || "deny",
      reason: opaResult.reason,
      violations: opaResult.violations?.map((v) => ({
        policy: v.policy,
        rule: v.rule,
        message: v.message,
      })),
      conditions: opaResult.conditions,
      duration,
      timestamp: new Date().toISOString(),
      requestId,
      policyPath,
    };
  }

  /**
   * Create OPA error
   */
  private createError(code: OPAErrorCode, message: string): OPAError {
    return {
      code,
      message,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }
}
