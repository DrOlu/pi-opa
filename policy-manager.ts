/**
 * Policy Manager Module
 * 
 * Manages OPA policies including loading, testing, validation,
 * and template generation.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { exec } from "node:child_process";
import * as util from "node:util";
import type { OPACLient } from "./opa-client.js";
import type {
  PolicyConfig,
  Policy,
  PolicyValidationResult,
  PolicyTestResult,
} from "./types.js";

const execAsync = util.promisify(exec);

/**
 * Policy Manager class
 */
export class PolicyManager {
  private config: PolicyConfig;
  private opaClient: OPACLient;
  private policies: Map<string, Policy> = new Map();
  private policyDir: string;

  constructor(config: PolicyConfig, opaClient: OPACLient) {
    this.config = config;
    this.opaClient = opaClient;
    this.policyDir = this.resolvePath(config.directory);
  }

  /**
   * Load policies from directory
   */
  async loadPolicies(directory?: string): Promise<void> {
    const dir = directory ? this.resolvePath(directory) : this.policyDir;

    if (!fs.existsSync(dir)) {
      // Create default policies if directory doesn't exist
      await this.createDefaultPolicies(dir);
      return;
    }

    // Find all .rego files
    const files = await this.findPolicyFiles(dir);

    // Clear existing policies
    this.policies.clear();

    // Load each policy
    for (const file of files) {
      try {
        await this.loadPolicyFile(file);
      } catch (error) {
        console.error(`Failed to load policy ${file}:`, error);
      }
    }

    // Test policies if configured
    if (this.config.testOnLoad) {
      await this.testPolicies();
    }
  }

  /**
   * Get policy count
   */
  getPolicyCount(): number {
    return this.policies.size;
  }

  /**
   * Get policy names
   */
  getPolicyNames(): string[] {
    return Array.from(this.policies.keys());
  }

  /**
   * Get policy by name
   */
  getPolicy(name: string): Policy | undefined {
    return this.policies.get(name);
  }

  /**
   * Test all policies
   */
  async testPolicies(policyFile?: string): Promise<PolicyTestResult[]> {
    const results: PolicyTestResult[] = [];

    try {
      let testCommand: string;

      if (policyFile) {
        // Test specific file
        const fullPath = path.isAbsolute(policyFile) 
          ? policyFile 
          : path.join(this.policyDir, policyFile);
        testCommand = `opa test ${fullPath} -v`;
      } else {
        // Test all policies in directory
        testCommand = `opa test ${this.policyDir} -v`;
      }

      const { stdout, stderr } = await execAsync(testCommand);

      // Parse test results from OPA output
      const lines = stdout.split("\n");
      
      for (const line of lines) {
        // Parse pass/fail from OPA test output
        if (line.includes("PASS")) {
          const match = line.match(/PASS:\s*(.+)/);
          if (match) {
            results.push({
              name: match[1].trim(),
              result: "PASS",
            });
          }
        } else if (line.includes("FAIL")) {
          const match = line.match(/FAIL:\s*(.+)/);
          if (match) {
            results.push({
              name: match[1].trim(),
              result: "FAIL",
              message: stderr || "Test failed",
            });
          }
        }
      }
    } catch (error) {
      // OPA test returns non-zero exit code on failures
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Try to parse failures from error
      const failMatch = errorMessage.match(/(\d+)\s+failures?/);
      if (failMatch) {
        results.push({
          name: "opa-test",
          result: "FAIL",
          message: `${failMatch[1]} test(s) failed`,
        });
      } else {
        results.push({
          name: "opa-test",
          result: "ERROR",
          message: errorMessage,
        });
      }
    }

    return results;
  }

  /**
   * Validate policy syntax
   */
  async validatePolicy(policyFile: string): Promise<PolicyValidationResult> {
    const fullPath = path.isAbsolute(policyFile)
      ? policyFile
      : path.join(this.policyDir, policyFile);

    if (!fs.existsSync(fullPath)) {
      return {
        valid: false,
        file: fullPath,
        errors: [`Policy file not found: ${fullPath}`],
      };
    }

    try {
      // Use OPA to check syntax
      const { stdout, stderr } = await execAsync(`opa parse ${fullPath}`);

      if (stderr) {
        return {
          valid: false,
          file: fullPath,
          errors: [stderr],
        };
      }

      // Parse AST to verify structure
      const ast = stdout ? JSON.parse(stdout) : null;

      return {
        valid: true,
        file: fullPath,
        errors: [],
        warnings: [],
        ast,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        valid: false,
        file: fullPath,
        errors: [errorMessage],
      };
    }
  }

  /**
   * Create policy template
   */
  async createTemplate(policyName: string, directory?: string): Promise<string> {
    const dir = directory || this.policyDir;
    
    // Ensure directory exists
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const fileName = `${policyName}.rego`;
    const filePath = path.join(dir, fileName);

    const template = this.generatePolicyTemplate(policyName);

    fs.writeFileSync(filePath, template, { encoding: "utf-8" });

    return filePath;
  }

  /**
   * Reload policies (for hot reload)
   */
  async reloadPolicies(): Promise<void> {
    await this.loadPolicies();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Load a single policy file
   */
  private async loadPolicyFile(filePath: string): Promise<void> {
    const content = fs.readFileSync(filePath, "utf-8");
    const fileName = path.basename(filePath, ".rego");

    // Parse package name from content
    const packageMatch = content.match(/package\s+(\S+)/);
    const packageName = packageMatch ? packageMatch[1] : this.config.defaultPackage;

    // Parse rules
    const rules = this.parseRules(content);

    const policy: Policy = {
      id: fileName,
      name: fileName,
      description: this.extractDescription(content),
      path: filePath,
      package: packageName,
      version: this.extractVersion(content) || "1.0.0",
      rules,
      metadata: {
        author: this.extractAuthor(content),
        created: new Date().toISOString(),
        tags: this.extractTags(content),
      },
    };

    this.policies.set(fileName, policy);

    // Load into OPA server if running
    if (this.opaClient.isServerRunning()) {
      try {
        await this.opaClient.loadPolicy(fileName, content);
      } catch (error) {
        console.error(`Failed to load policy into OPA server: ${error}`);
      }
    }
  }

  /**
   * Find all .rego files in directory
   */
  private async findPolicyFiles(dir: string): Promise<string[]> {
    const files: string[] = [];

    if (!fs.existsSync(dir)) {
      return files;
    }

    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Recursively search subdirectories
        const subFiles = await this.findPolicyFiles(fullPath);
        files.push(...subFiles);
      } else if (entry.isFile() && entry.name.endsWith(".rego")) {
        files.push(fullPath);
      }
    }

    return files;
  }

  /**
   * Create default policies
   */
  private async createDefaultPolicies(dir: string): Promise<void> {
    fs.mkdirSync(dir, { recursive: true });

    // Create default authorization policy
    const defaultPolicy = `package pi.authz

# Default deny
default allow := false

# Allow if all conditions are met
allow if {
    input.agent.trust_level == "high"
    input.action.category == "read"
    input.resource.classification != "secret"
}

# Deny destructive actions outside business hours
deny contains violation if {
    input.action.category == "delete"
    not is_business_hours
    violation := {
        "policy": "business_hours",
        "rule": "no_destructive_after_hours",
        "message": "Destructive actions not allowed outside business hours"
    }
}

# Deny access to sensitive resources by untrusted agents
deny contains violation if {
    input.resource.classification == "secret"
    input.agent.trust_level == "low"
    violation := {
        "policy": "sensitive_access",
        "rule": "untrusted_no_secrets",
        "message": "Untrusted agents cannot access secret resources"
    }
}

# Helper: Check if business hours
is_business_hours if {
    time.now_ns >= time.parse_rfc3339_ns("${format_date(new Date())}T09:00:00Z")
    time.now_ns <= time.parse_rfc3339_ns("${format_date(new Date())}T17:00:00Z")
}

# Metadata
# Author: pi-opa
# Version: 1.0.0
# Tags: ["default", "authorization", "business-hours"]
`;

    fs.writeFileSync(path.join(dir, "default_authz.rego"), defaultPolicy);

    // Create tests for default policy
    const testPolicy = `package pi.authz_test

import data.pi.authz

test_allow_read_low_sensitivity if {
    authz.allow with input as {
        "agent": {"trust_level": "high"},
        "action": {"category": "read"},
        "resource": {"classification": "internal"}
    }
}

test_deny_delete_after_hours if {
    count(authz.deny) > 0 with input as {
        "agent": {"trust_level": "high"},
        "action": {"category": "delete"},
        "resource": {"classification": "internal"}
    }
}

test_deny_untrusted_secret if {
    count(authz.deny) > 0 with input as {
        "agent": {"trust_level": "low"},
        "action": {"category": "read"},
        "resource": {"classification": "secret"}
    }
}
`;

    fs.writeFileSync(path.join(dir, "default_authz_test.rego"), testPolicy);

    // Reload policies
    await this.loadPolicies();
  }

  /**
   * Generate policy template
   */
  private generatePolicyTemplate(policyName: string): string {
    const packageName = this.config.defaultPackage;
    
    return `package ${packageName}.${policyName}

# Policy: ${policyName}
# Description: Add your policy description here
# Author: Your Name
# Version: 1.0.0
# Tags: ["custom", "authorization"]

# Default deny
default allow := false

# Add your allow rules here
# Example:
# allow if {
#     input.agent.name == "trusted-agent"
#     input.action.type == "read"
# }

# Add your deny rules here
# Example:
# deny contains violation if {
#     input.action.category == "delete"
#     input.resource.classification == "secret"
#     violation := {
#         "policy": "${policyName}",
#         "rule": "no_delete_secrets",
#         "message": "Cannot delete secret resources"
#     }
# }

# Add helper functions here
# is_admin if {
#     "admin" in input.agent.roles
# }
`;
  }

  /**
   * Parse rules from policy content
   */
  private parseRules(content: string): Array<{ name: string; query: string; default: boolean }> {
    const rules: Array<{ name: string; query: string; default: boolean }> = [];
    
    // Simple regex parsing for rules
    const ruleRegex = /^(\w+)\s*\{([^}]+)\}/gm;
    let match;
    
    while ((match = ruleRegex.exec(content)) !== null) {
      const name = match[1];
      const query = match[2].trim();
      
      if (name && query) {
        rules.push({
          name,
          query,
          default: name === "allow" || name === "default",
        });
      }
    }

    return rules;
  }

  /**
   * Extract description from comments
   */
  private extractDescription(content: string): string {
    const match = content.match(/#\s*Description:\s*(.+)/);
    return match ? match[1].trim() : "No description provided";
  }

  /**
   * Extract version from comments
   */
  private extractVersion(content: string): string | undefined {
    const match = content.match(/#\s*Version:\s*(.+)/);
    return match ? match[1].trim() : undefined;
  }

  /**
   * Extract author from comments
   */
  private extractAuthor(content: string): string | undefined {
    const match = content.match(/#\s*Author:\s*(.+)/);
    return match ? match[1].trim() : undefined;
  }

  /**
   * Extract tags from comments
   */
  private extractTags(content: string): string[] {
    const match = content.match(/#\s*Tags:\s*(.+)/);
    if (!match) return [];
    
    try {
      return JSON.parse(match[1].trim());
    } catch {
      return [];
    }
  }

  /**
   * Resolve path (expand ~ to home directory)
   */
  private resolvePath(inputPath: string): string {
    if (inputPath.startsWith("~/")) {
      return path.join(os.homedir(), inputPath.slice(2));
    }
    return inputPath;
  }
}

/**
 * Format date for OPA time parsing
 */
function format_date(date: Date): string {
  return date.toISOString().split("T")[0];
}
