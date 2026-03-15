/**
 * Configuration Manager Module
 * 
 * Manages OPA configuration with persistence and validation.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { OPAConfig } from "./types.js";

/**
 * Config Manager class
 */
export class ConfigManager {
  private config: OPAConfig;
  private configPath: string;

  constructor(defaults: Partial<OPAConfig>) {
    this.configPath = this.getConfigPath();
    this.config = this.loadConfig(defaults);
  }

  /**
   * Get current configuration
   */
  getConfig(): OPAConfig {
    return this.config;
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<OPAConfig>): void {
    this.config = this.mergeConfig(this.config, updates);
    this.saveConfig();
  }

  /**
   * Set a specific configuration value by path
   */
  set(path: string, value: string | number | boolean): void {
    const parts = path.split(".");
    let current: any = this.config;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current)) {
        current[part] = {};
      }
      current = current[part];
    }

    const lastPart = parts[parts.length - 1];

    // Parse value
    let parsedValue: string | number | boolean = value;
    if (typeof value === "string") {
      if (value.toLowerCase() === "true") parsedValue = true;
      else if (value.toLowerCase() === "false") parsedValue = false;
      else if (!isNaN(Number(value))) parsedValue = Number(value);
    }

    current[lastPart] = parsedValue;
    this.saveConfig();
  }

  /**
   * Get a specific configuration value
   */
  get(path: string): unknown {
    const parts = path.split(".");
    let current: any = this.config;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }
      current = current[part];
    }

    return current;
  }

  /**
   * Reset to defaults
   */
  reset(defaults: Partial<OPAConfig>): void {
    this.config = this.mergeConfig(defaults, {});
    this.saveConfig();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get configuration file path
   */
  private getConfigPath(): string {
    const configDir = path.join(os.homedir(), ".pi", "agent", "opa");
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    return path.join(configDir, "config.json");
  }

  /**
   * Load configuration from disk
   */
  private loadConfig(defaults: Partial<OPAConfig>): OPAConfig {
    let loaded: Partial<OPAConfig> = {};

    if (fs.existsSync(this.configPath)) {
      try {
        const content = fs.readFileSync(this.configPath, "utf-8");
        loaded = JSON.parse(content);
      } catch (error) {
        console.error("Failed to load config:", error);
      }
    }

    return this.mergeConfig(defaults, loaded);
  }

  /**
   * Save configuration to disk
   */
  private saveConfig(): void {
    try {
      fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2), "utf-8");
    } catch (error) {
      console.error("Failed to save config:", error);
    }
  }

  /**
   * Deep merge configurations
   */
  private mergeConfig(base: Partial<OPAConfig>, override: Partial<OPAConfig>): OPAConfig {
    const result: any = { ...base };

    for (const key in override) {
      if (override[key] !== null && typeof override[key] === "object" && !Array.isArray(override[key])) {
        result[key] = this.mergeConfig(result[key] || {}, override[key] as any);
      } else if (override[key] !== undefined) {
        result[key] = override[key];
      }
    }

    return result as OPAConfig;
  }
}
