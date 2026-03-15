/**
 * Audit Logger Module
 * 
 * Comprehensive audit logging for authorization decisions.
 * Supports JSON, CSV formats with rotation and export.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { AuditConfig, AuditEntry, AuditQuery, AuditStats } from "./types.js";

/**
 * Audit Logger class
 */
export class AuditLogger {
  private config: AuditConfig;
  private logDir: string;
  private currentLogFile: string;
  private entries: AuditEntry[] = [];
  private maxBufferSize = 100;

  constructor(config: AuditConfig) {
    this.config = config;
    this.logDir = this.resolvePath(config.logDirectory);
    this.currentLogFile = this.getLogFilePath();

    // Ensure log directory exists
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  /**
   * Log an audit entry
   */
  async log(entry: AuditEntry): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    // Filter by decision type
    if (entry.allowed && !this.config.logSuccessful) {
      return;
    }
    if (!entry.allowed && !this.config.logFailed) {
      return;
    }

    // Add metadata
    const fullEntry: AuditEntry = {
      id: this.generateId(),
      ...entry,
    };

    // Add to buffer
    this.entries.push(fullEntry);

    // Flush if buffer is full
    if (this.entries.length >= this.maxBufferSize) {
      await this.flush();
    }
  }

  /**
   * Get recent audit entries
   */
  async getRecentEntries(count: number): Promise<AuditEntry[]> {
    // First, flush any buffered entries
    await this.flush();

    // Read from log files
    const allEntries = await this.readAllEntries();
    
    // Sort by timestamp (newest first)
    allEntries.sort((a, b) => {
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    return allEntries.slice(0, count);
  }

  /**
   * Query audit log with filters
   */
  async query(filters: AuditQuery): Promise<AuditEntry[]> {
    await this.flush();

    let entries = await this.readAllEntries();

    // Apply filters
    if (filters.startTime) {
      const startDate = new Date(filters.startTime);
      entries = entries.filter((e) => new Date(e.timestamp) >= startDate);
    }

    if (filters.endTime) {
      const endDate = new Date(filters.endTime);
      entries = entries.filter((e) => new Date(e.timestamp) <= endDate);
    }

    if (filters.agent) {
      entries = entries.filter((e) => e.agent === filters.agent);
    }

    if (filters.action) {
      entries = entries.filter((e) => e.action === filters.action);
    }

    if (filters.resource) {
      entries = entries.filter((e) => e.resource === filters.resource);
    }

    if (filters.decision) {
      entries = entries.filter((e) => e.decision === filters.decision);
    }

    if (filters.allowed !== undefined) {
      entries = entries.filter((e) => e.allowed === filters.allowed);
    }

    // Apply limit and offset
    const offset = filters.offset || 0;
    const limit = filters.limit || entries.length;

    return entries.slice(offset, offset + limit);
  }

  /**
   * Get audit statistics
   */
  async getStats(): Promise<AuditStats> {
    await this.flush();

    const entries = await this.readAllEntries();

    const stats: AuditStats = {
      totalEntries: entries.length,
      allowed: entries.filter((e) => e.allowed).length,
      denied: entries.filter((e) => !e.allowed).length,
      byAgent: {},
      byAction: {},
      byResource: {},
      byPolicy: {},
      averageDuration: 0,
    };

    // Calculate by-agent stats
    for (const entry of entries) {
      stats.byAgent[entry.agent] = (stats.byAgent[entry.agent] || 0) + 1;
      stats.byAction[entry.action] = (stats.byAction[entry.action] || 0) + 1;
      stats.byResource[entry.resource] = (stats.byResource[entry.resource] || 0) + 1;
      
      if (entry.policyPath) {
        stats.byPolicy[entry.policyPath] = (stats.byPolicy[entry.policyPath] || 0) + 1;
      }
    }

    // Calculate average duration
    if (entries.length > 0) {
      const totalDuration = entries.reduce((sum, e) => sum + (e.duration || 0), 0);
      stats.averageDuration = totalDuration / entries.length;
    }

    return stats;
  }

  /**
   * Export audit log
   */
  async export(format: "json" | "csv", outputFile: string): Promise<void> {
    await this.flush();

    const entries = await this.readAllEntries();

    if (format === "json") {
      fs.writeFileSync(outputFile, JSON.stringify(entries, null, 2), "utf-8");
    } else if (format === "csv") {
      const csv = this.convertToCSV(entries);
      fs.writeFileSync(outputFile, csv, "utf-8");
    }
  }

  /**
   * Flush buffered entries to disk
   */
  async flush(): Promise<void> {
    if (this.entries.length === 0) {
      return;
    }

    // Rotate log if needed
    this.rotateLogIfNeeded();

    // Write entries
    const lines = this.entries.map((entry) => JSON.stringify(entry));
    fs.appendFileSync(this.currentLogFile, lines.join("\n") + "\n", "utf-8");

    // Clear buffer
    this.entries = [];
  }

  /**
   * Clean up old log files
   */
  async cleanup(): Promise<void> {
    await this.flush();

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

    const files = fs.readdirSync(this.logDir);

    for (const file of files) {
      if (file.startsWith("audit-") && file.endsWith(".log")) {
        const filePath = path.join(this.logDir, file);
        const stats = fs.statSync(filePath);

        if (stats.mtime < cutoffDate) {
          fs.unlinkSync(filePath);
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get current log file path
   */
  private getLogFilePath(): string {
    const date = new Date().toISOString().split("T")[0];
    return path.join(this.logDir, `audit-${date}.log`);
  }

  /**
   * Rotate log if file is too large
   */
  private rotateLogIfNeeded(): void {
    if (!fs.existsSync(this.currentLogFile)) {
      return;
    }

    const stats = fs.statSync(this.currentLogFile);
    const maxSize = 100 * 1024 * 1024; // 100MB

    if (stats.size > maxSize) {
      // Rotate current file
      const timestamp = Date.now();
      const rotatedPath = this.currentLogFile.replace(".log", `-${timestamp}.log`);
      fs.renameSync(this.currentLogFile, rotatedPath);
    }
  }

  /**
   * Read all entries from log files
   */
  private async readAllEntries(): Promise<AuditEntry[]> {
    const entries: AuditEntry[] = [];

    if (!fs.existsSync(this.logDir)) {
      return entries;
    }

    const files = fs.readdirSync(this.logDir);
    const logFiles = files.filter((f) => f.startsWith("audit-") && f.endsWith(".log"));

    for (const file of logFiles) {
      const filePath = path.join(this.logDir, file);
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.trim().split("\n");

      for (const line of lines) {
        if (line.trim()) {
          try {
            const entry = JSON.parse(line) as AuditEntry;
            entries.push(entry);
          } catch {
            // Skip invalid lines
          }
        }
      }
    }

    return entries;
  }

  /**
   * Convert entries to CSV
   */
  private convertToCSV(entries: AuditEntry[]): string {
    const headers = [
      "timestamp",
      "requestId",
      "agent",
      "action",
      "resource",
      "decision",
      "allowed",
      "reason",
      "duration",
      "policyPath",
    ];

    const rows = entries.map((e) => [
      e.timestamp,
      e.requestId,
      e.agent,
      e.action,
      e.resource,
      e.decision,
      e.allowed,
      e.reason || "",
      e.duration,
      e.policyPath || "",
    ]);

    return [
      headers.join(","),
      ...rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")),
    ].join("\n");
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

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }
}
