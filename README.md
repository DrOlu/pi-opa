# pi-opa

Enterprise-grade Open Policy Agent (OPA) integration for pi coding agent. Provides comprehensive authorization, authentication, and policy enforcement for multi-agent systems.

## Overview

pi-opa brings enterprise-class authorization to pi using the industry-standard Open Policy Agent (OPA). It enables:

- **Policy-as-Code** - Define authorization rules in Rego language
- **Multi-dimensional Access Control** - WHO, WHAT, WHEN, WHERE, WHY
- **Audit Logging** - Complete decision trail for compliance
- **A2A Integration** - Secure multi-agent authorization
- **Dynamic Policy Updates** - Hot-reload without restarting

## Prerequisites

- pi coding agent >= 1.0.0
- Node.js >= 18.0.0
- OPA binary installed (`opa`) - [Install OPA](https://www.openpolicyagent.org/docs/latest/#running-opa)

## Installation

```bash
# Via npm (recommended)
pi install npm:pi-opa

# Via git
pi install git:github.com/DrOlu/pi-opa
```

## Quick Start

### 1. Start OPA Server

```bash
/opa-start
# OPA server started on localhost:8181
```

### 2. Create a Policy

```bash
/opa-template my_policy
# Created: ~/.pi/agent/opa/policies/my_policy.rego
```

### 3. Edit the Policy

Edit the generated policy file to add your rules.

### 4. Test Authorization

```bash
/opa-check ci-bot deploy production
# ✅ ALLOWED
# Agent: ci-bot
# Action: deploy
# Resource: production
# Reason: Agent has high trust level and is within business hours
```

## Features

### Authorization Commands

| Command | Description |
|---------|-------------|
| `/opa-check` | Check authorization for an action |
| `/opa-start` | Start OPA server |
| `/opa-stop` | Stop OPA server |
| `/opa-status` | Show OPA status |

### Policy Management

| Command | Description |
|---------|-------------|
| `/opa-load` | Load policies from directory |
| `/opa-test` | Test policies |
| `/opa-validate` | Validate policy syntax |
| `/opa-template` | Create policy template |

### Audit & Logging

| Command | Description |
|---------|-------------|
| `/opa-audit` | Show authorization audit log |
| `/opa-export-audit` | Export audit log (json/csv) |

### Configuration

| Command | Description |
|---------|-------------|
| `/opa-config` | Configure settings |
| `/opa-help` | Show help |

## Policy Language (Rego)

Policies are written in OPA's Rego language:

```rego
package pi.authz

# Default deny
default allow := false

# Allow trusted agents to read non-sensitive resources
allow if {
    input.agent.trust_level == "high"
    input.action.category == "read"
    input.resource.classification != "secret"
}

# Deny destructive actions after hours
deny contains violation if {
    input.action.category == "delete"
    not is_business_hours
    violation := {
        "policy": "business_hours",
        "rule": "no_destructive_after_hours",
        "message": "Destructive actions not allowed outside 9-5"
    }
}

is_business_hours if {
    time.now_ns >= time.parse_rfc3339_ns("2026-01-01T09:00:00Z")
    time.now_ns <= time.parse_rfc3339_ns("2026-01-01T17:00:00Z")
}
```

## Multi-Dimensional Access Control

OPA can evaluate multiple factors:

- **WHO** - Agent identity, roles, trust level
- **WHAT** - Action type, sensitivity
- **WHERE** - Network zone, IP address, VPN status
- **WHEN** - Time of day, business hours
- **WHY** - Purpose, ticket ID, approval chain

## A2A Integration

pi-opa integrates with `pi-a2a-communication` for agent-to-agent authorization:

```bash
# Enable A2A authorization
/opa-config integration.a2aEnabled true
/opa-config integration.requireOPAForA2A true

# Now all A2A requests go through OPA
/a2a-send some-agent "do something"
# → OPA evaluates authorization first
```

## Tools

### opa_evaluate

Evaluate authorization programmatically:

```json
{
  "tool": "opa_evaluate",
  "params": {
    "agent": "ci-bot",
    "action": "deploy",
    "resource": "production",
    "context": {
      "time": "14:00",
      "emergency": false
    }
  }
}
```

### opa_check_policy

Validate policy syntax:

```json
{
  "tool": "opa_check_policy",
  "params": {
    "policy_file": "./my_policy.rego"
  }
}
```

## Configuration

Default configuration location: `~/.pi/agent/opa/config.json`

```json
{
  "opa": {
    "binaryPath": "opa",
    "serverPort": 8181,
    "serverHost": "localhost",
    "autoStart": true,
    "logLevel": "info"
  },
  "policies": {
    "directory": "~/.pi/agent/opa/policies",
    "defaultPackage": "pi.authz",
    "autoReload": true,
    "testOnLoad": true
  },
  "authorization": {
    "defaultDecision": "deny",
    "cacheDecisions": true,
    "cacheTTL": 300000,
    "requireAuthentication": true
  },
  "audit": {
    "enabled": true,
    "logDirectory": "~/.pi/agent/opa/audit",
    "retentionDays": 90,
    "logSuccessful": true,
    "logFailed": true
  }
}
```

## Enterprise Features

### Audit Logging

All authorization decisions are logged with:
- Timestamp
- Agent identity
- Action and resource
- Decision (allow/deny)
- Policy violations
- Duration
- Context

Export to JSON or CSV for compliance reporting.

### Policy Testing

Write tests for your policies:

```rego
package pi.authz_test

import data.pi.authz

test_allow_trusted_read if {
    authz.allow with input as {
        "agent": {"trust_level": "high"},
        "action": {"category": "read"},
        "resource": {"classification": "internal"}
    }
}
```

### Decision Caching

Frequently evaluated decisions are cached for performance (configurable TTL).

### Hot Reload

Update policies without restarting - changes take effect immediately.

## Examples

### Example 1: Time-Based Access

```rego
# No destructive operations after 6 PM
deny contains violation if {
    input.action.category == "delete"
    time.now_ns > time.parse_rfc3339_ns("${TODAY}T18:00:00Z")
    violation := {
        "policy": "time_based",
        "message": "Destructive ops only allowed 9-6"
    }
}
```

### Example 2: Need-to-Know

```rego
# Customer data only for assigned agents
allow if {
    input.resource.type == "customer_data"
    input.agent.id == input.resource.assigned_agent
}
```

### Example 3: Emergency Override

```rego
# Emergency break-glass
allow if {
    input.context.emergency == true
    input.context.incident_id != ""
    input.agent.on_call == true
}
```

## Integration with OPA Ecosystem

pi-opa works with:
- **OPA CLI** - Local policy testing
- **OPA Server** - Production deployment
- **OPA Bundles** - Distributed policy updates
- **OPA Discovery** - Dynamic configuration
- **Styra DAS** - Managed OPA service

## Documentation

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [OPA Policy Testing](https://www.openpolicyagent.org/docs/latest/policy-testing/)

## License

MIT License - See [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please ensure:
1. Code follows TypeScript best practices
2. All new features include tests
3. Documentation is updated
4. Changes are backward compatible

## Support

- GitHub Issues: https://github.com/DrOlu/pi-opa/issues
- pi Discord: Link on pi.dev

---

**Secure your multi-agent workflows with pi-opa!** 🔒
