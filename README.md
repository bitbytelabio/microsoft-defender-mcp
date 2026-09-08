# Microsoft Defender MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for security investigation, threat intelligence, vulnerability management, and response workflows across Microsoft Defender XDR and Microsoft Defender for Endpoint (MDE).

Built in Rust with the official [`rmcp`](https://crates.io/crates/rmcp) SDK (v1.8), the server exposes **88 tools** across Microsoft Graph Security and Defender for Endpoint APIs. **86 tools are read-only**. The two mutating tools—Live Response execution and library file upload—are disabled by default through `DEFENDER_ENABLE_LIVE_RESPONSE`; command execution can be narrowed further with an optional command allowlist.

> **Security warning**
> `defender_library_file_upload` changes the tenant's Live Response library. `defender_endpoint_live_response_run` can copy files to, execute scripts on, or retrieve files from managed endpoints. MCP clients should require explicit human confirmation before invoking either tool.
> The HTTP transport has no built-in TLS or client authentication. Binding beyond `127.0.0.1` requires an authenticated reverse proxy, VPN, or equivalent trusted network boundary.

---

## Capabilities & Tool Summary

The server implements **88 tools** partitioned across two upstream API scopes:

```text
                               +-------------------------------------+
                               |          MCP Client (LLM)           |
                               +-------------------------------------+
                                                  |
                                   MCP Protocol (stdio / HTTP)
                                                  |
                               +-------------------------------------+
                               |    microsoft-defender-mcp-server    |
                               |    (In-memory OAuth2 token cache)   |
                               +-------------------------------------+
                                       /                     \
       OAuth scope: https://graph.microsoft.com/.default     OAuth scope: https://api.securitycenter.microsoft.com/.default
                                     /                         \
            +-------------------------------+    +------------------------------------+
            |      Microsoft Graph API      |    |    Defender for Endpoint API       |
            | (Advanced Hunting, TI, XDR)   |    | (Machines, TVM, Alerts, Response)  |
            +-------------------------------+    +------------------------------------+
```

### Tool Inventory & Categorization (88 Tools)

| Category / Domain | API Scope | Tools | Mode | Key Example Tools |
| :--- | :--- | :---: | :---: | :--- |
| **Advanced Hunting** | Graph Security | 1 | Read-Only | `defender_advanced_hunting_run` |
| **Threat Intelligence: Actors & Profiles** | Defender TI (Graph) | 5 | Read-Only | `defender_ti_intel_profiles_list`, `defender_ti_intel_profile_indicators_list` |
| **Threat Intelligence: Research Articles** | Defender TI (Graph) | 5 | Read-Only | `defender_ti_articles_list`, `defender_ti_article_indicators_list` |
| **Threat Intelligence: Host Infrastructure** | Defender TI (Graph) | 20 | Read-Only | `defender_ti_host_get`, `defender_ti_host_reputation_get`, `defender_ti_host_ports_list`, `defender_ti_host_pairs_list` |
| **Threat Intelligence: Global Entities** | Defender TI (Graph) | 6 | Read-Only | `defender_ti_ssl_certs_list`, `defender_ti_whois_records_list`, `defender_ti_passive_dns_get` |
| **Threat Intelligence: Vulnerabilities (CVE)** | Defender TI (Graph) | 3 | Read-Only | `defender_ti_vulnerability_get`, `defender_ti_vulnerability_components_list` |
| **XDR Incidents & Multi-Stage Alerts** | Graph Security v2 | 4 | Read-Only | `defender_xdr_incident_list`, `defender_xdr_incident_get`, `defender_xdr_alert_list` |
| **Endpoint Inventory & Configuration** | Defender for Endpoint | 6 | Read-Only | `defender_endpoint_machine_list`, `defender_endpoint_machine_logged_on_users`, `defender_endpoint_machine_find_by_tag` |
| **Software Inventory & Missing KBs** | Defender for Endpoint | 6 | Read-Only | `defender_endpoint_software_list`, `defender_endpoint_software_machines`, `defender_endpoint_software_missing_kbs` |
| **Vulnerability Management (TVM)** | Defender for Endpoint | 4 | Read-Only | `defender_endpoint_vulnerability_list`, `defender_endpoint_vulnerability_get_machines` |
| **Security Recommendations** | Defender for Endpoint | 5 | Read-Only | `defender_endpoint_recommendation_list`, `defender_endpoint_recommendation_machines` |
| **Remediation Tasks & Status** | Defender for Endpoint | 3 | Read-Only | `defender_endpoint_remediation_list`, `defender_endpoint_remediation_exposed_devices` |
| **Exposure & Risk Scoring** | Defender for Endpoint | 2 | Read-Only | `defender_endpoint_exposure_score`, `defender_endpoint_exposure_score_by_machine_groups` |
| **Entity Statistics: IP & Domain** | Defender for Endpoint | 5 | Read-Only | `defender_endpoint_ip_statistics`, `defender_endpoint_domain_statistics`, `defender_endpoint_domain_related_machines` |
| **Entity Statistics: Files & Prevalence** | Defender for Endpoint | 4 | Read-Only | `defender_endpoint_file_get`, `defender_endpoint_file_statistics`, `defender_endpoint_file_related_machines` |
| **User Entity Context** | Defender for Endpoint | 2 | Read-Only | `defender_endpoint_user_related_alerts`, `defender_endpoint_user_related_machines` |
| **Endpoint Alerts & Actions** | Defender for Endpoint | 4 | Read-Only | `defender_endpoint_alert_list`, `defender_endpoint_machine_action_get_status` |
| **Live Response (Gated Inspection)** | Defender for Endpoint | 1 | Read-Only | `defender_endpoint_live_response_get_result` |
| **Live Response & Library (Gated Mutations)** | Defender for Endpoint | 2 | **Mutation** | `defender_library_file_upload`, `defender_endpoint_live_response_run` |
| **Total** | | **88** | **86 RO / 2 Mut** | |

> **Authoritative Schemas:**
> Every tool publishes its complete JSON schema, parameter constraints, and security annotations via the standard MCP `tools/list` protocol endpoint.

---

## Prerequisites & Entra ID Permissions

Access requires a **Microsoft Entra ID (Azure AD)** Application Registration configured with an application password (client secret).

### Token Acquisition & Scopes

The server utilizes the OAuth 2.0 `client_credentials` grant. Access tokens are cached in-memory per scope with an automated **60-second safety refresh buffer**:
- **Microsoft Graph Scope:** `https://graph.microsoft.com/.default`
- **Defender for Endpoint Scope:** `https://api.securitycenter.microsoft.com/.default`

No credentials or access tokens are ever written to persistent storage.

### Application Permissions Reference

Following the principle of **least privilege**, grant only the application permissions required for the tool subsets your integration exercises. Application permissions require Entra ID administrator consent.

| Upstream Service | Application Permission | Operations / Tools Covered |
| :--- | :--- | :--- |
| **Microsoft Graph** | `ThreatHunting.Read.All` | KQL Advanced Hunting (`defender_advanced_hunting_run`) |
| **Microsoft Graph** | `ThreatIntelligence.Read.All` | Threat actor profiles, articles, host infrastructure, DNS, WHOIS, SSL certificates, CVEs *(Requires active Defender TI Portal & API add-on license)* |
| **Microsoft Graph** | `SecurityAlert.Read.All` | Microsoft Defender XDR Alerts v2 (`defender_xdr_alert_list`, `defender_xdr_alert_get`) |
| **Microsoft Graph** | `SecurityIncident.Read.All` | Microsoft Defender XDR Incidents (`defender_xdr_incident_list`, `defender_xdr_incident_get`) |
| **Defender for Endpoint** | `Machine.Read.All` | Device inventory/details, machine tags, and machine-action status |
| **Defender for Endpoint** | `User.Read.All` | Users observed on a machine |
| **Defender for Endpoint** | `Software.Read.All` | Organizational and per-machine software inventory, distributions, and missing KBs |
| **Defender for Endpoint** | `Vulnerability.Read.All` | Vulnerabilities, exposed machines, and recommendation-related CVEs |
| **Defender for Endpoint** | `SecurityRecommendation.Read.All` | Security recommendations and their machine references |
| **Defender for Endpoint** | `RemediationTasks.Read.All` | Remediation activities and exposed device lists |
| **Defender for Endpoint** | `Score.Read.All` | Tenant and device-group exposure scores |
| **Defender for Endpoint** | `Ip.Read.All` | IP communication statistics |
| **Defender for Endpoint** | `URL.Read.All` | Domain prevalence and communication statistics |
| **Defender for Endpoint** | `File.Read.All` | Global file reputation and organizational file prevalence |
| **Defender for Endpoint** | `Alert.Read.All` | Endpoint alerts plus IP- and user-related alerts |
| **Defender for Endpoint** | `Alert.ReadWrite.All` | Required by the upstream API for domain- and file-related alert queries; also accepted for IP/user alert queries |
| **Defender for Endpoint** | `Machine.ReadWrite.All` | Required by the upstream API for domain-, file-, and user-related machine queries and Live Response result links |
| **Defender for Endpoint** | `Machine.LiveResponse` | Live Response command execution (`defender_endpoint_live_response_run`) |
| **Defender for Endpoint** | `Library.Manage` | Live Response library uploads (`defender_library_file_upload`) |

---

## Installation & Build

### Install via Cargo (crates.io)

Install the pre-published crate directly from [crates.io](https://crates.io/crates/microsoft-defender-mcp-server):

```bash
cargo install microsoft-defender-mcp-server --locked
```

This installs the executable:
```text
microsoft-defender-mcp-server
```
Ensure Cargo's binary installation directory (typically `~/.cargo/bin`) is in your system `PATH`.

### Build from Source

Alternatively, build from source with an up-to-date Rust toolchain that supports the Rust 2024 edition:

```bash
# Clone the repository
git clone https://github.com/bitbytelabio/microsoft-defender-mcp.git
cd microsoft-defender-mcp

# Build release binary using locked dependencies
cargo build --release --locked
```

The compiled binary will be located at:
```text
target/release/microsoft-defender-mcp-server
```

---

## Configuration

Configuration is managed entirely through environment variables.

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `AZURE_TENANT_ID` | **Yes** | — | Microsoft Entra ID Directory (tenant) ID (GUID). |
| `AZURE_CLIENT_ID` | **Yes** | — | Application (client) ID registered in Entra ID (GUID). |
| `AZURE_CLIENT_SECRET` | **Yes** | — | Application client secret string. |
| `TRANSPORT` | No | `stdio` | Transport protocol: `stdio` (default) or `http`. |
| `BIND_ADDRESS` | No | `127.0.0.1:8000` | Socket address for HTTP transport (`TRANSPORT=http`). |
| `DEFENDER_ENABLE_LIVE_RESPONSE` | No | `false` | Gatekeeper for Live Response tools. Must be set to `true` to enable mutating and result tools. |
| `DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS` | No | *(all)* | Optional comma-separated allowlist for `defender_endpoint_live_response_run`: `PutFile`, `RunScript`, `GetFile`. It does not restrict library uploads or result-link retrieval. |
| `RUST_LOG` | No | `info` | Tracing log level filter (e.g. `info`, `debug`, `warn`). |

### Testing & Development Overrides (Advanced)

* `GRAPH_BASE_URL`: Overrides `https://graph.microsoft.com/v1.0` (used for mock server testing).
* `DEFENDER_ENDPOINT_BASE_URL`: Overrides `https://api.securitycenter.microsoft.com` (used for mock server testing).

---

## Running the Server

### 1. Standard I/O Transport (Recommended)

Stdio transport is the default mode, optimal for local MCP client runners (such as desktop AI assistants and local agent runtimes). Tracing diagnostic logs are written exclusively to `stderr`, leaving `stdout` clean for JSON-RPC MCP framing.

```bash
export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_CLIENT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_SECRET="your-azure-client-secret"

./target/release/microsoft-defender-mcp-server
```

### 2. Streamable HTTP Transport

Streamable HTTP transport allows hosting the MCP server over HTTP SSE/POST at the `/mcp` endpoint.

```bash
export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_CLIENT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_SECRET="your-azure-client-secret"
export TRANSPORT="http"
export BIND_ADDRESS="127.0.0.1:8000"

./target/release/microsoft-defender-mcp-server
```

Endpoint exposed:
```text
http://127.0.0.1:8000/mcp
```

#### Network Security Notice for HTTP
The built-in HTTP server provides **no encryption (TLS) or inbound client authentication**.
- By default, bind to the local loopback interface `127.0.0.1`.
- If binding to external interfaces (`0.0.0.0`), you **MUST** place the endpoint behind an authenticated reverse proxy (e.g., Nginx, Envoy, Caddy with mTLS or OAuth validation) or a private VPN boundary.

---

## MCP Client Configuration

Add the server to your MCP client configuration (e.g., `claude_desktop_config.json` or client settings).

### Stdio Configuration (Compiled Binary)

```json
{
  "mcpServers": {
    "microsoft-defender": {
      "command": "/absolute/path/to/microsoft-defender-mcp/target/release/microsoft-defender-mcp-server",
      "env": {
        "AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CLIENT_ID": "11111111-1111-1111-1111-111111111111",
        "AZURE_CLIENT_SECRET": "your-azure-client-secret"
      }
    }
  }
}
```

### Stdio Configuration with Live Response Enabled (Strictly Gated)

```json
{
  "mcpServers": {
    "microsoft-defender": {
      "command": "/absolute/path/to/microsoft-defender-mcp/target/release/microsoft-defender-mcp-server",
      "env": {
        "AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000000",
        "AZURE_CLIENT_ID": "11111111-1111-1111-1111-111111111111",
        "AZURE_CLIENT_SECRET": "your-azure-client-secret",
        "DEFENDER_ENABLE_LIVE_RESPONSE": "true",
        "DEFENDER_LIVE_RESPONSE_ALLOWED_COMMANDS": "GetFile,RunScript"
      }
    }
  }
}
```

Enabling `DEFENDER_ENABLE_LIVE_RESPONSE` also enables library upload and result-link retrieval. The command allowlist narrows only `defender_endpoint_live_response_run`; it is not an upload allowlist.

---

## Key Tool Call Examples

The following objects are the `params` portion of MCP `tools/call` requests. Tool responses use structured JSON.

### 1. Advanced Hunting (`defender_advanced_hunting_run`)

Executes read-only KQL queries across Microsoft Defender XDR unified event tables (`DeviceProcessEvents`, `DeviceNetworkEvents`, `EmailEvents`, `IdentityLogonEvents`, etc.).

```json
{
  "name": "defender_advanced_hunting_run",
  "arguments": {
    "query": "DeviceProcessEvents | where Timestamp > ago(7d) | where FileName =~ 'powershell.exe' | project Timestamp, DeviceName, AccountName, ProcessCommandLine | take 50",
    "timespan": "P7D"
  }
}
```

- **Timespan:** Defaults to `P30D` (30 days). Accepts ISO 8601 duration/interval representations (e.g., `P7D`, `P90D`, or explicit start/end ISO intervals). Queryable history depends on tenant event retention policies.
- **Client Limits:** Queries are locally validated (non-empty, <= 128 KB, cannot begin with management dot `.`). Upstream limits enforce a maximum of 100,000 rows, 50 MB response payload, and approximately 3-minute execution limit. The server HTTP client uses a 210-second timeout to accommodate long-running analytical queries.

### 2. XDR Incidents Listing (`defender_xdr_incident_list`)

Retrieves correlated security incidents aggregating signals across Identity, Endpoint, Cloud Apps, and Email.

```json
{
  "name": "defender_xdr_incident_list",
  "arguments": {
    "filter": "severity eq 'high' and status eq 'active'",
    "top": 25,
    "skip": 0
  }
}
```

### 3. Device Software Inventory (`defender_endpoint_machine_list_software`)

Lists installed software applications and versions discovered on an enrolled endpoint device.

```json
{
  "name": "defender_endpoint_machine_list_software",
  "arguments": {
    "machine_id": "1e50020e54d31e974e64f8c14828114be2880017"
  }
}
```

### 4. Live Response: Script Upload & Session (Gated Mutation)

> **Human Authorization Required:**
> Mutating actions must be confirmed by the human operator. Live Response operations require `DEFENDER_ENABLE_LIVE_RESPONSE=true`.

#### Step A: Upload File to Library (`defender_library_file_upload`)
Uploads a script to the shared Defender for Endpoint Live Response library.

```json
{
  "name": "defender_library_file_upload",
  "arguments": {
    "file_name": "collect_triage.ps1",
    "file_content": "Get-Process | Export-Csv -Path C:\\temp\\processes.csv -NoTypeInformation",
    "description": "Triage script for incident response process collection",
    "parameters_description": "No parameters required",
    "override_if_exists": true
  }
}
```
*Validation:* `file_name` must be a bare basename without directory separators. File content must be valid UTF-8 up to 20 MiB.

#### Step B: Execute Live Response Session (`defender_endpoint_live_response_run`)
Dispatches ordered remediation commands to an active machine.

```json
{
  "name": "defender_endpoint_live_response_run",
  "arguments": {
    "machine_id": "1e50020e54d31e974e64f8c14828114be2880017",
    "comment": "Executing forensic process collection for incident INC-10492",
    "commands": [
      {
        "type": "RunScript",
        "params": [
          { "key": "ScriptName", "value": "collect_triage.ps1" }
        ]
      },
      {
        "type": "GetFile",
        "params": [
          { "key": "Path", "value": "C:\\temp\\processes.csv" }
        ]
      }
    ]
  }
}
```
*Validation:* `commands` supports up to 20 ordered items. `comment` must contain at least 10 Unicode characters after trimming leading and trailing whitespace. If the target device is offline, commands can remain queued by the upstream service for up to 2 hours.

#### Step C: Download Command Result Link (`defender_endpoint_live_response_get_result`)
Fetches the SAS download URL for the output of a completed `RunScript` or `GetFile` command.

```json
{
  "name": "defender_endpoint_live_response_get_result",
  "arguments": {
    "action_id": "3b2e7a10-4491-4d3f-912a-8c011e4bf312",
    "command_index": 1
  }
}
```
*Validation:* `command_index` must be zero or positive (`>= 0`).

---

## Limits, Pagination & Error Handling

### Pagination Boundaries
- **Microsoft Graph list endpoints:** `top` defaults to 50, maximum 1,000.
- **Defender for Endpoint list endpoints:** `top` defaults to 50, maximum 10,000.
- **Skip offset:** Range `0` to `100,000`.
- **No Auto-Paging:** The server does not auto-follow `@odata.nextLink`. It preserves the link in the raw response; request subsequent pages explicitly with the pagination parameters supported by that tool.

### Query & Parameter Constraints
- **Hostnames:** Max 253 characters; internal whitespace, control characters, slashes, and dot navigation segments (`.` or `..`) are rejected.
- **Identifiers & Entity Keys:** Dynamically percent-encoded to RFC 3986 unreserved standards before inclusion in URI path segments.
- **Look-back Hours:** Statistics endpoints accept `look_back_hours` between 1 and 720 hours (up to 30 days; default 720).

### Response Structure & Error Mapping
- **Success:** Returns the upstream JSON in MCP `structuredContent`; `rmcp` also supplies a JSON text content item for compatible clients.
- **Client/Input Validation Failures:** Emits standard MCP protocol errors (`invalid_params`) containing the specific validation failure message.
- **API & Service Errors:** Emits tool-level errors (`isError: true`) with structured problem details:
  ```json
  {
    "error": "Permission denied for: /api/machines. Ensure the application registration has the required permissions and the tenant has appropriate licenses.",
    "httpStatus": 403
  }
  ```
  Standardized HTTP error mappings:
  - `400`: Bad request / invalid upstream query parameters.
  - `401`: Authentication failure (invalid client ID, secret, or tenant ID).
  - `403`: Permission denied (missing application permission or missing tenant license).
  - `404`: Target resource ID not found.
  - `429`: Rate limit exceeded (client should wait before retrying).
  - `504`: Upstream timeout (query too complex or timespan too broad).

---

## Development & Verification

The test suite uses local loopback HTTP services and synthetic fixtures; it does not require or contact a Microsoft tenant.

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --all-targets --workspace --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked
```

The test matrix exercises:
- OData serialization and Graph/MDE parameter bounds.
- RFC 3986 path-segment encoding and traversal defenses.
- KQL, IP, hostname, hash, filename, and Unicode-boundary validation.
- Live Response gating, typed commands, command allowlists, and result indices.
- Upstream success parsing and HTTP error-status preservation through real loopback requests.

---

## Official Documentation References

- [Model Context Protocol: Tools Specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [Microsoft Graph: Advanced Hunting API](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
- [Microsoft Graph: Security API Overview & Quotas](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview?view=graph-rest-1.0)
- [Microsoft Graph: Alerts v2 API](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0)
- [Microsoft Graph: Incidents API](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0)
- [Microsoft Defender for Endpoint: Run Live Response API](https://learn.microsoft.com/en-us/defender-endpoint/api/run-live-response)
- [Microsoft Defender for Endpoint: Upload File to Library API](https://learn.microsoft.com/en-us/defender-endpoint/api/upload-library)
- [Microsoft Defender for Endpoint: Get Live Response Result Download Link](https://learn.microsoft.com/en-us/defender-endpoint/api/get-live-response-result)
- [Microsoft Defender for Endpoint: API Permission Reference](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-full-high-level)

---

## License

Licensed under the MIT license declared in `Cargo.toml`.
