# Cisco Umbrella MCP Server

A production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for querying and managing Cisco Secure Access (Umbrella) infrastructure. Built with [FastMCP](https://github.com/jlowin/fastmcp), this server provides comprehensive access to **87+ Umbrella API endpoints** across 5 API sections — enabling AI assistants like Claude to interact directly with your Umbrella security platform.

## Features

- **OAuth2 Authentication** — Automatic token management via client credentials flow with 60-second refresh buffer
- **87+ API Endpoints** — Covers Admin, Deployments, Reports, Investigate, and Policies sections
- **13 Pre-Registered Tools** — Optimized tools for the most common operations (VPN, DNS, threats, tunnels, etc.)
- **Generic API Gateway** — `call_umbrella_api` tool provides access to all 87+ registered endpoints
- **Two-Tier Caching** — In-memory + file-based caching with configurable TTL (default 5 min)
- **Multi-Tenant Support** — Optional `X-Umbrella-OrgId` header for multi-org environments
- **Read-Only Mode** — Enforce safe audit/reporting workflows by blocking write operations
- **Automatic 401 Retry** — Token refresh and request retry on authentication failures
- **Method Discovery** — Search and list available API methods at runtime

## Architecture

```
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│   Claude Desktop /   │     │   Umbrella MCP       │     │   Cisco Umbrella     │
│   AI Assistant       │────▶│   Server (FastMCP)   │────▶│   API                │
│                      │ MCP │                      │HTTP │                      │
│   - 13 direct tools  │◀────│   - OAuth2 tokens    │◀────│   - Reports v2       │
│   - Generic API call │     │   - Request caching  │     │   - Deployments v2   │
│   - Method discovery │     │   - File caching     │     │   - Policies v2      │
└──────────────────────┘     └──────────────────────┘     │   - Admin v2         │
                                                          │   - Investigate v2   │
                                                          └──────────────────────┘
```

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/demon0110/umbrella_mcp.git
cd umbrella_mcp
```

### 2. Get API Credentials

1. Log in to the [Cisco Umbrella Dashboard](https://dashboard.umbrella.com)
2. Navigate to **Admin → API Keys**
3. Click **Create** to generate a new API key pair
4. Select the scopes you need (Reports, Deployments, Policies, Investigate, Admin)
5. Copy the **Client ID** and **Client Secret**
6. Note your **Organization ID** if using multi-tenant mode

### 3. Configure Environment

```bash
cp .env-example .env
```

Edit `.env` with your credentials:

```env
CISCO_CLIENT_ID="your-client-id-here"
CISCO_CLIENT_SECRET="your-client-secret-here"
CISCO_ORG_ID="your-org-id"          # Optional, for multi-tenant
```

### 4. Install Dependencies

**Option A: Using the setup script (recommended)**

```bash
chmod +x setup.sh
./setup.sh
```

**Option B: Manual install**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 5. Configure Claude Desktop

Add the following to your `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "Umbrella_MCP": {
      "command": "/path/to/umbrella_mcp/.venv/bin/python",
      "args": ["/path/to/umbrella_mcp/umbrella-mcp.py"]
    }
  }
}
```

> **Note:** The server reads credentials from the `.env` file in the project directory. Alternatively, you can pass them via the `env` block in the config above.

### 6. Restart Claude Desktop

After saving the config, fully restart Claude Desktop. The Umbrella MCP tools should appear in the tool list.

## Available Tools

### Pre-Registered Tools (13)

These are first-class MCP tools optimized for the most common workflows:

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `getVpnUserConnections` | List active VPN user connections | `status`, `limit`, `offset` |
| `getActivityDns` | Query DNS activity records | `time_from`, `time_to`, `verdict`, `domains` |
| `getActivityProxy` | Query proxy/web activity records | `time_from`, `time_to`, `verdict` |
| `getActivityFirewall` | Query firewall activity records | `time_from`, `time_to` |
| `getActivityZtna` | Query ZTNA activity records | `time_from`, `time_to` |
| `getRemoteAccessEvents` | Get remote access events | `time_from`, `time_to` |
| `getSummary` | Get summary statistics | `time_from`, `time_to` |
| `getTopThreats` | Get top threats by count | `time_from`, `time_to`, `limit` |
| `getTopDestinations` | Get top destinations | `time_from`, `time_to`, `verdict` |
| `getTopIdentities` | Get top users/identities | `time_from`, `time_to`, `limit` |
| `getRoamingComputers` | Get endpoint inventory | `limit`, `offset` |
| `getNetworkTunnelGroups` | Get all tunnel groups | — |
| `getNetworkTunnelGroupStates` | Get tunnel group states | — |

### Generic Tools (7)

| Tool | Description |
|------|-------------|
| `call_umbrella_api` | Call **any** registered endpoint by section and method name |
| `list_all_methods` | Discover available API methods (optionally filter by section) |
| `search_methods` | Search for methods by keyword |
| `get_cached_response` | Retrieve paginated cached responses from disk |
| `cache_stats` | View cache statistics and configuration |
| `cache_clear` | Flush all in-memory and file-based caches |
| `get_mcp_config` | View current server configuration |

## API Sections & Endpoint Counts

| Section | Endpoints | Description |
|---------|-----------|-------------|
| **admin** | 12 | VPN users, API keys, ZTNA, integrations, alerts, tenants |
| **deployments** | 20 | Tunnel groups, connectors, roaming computers, sites, internal domains |
| **reports** | 41 | Activity logs, top lists, summaries, bandwidth, deployment status |
| **investigate** | 3 | Domain, IP, and URL threat investigation |
| **policies** | 11 | Destination lists, private resources, access policies, network/service objects |

## Configuration Reference

All configuration is done via environment variables in `.env`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CISCO_CLIENT_ID` | Yes | — | OAuth2 Client ID from Umbrella dashboard |
| `CISCO_CLIENT_SECRET` | Yes | — | OAuth2 Client Secret |
| `CISCO_ORG_ID` | No | — | Organization ID for multi-tenant mode |
| `CISCO_BASE_URL` | No | `https://api.umbrella.com` | API base URL |
| `CISCO_AUTH_URL` | No | `{base_url}/auth/v2/token` | OAuth2 token endpoint |
| `ENABLE_CACHING` | No | `true` | Enable/disable response caching |
| `CACHE_TTL_SECONDS` | No | `300` | Cache time-to-live in seconds |
| `READ_ONLY_MODE` | No | `false` | Block all write (PUT/POST/DELETE) operations |
| `ENABLE_FILE_CACHING` | No | `true` | Enable disk-based caching for large responses |
| `MAX_RESPONSE_TOKENS` | No | `5000` | Maximum response token size |
| `MAX_PER_PAGE` | No | `100` | Maximum items per paginated request |
| `RESPONSE_CACHE_DIR` | No | `~/.umbrella_cache` | Custom cache directory path |

## Usage Examples

### Query Blocked DNS Activity

```
Tool: getActivityDns
  time_from: "2026-03-01T00:00:00Z"
  time_to: "2026-03-11T23:59:59Z"
  verdict: "blocked"
  limit: 50
```

### Get Top Threats

```
Tool: getTopThreats
  time_from: "2026-03-01T00:00:00Z"
  time_to: "2026-03-11T23:59:59Z"
  limit: 10
```

### List Active VPN Connections

```
Tool: getVpnUserConnections
  limit: 50
```

### Call Any Endpoint via Generic Tool

```
Tool: call_umbrella_api
  section: "policies"
  method_name: "getDestinationLists"
  parameters: {}
```

### Investigate a Suspicious Domain

```
Tool: call_umbrella_api
  section: "investigate"
  method_name: "investigateDomain"
  parameters: {"domain": "suspicious-site.com"}
```

### Discover Available Methods

```
Tool: search_methods
  keyword: "tunnel"
```

## Caching

The server implements a two-tier caching strategy:

1. **In-Memory Cache** — Fast dictionary-based lookup for recently accessed GET endpoints. Keyed by SHA-256 hash of method + path + parameters.
2. **File Cache** — Persistent JSON files stored in `~/.umbrella_cache/` (configurable). Useful for large responses that exceed context window limits.

Cache entries are automatically invalidated after the configured TTL (default: 300 seconds). Use the `cache_clear` tool to manually flush all caches, or `cache_stats` to inspect current cache state.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| **401 Unauthorized** | Automatically clears token, refreshes, and retries the request once |
| **Invalid Credentials** | Raises `ValueError` at startup with instructions to get credentials |
| **Read-Only Violation** | Returns error message when write operations are attempted in read-only mode |
| **Network Errors** | Propagated as `httpx` exceptions with descriptive messages |

## Troubleshooting

### "CISCO_CLIENT_ID and CISCO_CLIENT_SECRET must be set"
- Ensure your `.env` file exists in the project root and contains valid credentials
- Verify the `.env` file is being loaded (check working directory)

### 400 Bad Request on Reports Endpoints
- Verify your API key has the **Reports** scope enabled in Umbrella dashboard
- New API keys may take 15–30 minutes to propagate
- Some report endpoints require specific Umbrella license tiers (Advantage/SIG)

### 401 Errors Persisting After Retry
- Regenerate your API key in the Umbrella dashboard
- Confirm `CISCO_BASE_URL` matches your deployment (umbrella.com vs sse.cisco.com)

### Slow Queries
- Use `time_from` and `time_to` to narrow time ranges
- Check `cache_stats` to verify caching is working
- Reduce `limit` for large result sets

## Project Structure

```
umbrella_mcp/
├── umbrella-mcp.py      # Main MCP server (all-in-one)
├── .env-example          # Template for environment variables
├── .env                  # Your actual credentials (git-ignored)
├── .gitignore            # Git ignore rules
├── requirements.txt      # Python dependencies
├── pyproject.toml        # Project metadata
├── setup.sh              # Automated setup script
└── README.md             # This file
```

## Requirements

- Python 3.10+
- `mcp[cli]>=1.0.0` — Model Context Protocol SDK
- `httpx>=0.27.0` — Async HTTP client
- `pydantic>=2.0.0` — Data validation
- `python-dotenv>=1.0.0` — Environment variable management

## License

MIT License

## Resources

- [Cisco Secure Access API Documentation](https://developer.cisco.com/docs/secure-access/)
- [Umbrella API Reference](https://docs.umbrella.com/developer/management-api/v2/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [FastMCP Framework](https://github.com/jlowin/fastmcp)
