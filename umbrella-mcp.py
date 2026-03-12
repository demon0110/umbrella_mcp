#!/usr/bin/env python3
"""
Cisco Secure Access (Umbrella) MCP Server
Provides access to Umbrella API endpoints for querying and managing security infrastructure.
"""

import os
import json
import time
import hashlib
import asyncio
from typing import Optional, Any, Dict, List, Union
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import asynccontextmanager

import httpx
from pydantic import BaseModel
from mcp.server.fastmcp import FastMCP


# ============================================================================
# TokenManager: OAuth2 Client Credentials Flow
# ============================================================================

class TokenManager:
    """Manages OAuth2 tokens with automatic refresh."""

    def __init__(self, client_id: str, client_secret: str,
                 auth_url: str = "https://api.sse.cisco.com/auth/v2/token"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.token = None
        self.token_expiry = None
        self.lock = asyncio.Lock()

    async def get_token(self, http_client: httpx.AsyncClient) -> str:
        """Get valid token, refreshing if needed."""
        async with self.lock:
            # Check if token is still valid (with 60s buffer)
            if self.token and self.token_expiry and \
               datetime.utcnow() < self.token_expiry - timedelta(seconds=60):
                return self.token

            # Refresh token
            auth = (self.client_id, self.client_secret)
            data = {"grant_type": "client_credentials"}

            response = await http_client.post(
                self.auth_url,
                auth=auth,
                data=data,
                timeout=30.0
            )
            response.raise_for_status()

            token_data = response.json()
            self.token = token_data["access_token"]
            expires_in = token_data.get("expires_in", 3600)
            self.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

            return self.token


# ============================================================================
# SecureAccessClient: HTTP Client with Caching
# ============================================================================

class SecureAccessClient:
    """HTTP client for Umbrella API with caching support."""

    def __init__(self, base_url: str, token_manager: TokenManager,
                 enable_caching: bool = True, cache_ttl: int = 300,
                 enable_file_caching: bool = True,
                 cache_dir: Optional[str] = None,
                 org_id: Optional[str] = None,
                 sse_base_url: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        # Secure Access (SSE) base URL for deployments/admin endpoints
        self.sse_base_url = (sse_base_url or "https://api.sse.cisco.com").rstrip("/")
        self.token_manager = token_manager
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        self.enable_file_caching = enable_file_caching
        self.org_id = org_id
        self.memory_cache = {}  # {cache_key: (data, timestamp)}

        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".umbrella_cache"

        if self.enable_file_caching:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, method: str, path: str, params: Optional[Dict] = None) -> str:
        """Generate cache key from request parameters."""
        key_str = f"{method}:{path}:{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    def _get_file_cache_path(self, cache_key: str) -> Path:
        """Get file cache path for a key."""
        return self.cache_dir / f"{cache_key}.json"

    def _is_cache_valid(self, timestamp: float) -> bool:
        """Check if cache entry is still valid."""
        return (time.time() - timestamp) < self.cache_ttl

    async def request(self, method: str, path: str,
                     params: Optional[Dict] = None,
                     json_body: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     retry_on_401: bool = True,
                     use_sse: bool = False) -> Any:
        """Make HTTP request with caching.

        Args:
            use_sse: If True, use the Secure Access (SSE) base URL instead of the
                     Umbrella base URL. Required for /deployments and /admin endpoints
                     on Secure Connect organizations.
        """

        # Build headers
        req_headers = headers or {}
        if self.org_id and "X-Umbrella-OrgId" not in req_headers:
            req_headers["X-Umbrella-OrgId"] = self.org_id

        # Check memory cache for GET requests
        cache_key = self._get_cache_key(method, path, params)
        if self.enable_caching and method == "GET":
            if cache_key in self.memory_cache:
                data, timestamp = self.memory_cache[cache_key]
                if self._is_cache_valid(timestamp):
                    return data

            # Check file cache
            if self.enable_file_caching:
                cache_file = self._get_file_cache_path(cache_key)
                if cache_file.exists():
                    try:
                        with open(cache_file, "r") as f:
                            cached = json.load(f)
                            if self._is_cache_valid(cached.get("_cached_at", 0)):
                                return cached.get("data", {})
                    except Exception:
                        pass

        # Make actual request — use SSE base URL for deployments/admin endpoints
        effective_base = self.sse_base_url if use_sse else self.base_url
        url = f"{effective_base}{path}"
        token = await self.token_manager.get_token(httpx.AsyncClient())
        req_headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method, url,
                params=params,
                json=json_body,
                headers=req_headers
            )

            # Handle 401 with token refresh
            if response.status_code == 401 and retry_on_401:
                self.token_manager.token = None
                self.token_manager.token_expiry = None
                return await self.request(method, path, params, json_body,
                                        headers, retry_on_401=False)

            response.raise_for_status()
            data = response.json() if response.content else {}

        # Cache successful response
        if self.enable_caching and method == "GET":
            self.memory_cache[cache_key] = (data, time.time())

            if self.enable_file_caching:
                cache_file = self._get_file_cache_path(cache_key)
                try:
                    with open(cache_file, "w") as f:
                        json.dump({
                            "_cached_at": time.time(),
                            "data": data
                        }, f)
                except Exception:
                    pass

        return data

    async def get(self, path: str, params: Optional[Dict] = None,
                 headers: Optional[Dict] = None, use_sse: bool = False) -> Any:
        """GET request."""
        return await self.request("GET", path, params=params, headers=headers, use_sse=use_sse)

    async def put(self, path: str, json_body: Optional[Dict] = None,
                 headers: Optional[Dict] = None, use_sse: bool = False) -> Any:
        """PUT request."""
        return await self.request("PUT", path, json_body=json_body, headers=headers, use_sse=use_sse)

    async def post(self, path: str, json_body: Optional[Dict] = None,
                  headers: Optional[Dict] = None, use_sse: bool = False) -> Any:
        """POST request."""
        return await self.request("POST", path, json_body=json_body, headers=headers, use_sse=use_sse)

    async def delete(self, path: str, headers: Optional[Dict] = None, use_sse: bool = False) -> Any:
        """DELETE request."""
        return await self.request("DELETE", path, headers=headers, use_sse=use_sse)


# ============================================================================
# API Registry
# ============================================================================

API_REGISTRY = {
    "admin": {
        "getVpnUserConnections": {
            "method": "GET",
            "path": "/admin/v2/vpn/userConnections",
            "description": "List active VPN user connections"
        },
        "disconnectVpnUsers": {
            "method": "PUT",
            "path": "/admin/v2/vpn/userConnections",
            "description": "Disconnect VPN users",
            "read_only": False
        },
        "getApiKeys": {
            "method": "GET",
            "path": "/admin/v2/apiKeys",
            "description": "Get API keys"
        },
        "getZtnaUserSummaries": {
            "method": "GET",
            "path": "/admin/v2/ztna/userSummaries",
            "description": "Get ZTNA user summaries"
        },
        "getIntegrations": {
            "method": "GET",
            "path": "/admin/v2/integrations",
            "description": "Get integrations"
        },
        "getIntegration": {
            "method": "GET",
            "path": "/admin/v2/integrations/{intId}",
            "description": "Get integration by ID"
        },
        "getIntegrationTypes": {
            "method": "GET",
            "path": "/admin/v2/integrationTypes",
            "description": "Get integration types"
        },
        "getAlertRules": {
            "method": "GET",
            "path": "/admin/v2/alerting/rules",
            "description": "Get alert rules"
        },
        "getAlertRule": {
            "method": "GET",
            "path": "/admin/v2/alerting/rules/{ruleId}",
            "description": "Get alert rule by ID"
        },
        "getAlerts": {
            "method": "GET",
            "path": "/admin/v2/alerting/alerts",
            "description": "Get alerts"
        },
        "getAlert": {
            "method": "GET",
            "path": "/admin/v2/alerting/alerts/{alertId}",
            "description": "Get alert by ID"
        },
        "getTenants": {
            "method": "GET",
            "path": "/admin/v2/tenants/list",
            "description": "List tenants"
        },
    },
    "deployments": {
        "getNetworkTunnelGroups": {
            "method": "GET",
            "path": "/deployments/v2/networktunnelgroups",
            "description": "Get network tunnel groups"
        },
        "getNetworkTunnelGroup": {
            "method": "GET",
            "path": "/deployments/v2/networktunnelgroups/{id}",
            "description": "Get network tunnel group by ID"
        },
        "getNetworkTunnelGroupState": {
            "method": "GET",
            "path": "/deployments/v2/networktunnelgroups/{id}/state",
            "description": "Get network tunnel group state"
        },
        "getNetworkTunnelGroupStates": {
            "method": "GET",
            "path": "/deployments/v2/networktunnelgroupsstate",
            "description": "Get network tunnel group states"
        },
        "getNetworkTunnelGroupPeers": {
            "method": "GET",
            "path": "/deployments/v2/networktunnelgroups/{id}/peers",
            "description": "Get network tunnel group peers"
        },
        "getRegions": {
            "method": "GET",
            "path": "/deployments/v2/regions",
            "description": "Get regions"
        },
        "getConnectorGroups": {
            "method": "GET",
            "path": "/deployments/v2/connectorGroups",
            "description": "Get connector groups"
        },
        "getConnectorGroup": {
            "method": "GET",
            "path": "/deployments/v2/connectorGroups/{id}",
            "description": "Get connector group by ID"
        },
        "getConnectorGroupCounts": {
            "method": "GET",
            "path": "/deployments/v2/connectorGroups/counts",
            "description": "Get connector group counts"
        },
        "getConnectors": {
            "method": "GET",
            "path": "/deployments/v2/connectorAgents",
            "description": "Get connectors"
        },
        "getConnector": {
            "method": "GET",
            "path": "/deployments/v2/connectorAgents/{id}",
            "description": "Get connector by ID"
        },
        "getConnectorCounts": {
            "method": "GET",
            "path": "/deployments/v2/connectorAgents/counts",
            "description": "Get connector counts"
        },
        "getRoamingComputers": {
            "method": "GET",
            "path": "/deployments/v2/roamingcomputers",
            "description": "Get roaming computers"
        },
        "getRoamingComputer": {
            "method": "GET",
            "path": "/deployments/v2/roamingcomputers/{deviceId}",
            "description": "Get roaming computer by ID"
        },
        "getRoamingComputersOrgInfo": {
            "method": "GET",
            "path": "/deployments/v2/roamingcomputers/orgInfo",
            "description": "Get roaming computers organization info"
        },
        "getInternalDomains": {
            "method": "GET",
            "path": "/deployments/v2/internaldomains",
            "description": "Get internal domains"
        },
        "getInternalDomain": {
            "method": "GET",
            "path": "/deployments/v2/internaldomains/{internalDomainId}",
            "description": "Get internal domain by ID"
        },
        "getSites": {
            "method": "GET",
            "path": "/deployments/v2/sites",
            "description": "Get sites"
        },
        "getSite": {
            "method": "GET",
            "path": "/deployments/v2/sites/{siteId}",
            "description": "Get site by ID"
        },
    },
    "reports": {
        "getActivity": {
            "method": "GET",
            "path": "/reports/v2/activity",
            "description": "Get all activity records"
        },
        "getActivityDns": {
            "method": "GET",
            "path": "/reports/v2/activity/dns",
            "description": "Get DNS activity"
        },
        "getActivityProxy": {
            "method": "GET",
            "path": "/reports/v2/activity/proxy",
            "description": "Get proxy activity"
        },
        "getActivityFirewall": {
            "method": "GET",
            "path": "/reports/v2/activity/firewall",
            "description": "Get firewall activity"
        },
        "getActivityIntrusion": {
            "method": "GET",
            "path": "/reports/v2/activity/intrusion",
            "description": "Get intrusion activity"
        },
        "getActivityZtna": {
            "method": "GET",
            "path": "/reports/v2/activity/ztna",
            "description": "Get ZTNA activity"
        },
        "getActivityDecryption": {
            "method": "GET",
            "path": "/reports/v2/activity/decryption",
            "description": "Get decryption activity"
        },
        "getActivityAmpRetrospective": {
            "method": "GET",
            "path": "/reports/v2/activity/amp-retrospective",
            "description": "Get AMP retrospective activity"
        },
        "getTopIdentities": {
            "method": "GET",
            "path": "/reports/v2/top-identities",
            "description": "Get top identities"
        },
        "getTopDestinations": {
            "method": "GET",
            "path": "/reports/v2/top-destinations",
            "description": "Get top destinations"
        },
        "getTopUrls": {
            "method": "GET",
            "path": "/reports/v2/top-urls",
            "description": "Get top URLs"
        },
        "getTopCategories": {
            "method": "GET",
            "path": "/reports/v2/top-categories",
            "description": "Get top categories"
        },
        "getTopEventTypes": {
            "method": "GET",
            "path": "/reports/v2/top-eventtypes",
            "description": "Get top event types"
        },
        "getTopThreats": {
            "method": "GET",
            "path": "/reports/v2/top-threats",
            "description": "Get top threats"
        },
        "getTopThreatTypes": {
            "method": "GET",
            "path": "/reports/v2/top-threattypes",
            "description": "Get top threat types"
        },
        "getTopIps": {
            "method": "GET",
            "path": "/reports/v2/top-ips",
            "description": "Get top IPs"
        },
        "getTopDnsQueryTypes": {
            "method": "GET",
            "path": "/reports/v2/top-dnsquerytypes",
            "description": "Get top DNS query types"
        },
        "getTopFiles": {
            "method": "GET",
            "path": "/reports/v2/top-files",
            "description": "Get top files"
        },
        "getTopResources": {
            "method": "GET",
            "path": "/reports/v2/top-resources",
            "description": "Get top resources"
        },
        "getSummary": {
            "method": "GET",
            "path": "/reports/v2/summary",
            "description": "Get summary"
        },
        "getSummaryByCategory": {
            "method": "GET",
            "path": "/reports/v2/summaries-by-category",
            "description": "Get summary by category"
        },
        "getSummaryByDestination": {
            "method": "GET",
            "path": "/reports/v2/summaries-by-destination",
            "description": "Get summary by destination"
        },
        "getSummaryByRule": {
            "method": "GET",
            "path": "/reports/v2/summaries-by-rule",
            "description": "Get summary by rule"
        },
        "getRequestsByHour": {
            "method": "GET",
            "path": "/reports/v2/requests-by-hour",
            "description": "Get requests by hour"
        },
        "getRequestsByTimerange": {
            "method": "GET",
            "path": "/reports/v2/requests-by-timerange",
            "description": "Get requests by timerange"
        },
        "getBandwidthByHour": {
            "method": "GET",
            "path": "/reports/v2/bandwidth-by-hour",
            "description": "Get bandwidth by hour"
        },
        "getBandwidthByTimerange": {
            "method": "GET",
            "path": "/reports/v2/bandwidth-by-timerange",
            "description": "Get bandwidth by timerange"
        },
        "getDeploymentStatus": {
            "method": "GET",
            "path": "/reports/v2/deployment-status",
            "description": "Get deployment status"
        },
        "getTotalRequests": {
            "method": "GET",
            "path": "/reports/v2/total-requests",
            "description": "Get total requests"
        },
        "getNetworkTunnelLogs": {
            "method": "GET",
            "path": "/reports/v2/network-tunnel-logs",
            "description": "Get network tunnel logs"
        },
        "getApplications": {
            "method": "GET",
            "path": "/reports/v2/applications",
            "description": "Get applications"
        },
        "getCategories": {
            "method": "GET",
            "path": "/reports/v2/categories",
            "description": "Get categories"
        },
        "getIdentities": {
            "method": "GET",
            "path": "/reports/v2/identities",
            "description": "Get identities"
        },
        "getIdentity": {
            "method": "GET",
            "path": "/reports/v2/identities/{identityId}",
            "description": "Get identity by ID"
        },
        "getThreatTypes": {
            "method": "GET",
            "path": "/reports/v2/threat-types",
            "description": "Get threat types"
        },
        "getThreatNames": {
            "method": "GET",
            "path": "/reports/v2/threat-names",
            "description": "Get threat names"
        },
        "getPrivateResourceAccessDetails": {
            "method": "GET",
            "path": "/reports/v2/private-resource-access/details",
            "description": "Get private resource access details"
        },
        "getPrivateResourceAccessByIdentity": {
            "method": "GET",
            "path": "/reports/v2/private-resource-access/identity",
            "description": "Get private resource access by identity"
        },
        "getPrivateResourceAccessSummary": {
            "method": "GET",
            "path": "/reports/v2/private-resource-access/summary",
            "description": "Get private resource access summary"
        },
        "getRemoteAccessEvents": {
            "method": "GET",
            "path": "/reports/v2/remote-access-events",
            "description": "Get remote access events"
        },
        "getRulesForActivity": {
            "method": "GET",
            "path": "/reports/v2/rules",
            "description": "Get rules for activity"
        },
    },
    "investigate": {
        "investigateDomain": {
            "method": "GET",
            "path": "/investigate/v2/domains/{domain}",
            "description": "Investigate domain"
        },
        "investigateIp": {
            "method": "GET",
            "path": "/investigate/v2/ips/{ip}",
            "description": "Investigate IP"
        },
        "investigateUrl": {
            "method": "GET",
            "path": "/investigate/v2/urls/{url}",
            "description": "Investigate URL"
        },
    },
    "policies": {
        "getDestinationLists": {
            "method": "GET",
            "path": "/policies/v2/destinationlists",
            "description": "Get destination lists"
        },
        "getDestinationList": {
            "method": "GET",
            "path": "/policies/v2/destinationlists/{listId}",
            "description": "Get destination list by ID"
        },
        "getDestinationListEntries": {
            "method": "GET",
            "path": "/policies/v2/destinationlists/{listId}/destinations",
            "description": "Get destination list entries"
        },
        "getPrivateResources": {
            "method": "GET",
            "path": "/policies/v2/privateresources",
            "description": "Get private resources"
        },
        "getPrivateResource": {
            "method": "GET",
            "path": "/policies/v2/privateresources/{resourceId}",
            "description": "Get private resource by ID"
        },
        "getResourceGroups": {
            "method": "GET",
            "path": "/policies/v2/resourcegroups",
            "description": "Get resource groups"
        },
        "getAccessPolicyRules": {
            "method": "GET",
            "path": "/policies/v2/accesspolicyrules",
            "description": "Get access policy rules"
        },
        "getNetworkObjects": {
            "method": "GET",
            "path": "/policies/v2/networkobjects",
            "description": "Get network objects"
        },
        "getServiceObjects": {
            "method": "GET",
            "path": "/policies/v2/serviceobjects",
            "description": "Get service objects"
        },
        "getApplicationLists": {
            "method": "GET",
            "path": "/policies/v2/applicationlists",
            "description": "Get application lists"
        },
        "getContentCategories": {
            "method": "GET",
            "path": "/policies/v2/contentcategories",
            "description": "Get content categories"
        },
        "getApplicationCategories": {
            "method": "GET",
            "path": "/policies/v2/applicationcategories",
            "description": "Get application categories"
        },
    },
}


# ============================================================================
# MCP Server Setup
# ============================================================================

# Initialize environment
from dotenv import load_dotenv
load_dotenv()

client_id = os.getenv("CISCO_CLIENT_ID")
client_secret = os.getenv("CISCO_CLIENT_SECRET")

if not client_id or not client_secret:
    raise ValueError(
        "CISCO_CLIENT_ID and CISCO_CLIENT_SECRET must be set. "
        "Get these from https://dashboard.umbrella.com → Admin → API Keys"
    )

base_url = os.getenv("CISCO_BASE_URL", "https://api.umbrella.com")
sse_base_url = os.getenv("CISCO_SSE_BASE_URL", "https://api.sse.cisco.com")
org_id = os.getenv("CISCO_ORG_ID")
enable_caching = os.getenv("ENABLE_CACHING", "true").lower() == "true"
cache_ttl = int(os.getenv("CACHE_TTL_SECONDS", "300"))
read_only_mode = os.getenv("READ_ONLY_MODE", "false").lower() == "true"
enable_file_caching = os.getenv("ENABLE_FILE_CACHING", "true").lower() == "true"
max_response_tokens = int(os.getenv("MAX_RESPONSE_TOKENS", "5000"))
max_per_page = int(os.getenv("MAX_PER_PAGE", "100"))
cache_dir = os.getenv("RESPONSE_CACHE_DIR")

# Initialize token manager and client
auth_url = os.getenv("CISCO_AUTH_URL", f"{base_url}/auth/v2/token")
token_manager = TokenManager(client_id, client_secret, auth_url=auth_url)
http_client = SecureAccessClient(
    base_url=base_url,
    token_manager=token_manager,
    enable_caching=enable_caching,
    cache_ttl=cache_ttl,
    enable_file_caching=enable_file_caching,
    cache_dir=cache_dir,
    org_id=org_id,
    sse_base_url=sse_base_url
)

# Create MCP server
mcp = FastMCP("umbrella-mcp")


# ============================================================================
# Pre-registered Tools (16 tools)
# ============================================================================

@mcp.tool()
async def getVpnOverview(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """Get a comprehensive VPN/Remote Access overview combining live connections and historical events.

    This tool queries TWO endpoints:
    1. Live VPN connections (/admin/v2/vpn/userConnections) — currently connected users
    2. Remote Access Events (/reports/v2/remote-access-events) — historical connect/disconnect logs

    NOTE: The live connections endpoint returns 404 when no users are actively connected
    (rather than an empty list). This is normal Umbrella API behavior — not an error.

    Args:
        time_from: Start time for historical events — ISO 8601 or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time for historical events — ISO 8601 or "now" (default: "now")
        limit: Maximum historical event results per page

    Returns:
        Combined dict with 'live_connections' (current) and 'historical_events' (time range)
    """
    results = {}

    # 1. Try to get live VPN connections (uses SSE base URL for admin endpoints)
    try:
        live = await http_client.get("/admin/v2/vpn/userConnections", params={}, use_sse=True)
        results["live_connections"] = live
    except Exception as e:
        error_str = str(e)
        if "404" in error_str:
            results["live_connections"] = {
                "status": "no_active_connections",
                "note": "No users currently connected via VPN (404 is normal when 0 connected)"
            }
        else:
            results["live_connections"] = {"error": error_str}

    # 2. Get historical remote access events
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)

    try:
        historical = await http_client.get("/reports/v2/remote-access-events", params=params)
        results["historical_events"] = historical
    except Exception as e:
        results["historical_events"] = {"error": str(e)}

    return results


@mcp.tool()
async def getActivityDns(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    domains: Optional[str] = None,
    verdict: Optional[str] = None
) -> Dict[str, Any]:
    """Get DNS activity records.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset
        domains: Filter by domains (comma-separated)
        verdict: Filter by verdict (blocked, allowed, etc)

    Returns:
        DNS activity records
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset
    if domains:
        params["domains"] = domains
    if verdict:
        params["verdict"] = verdict

    return await http_client.get("/reports/v2/activity/dns", params=params)


@mcp.tool()
async def getActivityProxy(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    verdict: Optional[str] = None
) -> Dict[str, Any]:
    """Get proxy activity records.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset
        verdict: Filter by verdict

    Returns:
        Proxy activity records
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset
    if verdict:
        params["verdict"] = verdict

    return await http_client.get("/reports/v2/activity/proxy", params=params)


@mcp.tool()
async def getActivityFirewall(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> Dict[str, Any]:
    """Get firewall activity records.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset

    Returns:
        Firewall activity records
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset

    return await http_client.get("/reports/v2/activity/firewall", params=params)


@mcp.tool()
async def getActivityZtna(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> Dict[str, Any]:
    """Get ZTNA activity records.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset

    Returns:
        ZTNA activity records
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset

    return await http_client.get("/reports/v2/activity/ztna", params=params)


@mcp.tool()
async def getRemoteAccessEvents(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> Dict[str, Any]:
    """Get remote access (VPN) events including connect/disconnect history.

    This is the primary endpoint for VPN user activity. Each event contains:
    - identities: User info (name, email)
    - connectionevent: 'connected' or 'disconnected'
    - osversion: Client OS version
    - publicip/internalip: Connection IPs
    - tunnel1/tunnel2: Tunnel details
    - reason: Disconnect reason (e.g., ACCT_DISC_SESS_TIMEOUT)
    - timestamp: Unix timestamp of the event

    TIP: Use getVpnOverview for a combined live + historical view.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset

    Returns:
        Remote access events with connection/disconnection details
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset

    return await http_client.get("/reports/v2/remote-access-events", params=params)


@mcp.tool()
async def getSummary(
    time_from: str = "-1days",
    time_to: str = "now"
) -> Dict[str, Any]:
    """Get summary statistics.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")

    Returns:
        Summary statistics
    """
    params = {"from": time_from, "to": time_to}

    return await http_client.get("/reports/v2/summary", params=params)


@mcp.tool()
async def getTopThreats(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """Get top threats.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results

    Returns:
        Top threats
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)

    return await http_client.get("/reports/v2/top-threats", params=params)



@mcp.tool()
async def getTopIdentities(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """Get top identities.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results

    Returns:
        Top identities
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)

    return await http_client.get("/reports/v2/top-identities", params=params)


@mcp.tool()
async def getRoamingComputers(
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> Union[Dict[str, Any], List[Any]]:
    """Get roaming computers (endpoints).

    Args:
        limit: Maximum results per page
        offset: Pagination offset

    Returns:
        List of roaming computers
    """
    params = {}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset

    result = await http_client.get("/deployments/v2/roamingcomputers", params=params, use_sse=True)
    # Umbrella returns a list for this endpoint; wrap it for consistent MCP response
    if isinstance(result, list):
        return {"result": result, "count": len(result)}
    return result


@mcp.tool()
async def getNetworkTunnelGroups() -> Dict[str, Any]:
    """Get all network tunnel groups (Secure Connect / IPsec tunnels).

    Returns tunnel group configurations including:
    - Tunnel name, ID, and type (Secure Internet Access, etc.)
    - Site assignment and data center location
    - Provisioning status (Active, Inactive, Unestablished)

    Returns:
        List of network tunnel groups
    """
    return await http_client.get("/deployments/v2/networktunnelgroups", use_sse=True)


@mcp.tool()
async def getNetworkTunnelGroupStates() -> Dict[str, Any]:
    """Get network tunnel group states (active/inactive/unestablished status).

    Returns the operational state of all configured tunnels. Use this to check
    which tunnels are currently up and passing traffic vs down or unestablished.

    Returns:
        Network tunnel group states with status for each tunnel
    """
    return await http_client.get("/deployments/v2/networktunnelgroupsstate", use_sse=True)


@mcp.tool()
async def getNetworkTunnelGroupById(
    tunnel_group_id: str
) -> Dict[str, Any]:
    """Get detailed configuration for a specific network tunnel group by ID.

    Args:
        tunnel_group_id: The ID of the tunnel group to retrieve

    Returns:
        Detailed tunnel group configuration including peers, site, and DC location
    """
    return await http_client.get(f"/deployments/v2/networktunnelgroups/{tunnel_group_id}", use_sse=True)


@mcp.tool()
async def getNetworkTunnelGroupPeers(
    tunnel_group_id: str
) -> Dict[str, Any]:
    """Get the IPsec peers (tunnel endpoints) for a specific tunnel group.

    Args:
        tunnel_group_id: The ID of the tunnel group

    Returns:
        List of IPsec peers with their configuration and status
    """
    return await http_client.get(f"/deployments/v2/networktunnelgroups/{tunnel_group_id}/peers", use_sse=True)


@mcp.tool()
async def getNetworkTunnelLogs(
    time_from: str = "-1days",
    time_to: str = "now",
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> Dict[str, Any]:
    """Get network tunnel logs showing tunnel up/down events and traffic stats.

    Use this to troubleshoot tunnel flapping, identify connectivity issues,
    and track tunnel establishment/teardown events over time.

    Args:
        time_from: Start time — ISO 8601 format or relative like "-1days", "-7days" (default: "-1days")
        time_to: End time — ISO 8601 format or "now" (default: "now")
        limit: Maximum results per page
        offset: Pagination offset

    Returns:
        Tunnel log events with timestamps, tunnel IDs, and status changes
    """
    params = {"from": time_from, "to": time_to}
    if limit:
        params["limit"] = min(limit, max_per_page)
    if offset:
        params["offset"] = offset

    return await http_client.get("/reports/v2/network-tunnel-logs", params=params)


# ============================================================================
# Generic Tools
# ============================================================================

@mcp.tool()
async def call_umbrella_api(
    section: str,
    method_name: str,
    parameters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Call any Umbrella API endpoint.

    Args:
        section: API section (admin, deployments, reports, investigate, policies)
        method_name: Method name from registry
        parameters: Query parameters or path replacements

    Returns:
        API response
    """
    if section not in API_REGISTRY:
        return {"error": f"Unknown section: {section}. Available: {list(API_REGISTRY.keys())}"}

    if method_name not in API_REGISTRY[section]:
        return {"error": f"Unknown method: {method_name} in section {section}"}

    endpoint = API_REGISTRY[section][method_name]
    path = endpoint["path"]
    method = endpoint["method"]

    # Replace path parameters
    params = parameters or {}
    for key, value in params.copy().items():
        placeholder = f"{{{key}}}"
        if placeholder in path:
            path = path.replace(placeholder, str(value))
            del params[key]

    # Check read_only mode
    if read_only_mode and method != "GET":
        return {"error": "Write operations disabled (READ_ONLY_MODE enabled)"}

    # Auto-detect SSE base URL for deployments and admin endpoints
    use_sse = section in ("deployments", "admin")

    try:
        if method == "GET":
            return await http_client.get(path, params=params if params else None, use_sse=use_sse)
        elif method == "PUT":
            return await http_client.put(path, json_body=params if params else None, use_sse=use_sse)
        elif method == "POST":
            return await http_client.post(path, json_body=params if params else None, use_sse=use_sse)
        elif method == "DELETE":
            return await http_client.delete(path, use_sse=use_sse)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def list_all_methods(section: Optional[str] = None) -> Dict[str, Any]:
    """List all available API methods.

    Args:
        section: Optional section to filter (admin, deployments, reports, investigate, policies)

    Returns:
        Available methods with descriptions
    """
    if section:
        if section not in API_REGISTRY:
            return {"error": f"Unknown section: {section}"}
        methods = API_REGISTRY[section]
    else:
        methods = {s: list(m.keys()) for s, m in API_REGISTRY.items()}

    return methods


@mcp.tool()
async def search_methods(keyword: str) -> Dict[str, Any]:
    """Search for API methods by keyword.

    Args:
        keyword: Search term

    Returns:
        Matching methods
    """
    keyword = keyword.lower()
    results = {}

    for section, methods in API_REGISTRY.items():
        for method_name, endpoint in methods.items():
            if keyword in method_name.lower() or keyword in endpoint["description"].lower():
                if section not in results:
                    results[section] = {}
                results[section][method_name] = endpoint

    return results


@mcp.tool()
async def get_cached_response(
    filepath: str,
    offset: int = 0,
    limit: int = 10
) -> Dict[str, Any]:
    """Get paginated cached response from file.

    Args:
        filepath: Path to cached response file
        offset: Starting index
        limit: Maximum items per page

    Returns:
        Paginated response
    """
    try:
        with open(filepath, "r") as f:
            cache_data = json.load(f)

        data = cache_data.get("data", {})

        # Handle array responses
        if isinstance(data, list):
            total = len(data)
            page = data[offset:offset+limit]
            return {
                "total": total,
                "offset": offset,
                "limit": limit,
                "count": len(page),
                "items": page
            }

        return {"error": "Cached response is not an array", "data": data}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def cache_stats() -> Dict[str, Any]:
    """Get cache statistics.

    Returns:
        Cache stats and configuration
    """
    cache_files = []
    if http_client.enable_file_caching and http_client.cache_dir.exists():
        cache_files = [f.name for f in http_client.cache_dir.glob("*.json")]

    return {
        "memory_cache_size": len(http_client.memory_cache),
        "file_cache_enabled": http_client.enable_file_caching,
        "file_cache_directory": str(http_client.cache_dir),
        "file_cache_count": len(cache_files),
        "cache_ttl_seconds": http_client.cache_ttl,
        "caching_enabled": http_client.enable_caching,
        "read_only_mode": read_only_mode
    }


@mcp.tool()
async def cache_clear() -> Dict[str, Any]:
    """Clear all caches.

    Returns:
        Confirmation
    """
    # Clear memory cache
    http_client.memory_cache.clear()

    # Clear file cache
    if http_client.enable_file_caching and http_client.cache_dir.exists():
        for cache_file in http_client.cache_dir.glob("*.json"):
            cache_file.unlink()

    return {"status": "success", "message": "All caches cleared"}


@mcp.tool()
async def get_mcp_config() -> Dict[str, Any]:
    """Get MCP configuration.

    Returns:
        Current configuration
    """
    return {
        "base_url": base_url,
        "sse_base_url": sse_base_url,
        "org_id": org_id if org_id else "Not set (single-tenant mode)",
        "caching_enabled": enable_caching,
        "cache_ttl_seconds": cache_ttl,
        "read_only_mode": read_only_mode,
        "file_caching_enabled": enable_file_caching,
        "max_response_tokens": max_response_tokens,
        "max_per_page": max_per_page,
        "cache_directory": cache_dir if cache_dir else str(Path.home() / ".umbrella_cache"),
        "api_sections": list(API_REGISTRY.keys()),
        "total_endpoints": sum(len(methods) for methods in API_REGISTRY.values())
    }


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
