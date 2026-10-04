"""Central configuration: semantic names, dynamic fields, ownership, sensitive."""
from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_SEMANTIC_NAMES: set[str] = {
    "id", "uid", "uuid", "guid",
    "userid", "user_id",
    "accountid", "account_id",
    "projectid", "project_id",
    "teamid", "team_id",
    "organizationid", "organization_id",
    "orgid", "org_id",
    "deploymentid", "deployment_id",
    "resourceid", "resource_id",
    "documentid", "document_id",
    "orderid", "order_id",
    "objectid", "object_id",
    "resource", "object",
    "tenantid", "tenant_id",
    "customerid", "customer_id",
    "memberid", "member_id",
    "groupid", "group_id",
    "fileid", "file_id",
    "reportid", "report_id",
    "invoiceid", "invoice_id",
}

DEFAULT_DYNAMIC_HEADERS: set[str] = {
    "date", "server", "content-length", "transfer-encoding",
    "connection", "keep-alive", "etag", "last-modified",
    "x-request-id", "x-trace-id", "x-correlation-id",
    "x-amzn-trace-id", "x-amz-cf-id", "cf-ray",
    "set-cookie", "cache-control", "expires", "age",
    "strict-transport-security", "vary", "via",
    "x-runtime", "x-response-time", "x-powered-by",
    "x-served-by", "x-cache", "x-cache-hits",
    "report-to", "nel", "alt-svc",
}

DEFAULT_DYNAMIC_JSON_FIELDS: set[str] = {
    "timestamp", "createdat", "created_at",
    "updatedat", "updated_at", "modifiedat", "modified_at",
    "requestid", "request_id", "traceid", "trace_id",
    "spanid", "span_id", "correlationid", "correlation_id",
    "nonce", "csrf", "csrftoken", "csrf_token",
    "sessionid", "session_id", "sessiontoken", "session_token",
    "servertime", "server_time", "elapsed", "duration",
    "expiresat", "expires_at", "issuedat", "issued_at",
}

DEFAULT_OWNERSHIP_FIELDS: set[str] = {
    "ownerid", "owner_id",
    "userid", "user_id",
    "accountid", "account_id",
    "teamid", "team_id",
    "organizationid", "organization_id",
    "orgid", "org_id",
    "tenantid", "tenant_id",
    "createdby", "created_by",
    "user", "owner", "account", "team", "organization",
    "tenant", "member",
}

DEFAULT_SENSITIVE_FIELDS: set[str] = {
    "password", "passwd", "pwd",
    "token", "access_token", "access-token",
    "refresh_token", "refresh-token",
    "apikey", "api_key", "api-key",
    "secret", "client_secret", "client-secret",
    "ssn", "social_security",
    "credit_card", "creditcard", "cardnumber", "card_number",
    "cvv", "cvc", "pin",
    "private_key", "privatekey",
    "mfa", "totp", "otp",
}

DEFAULT_PRIVATE_FIELDS: set[str] = {"private", "is_private", "isprivate"}
DEFAULT_PUBLIC_FIELDS: set[str] = {"public", "is_public", "ispublic"}

DEFAULT_VISIBILITY_FIELDS: set[str] = {"visibility", "scope", "access"}


@dataclass
class Config:
    semantic_names: set[str] = field(default_factory=lambda: set(DEFAULT_SEMANTIC_NAMES))
    dynamic_headers: set[str] = field(default_factory=lambda: set(DEFAULT_DYNAMIC_HEADERS))
    dynamic_json_fields: set[str] = field(default_factory=lambda: set(DEFAULT_DYNAMIC_JSON_FIELDS))
    ownership_fields: set[str] = field(default_factory=lambda: set(DEFAULT_OWNERSHIP_FIELDS))
    sensitive_fields: set[str] = field(default_factory=lambda: set(DEFAULT_SENSITIVE_FIELDS))
    private_fields: set[str] = field(default_factory=lambda: set(DEFAULT_PRIVATE_FIELDS))
    public_fields: set[str] = field(default_factory=lambda: set(DEFAULT_PUBLIC_FIELDS))
    visibility_fields: set[str] = field(default_factory=lambda: set(DEFAULT_VISIBILITY_FIELDS))
    similarity_threshold_high: float = 0.9
    similarity_threshold_medium: float = 0.7


def default_config() -> Config:
    return Config()
