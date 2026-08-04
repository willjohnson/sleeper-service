## 2026-08-03 20:24 #security #audit

### Architecture And Configuration
- [x] Map entry points, trust boundaries, configuration, and secret handling

### Authentication And Authorization
- [x] Audit API and UI routes for authentication, tenant isolation, RBAC, CSRF, and object-level authorization

### Runtime And Integrations
- [x] Audit workers, agent tools, storage, outbound requests, sandboxing, and credential propagation

### Verification
- [x] Run tests, lint/static checks, and dependency/security checks available locally
- [x] Produce severity-ranked findings with code references and test gaps

## 2026-08-03 21:18 #security #remediation

### Identity And Tenant Boundaries
- [x] Bind OIDC identities to tenant membership and prevent tenant IdPs from authenticating superusers
- [x] Restrict stdio MCP registration to instance superusers and tenant-qualify UUID grants
- [x] Replace caller-asserted MCP identity with a signed authenticated context envelope

### Outbound And Data Authorization
- [x] Validate callback destinations against SSRF at submission and worker delivery
- [x] Authorize every delegation-tree node and filter UI dashboards to visible teams

### Browser Security
- [x] Add secure session defaults, CSRF validation, and login throttling

### Documentation And Verification
- [x] Add regression tests and run the complete verification suite
- [x] Write SECURITY_AUDIT_REPORT_2.md with findings, fixes, and residual risks

## 2026-08-03 21:31 #security #followup

### Review Follow-Ups (low severity, from audit-2 review)
- [ ] Rotate the CSRF token on login instead of carrying the pre-auth token into the authenticated session (ui/routes.py login, ui/oidc.py callback)
- [ ] Key the login rate limit on the real client IP behind a reverse proxy — request.client.host is the proxy, making the limit per-email and enabling cheap account-lockout DoS
- [ ] Treat a delivery-time OutboundUrlError as permanent instead of retrying the callback callback_max_tries times (runtime/callbacks.py)
