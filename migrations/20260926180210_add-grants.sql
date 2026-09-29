-- SQL privileges. Policies decide which rows; grants decide which operations
-- reach them. Narrower surfaces revoke the broad default first.

GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;

-- role is admin-only: users edit their own preferences but cannot escalate.
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (name, avatar_url, theme, sidebar_collapsed, language,
              email_notifications, in_app_notifications, notify_scan_complete,
              notify_scan_failed, notify_vuln_found, notify_job_change,
              last_login_at)
  ON public.profiles TO authenticated;

-- Ownership columns on child tables are trigger/server maintained.
REVOKE UPDATE ON public.findings FROM authenticated;
GRANT UPDATE (type, severity, title, description, file, line, column_index, code,
              rule_id, rule_name, cve, package, installed_version, fixed_version,
              cvss_score, cwe, reference_urls, remediation, status)
  ON public.findings TO authenticated;

REVOKE UPDATE ON public.log_entries FROM authenticated;
GRANT UPDATE (timestamp, level, service, message, raw, fields, indexed)
  ON public.log_entries TO authenticated;

REVOKE UPDATE ON public.github_scans FROM authenticated;
GRANT UPDATE (branch, commit_sha, sbom, summary, vulnerabilities, secrets,
              code_issues, dep_issues, scan_time)
  ON public.github_scans TO authenticated;

-- key_hash is server-managed.
REVOKE UPDATE ON public.api_keys FROM authenticated;
GRANT UPDATE (name, last_used_at, expires_at, revoked_at)
  ON public.api_keys TO authenticated;

-- audit_logs is append-only from a client perspective.
REVOKE INSERT, UPDATE, DELETE ON public.audit_logs FROM authenticated;
