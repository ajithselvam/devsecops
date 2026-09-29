-- github_repositories / github_scans
CREATE TABLE public.github_repositories (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  github_id       bigint NOT NULL UNIQUE,
  name            text NOT NULL,
  full_name       text NOT NULL,
  url             text NOT NULL,
  clone_url       text NOT NULL,
  default_branch  text NOT NULL DEFAULT 'main',
  private         boolean NOT NULL DEFAULT false,
  connected_at    timestamptz NOT NULL DEFAULT now(),
  last_scanned_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_github_repositories_user ON public.github_repositories(user_id);

CREATE TABLE public.github_scans (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  repo_id          uuid NOT NULL REFERENCES public.github_repositories(id) ON DELETE CASCADE,
  branch           text NOT NULL,
  commit_sha       text NOT NULL,
  sbom             jsonb,
  summary          jsonb,
  vulnerabilities  jsonb NOT NULL DEFAULT '[]'::jsonb,
  secrets          jsonb NOT NULL DEFAULT '[]'::jsonb,
  code_issues      jsonb NOT NULL DEFAULT '[]'::jsonb,
  dep_issues       jsonb NOT NULL DEFAULT '[]'::jsonb,
  scan_time        timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_github_scans_repo_time ON public.github_scans(repo_id, scan_time DESC);

-- notifications
CREATE TABLE public.notifications (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  type        text NOT NULL CHECK (type IN ('scan_complete', 'scan_failed', 'vulnerability_found', 'job_completed', 'job_failed', 'fix_ready', 'pr_created', 'system_alert', 'info')),
  title       text NOT NULL,
  message     text NOT NULL,
  is_read     boolean NOT NULL DEFAULT false,
  action_url  text,
  metadata    jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_notifications_user_read_created ON public.notifications(user_id, is_read, created_at DESC);

-- api_keys (hash only; plaintext is never stored)
CREATE TABLE public.api_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  name         text NOT NULL,
  key_hash     text NOT NULL UNIQUE,
  prefix       text NOT NULL,
  last_used_at timestamptz,
  expires_at   timestamptz,
  revoked_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_user ON public.api_keys(user_id);

-- audit_logs (outlives the user row)
CREATE TABLE public.audit_logs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  action      text NOT NULL,
  resource    text NOT NULL,
  resource_id text,
  metadata    jsonb,
  ip          text,
  user_agent  text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_user_created ON public.audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_resource ON public.audit_logs(resource, resource_id);
