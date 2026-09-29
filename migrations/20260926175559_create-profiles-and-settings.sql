-- profiles (app-owned user profile; PK is the auth user id)
CREATE TABLE public.profiles (
  id                    uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name                  text NOT NULL DEFAULT '',
  avatar_url            text,
  role                  text NOT NULL DEFAULT 'engineer' CHECK (role IN ('admin', 'engineer', 'viewer')),
  theme                 text NOT NULL DEFAULT 'system' CHECK (theme IN ('light', 'dark', 'system')),
  sidebar_collapsed     boolean NOT NULL DEFAULT false,
  language              text NOT NULL DEFAULT 'en',
  email_notifications   boolean NOT NULL DEFAULT true,
  in_app_notifications  boolean NOT NULL DEFAULT true,
  notify_scan_complete  boolean NOT NULL DEFAULT true,
  notify_scan_failed    boolean NOT NULL DEFAULT true,
  notify_vuln_found     boolean NOT NULL DEFAULT true,
  notify_job_change     boolean NOT NULL DEFAULT true,
  last_login_at         timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_profiles_role ON public.profiles(role);

-- settings (per-user integration config; contains encrypted secrets)
CREATE TABLE public.settings (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid NOT NULL UNIQUE REFERENCES public.profiles(id) ON DELETE CASCADE,

  ai_provider             text NOT NULL DEFAULT 'apps_script',
  ai_apps_script_url      text,
  ai_openai_key           text,
  ai_gemini_key           text,
  ai_anthropic_key        text,
  ai_default_model        text NOT NULL DEFAULT 'gemini-pro',
  ai_temperature          real NOT NULL DEFAULT 0.2,
  ai_max_tokens           integer NOT NULL DEFAULT 8192,

  docker_hub_username     text,
  docker_hub_token        text,
  docker_registry         text NOT NULL DEFAULT 'docker.io',
  docker_build_timeout    integer NOT NULL DEFAULT 300000,
  docker_scan_timeout     integer NOT NULL DEFAULT 180000,

  github_app_id           text,
  github_private_key      text,
  github_webhook_secret   text,
  github_default_org      text,
  github_token            text,

  gitlab_token            text,
  bitbucket_token         text,
  slack_webhook           text,
  teams_webhook           text,
  jira_url                text,
  jira_token              text,
  webhook_url             text,
  webhook_secret          text,

  scanning_default_tools  jsonb NOT NULL DEFAULT '["grype", "syft"]'::jsonb,
  scanning_max_concurrent integer NOT NULL DEFAULT 3,
  scanning_timeout        integer NOT NULL DEFAULT 600000,

  debug_mode              boolean NOT NULL DEFAULT false,
  telemetry_enabled       boolean NOT NULL DEFAULT true,
  auto_update             boolean NOT NULL DEFAULT true,

  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);
