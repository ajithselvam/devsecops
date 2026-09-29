-- scans
CREATE TABLE public.scans (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  type           text NOT NULL CHECK (type IN ('dockerfile', 'docker_image', 'kubernetes', 'jenkinsfile', 'github_repo', 'dependency', 'logs')),
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
  target_type    text NOT NULL,
  target_value   text NOT NULL,
  target_meta    jsonb,
  summary        jsonb,
  job_id         uuid UNIQUE,
  artifact_key   text,
  artifact_url   text,
  completed_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_user_created ON public.scans(user_id, created_at DESC);
CREATE INDEX idx_scans_type_status ON public.scans(type, status);

-- findings (user_id denormalized from the parent scan by trigger)
CREATE TABLE public.findings (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  scan_id            uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  type               text NOT NULL CHECK (type IN ('vulnerability', 'misconfiguration', 'secret', 'bad_practice', 'syntax_error', 'security_issue', 'performance', 'compliance')),
  severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title              text NOT NULL,
  description        text NOT NULL,
  file               text,
  line               integer,
  column_index       integer,
  code               text,
  rule_id            text,
  rule_name          text,
  cve                text,
  package            text,
  installed_version  text,
  fixed_version      text,
  cvss_score         real,
  cwe                text,
  reference_urls     jsonb NOT NULL DEFAULT '[]'::jsonb,
  remediation        jsonb,
  status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored', 'in_progress', 'false_positive')),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_scan_severity ON public.findings(scan_id, severity);
CREATE INDEX idx_findings_user_severity ON public.findings(user_id, severity);
CREATE INDEX idx_findings_cve ON public.findings(cve);
CREATE INDEX idx_findings_package ON public.findings(package);
