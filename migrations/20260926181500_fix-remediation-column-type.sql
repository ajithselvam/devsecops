-- remediation is free-form prose, not a JSON document. It was declared jsonb by
-- mistake, which would force every writer to JSON-encode a sentence.
ALTER TABLE public.findings
  ALTER COLUMN remediation TYPE text USING remediation::text;
