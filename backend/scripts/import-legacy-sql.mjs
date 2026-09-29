/**
 * Loads migrations/legacy-data.sql into InsForge.
 *
 *   node scripts/import-legacy-sql.mjs [path/to/legacy-data.sql]
 *
 * The CLI has no stdin/file mode for `db query` and macOS caps a single argv
 * entry at 262144 bytes, so statements are read from the generated file and
 * packed into batches under that limit. Every statement is idempotent
 * (ON CONFLICT DO NOTHING), so an interrupted run can simply be repeated.
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(process.argv[2] ?? resolve(here, '../../migrations/legacy-data.sql'));
// The linked project lives in .insforge/project.json at the repo root.
const repoRoot = resolve(here, '../..');

const SEPARATOR = '\n-- @@\n';

const statements = readFileSync(sqlPath, 'utf8')
  .split(SEPARATOR)
  .map((statement) =>
    // The CLI parses a leading "--" as an option, so drop leading comment
    // lines; they are documentation for the generated file only. A comment at
    // the end of a chunk has no trailing newline, hence the `(?:\n|$)`.
    statement.replace(/^(?:[ \t]*--[^\n]*(?:\n|$))+/, '').trim()
  )
  .filter((statement) => statement.length > 0)
  .map((statement) => (statement.endsWith(';') ? statement : `${statement};`));

console.log(`${statements.length} statements from ${sqlPath}`);

// One statement per call: the CLI's SQL guard silently ignores any statement
// after the first in a multi-statement argument.
let applied = 0;
for (const [index, statement] of statements.entries()) {
  const result = spawnSync('npx', ['-y', '@insforge/cli', 'db', 'query', statement], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024
  });

  if (result.status !== 0) {
    const output = result.stderr || result.stdout || '(no output)';
    // Error payloads can echo a multi-megabyte SBOM, so keep the report short.
    console.error(`\nStatement ${index + 1}/${statements.length} failed (${applied} applied):`);
    console.error(`  starts: ${statement.slice(0, 200).replace(/\n/g, ' ')}`);
    console.error(`  output: ${output.slice(0, 1500)}`);
    process.exit(result.status ?? 1);
  }

  applied += 1;
  const preview = statement.split('\n')[0].slice(0, 58);
  console.log(`  ${index + 1}/${statements.length} ok  ${preview} (${(statement.length / 1024).toFixed(0)}KB)`);
}

console.log(`\nApplied ${applied} statements.`);
