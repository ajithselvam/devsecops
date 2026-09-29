import { getAdmin } from './insforge';
import { TABLE_COLUMNS, toColumn, toColumns, toFields, toRows, type TableName } from './mapper';
import type {
  ApiKey, AuditLog, Finding, GitHubRepository, GitHubScan, Job, LogEntry, LogFile,
  Notification, Scan, Settings, User
} from './types';

/**
 * A small Prisma-shaped data layer over the InsForge admin client.
 *
 * The route modules were written against Prisma's fluent API. Rather than
 * rewriting every call site, this exposes the same verbs (findMany,
 * findUnique, createMany, upsert, groupBy, ...) translated onto the PostgREST
 * query builder, with camelCase in and snake_case at the wire.
 *
 * Supported `where` shapes: scalar equality, `{ in: [...] }`,
 * `{ contains, mode }`, `null`, and `OR` arrays of those. That covers every
 * filter the current routes build.
 */

type Row = Record<string, unknown>;

export interface Where {
  [key: string]: unknown;
}

type IncludeSpec = true | Record<string, unknown>;

export interface FindArgs<K extends string = string> {
  where?: Where;
  orderBy?: Record<string, 'asc' | 'desc'> | Record<string, 'asc' | 'desc'>[];
  take?: number;
  skip?: number;
  include?: { [P in K]?: IncludeSpec } | Record<string, IncludeSpec>;
  select?: Record<string, boolean>;
}

interface RelationSpec {
  table: TableName;
  /** Column on the child table pointing back at the parent. */
  foreignKey: string;
}

const RELATIONS: Record<string, RelationSpec> = {
  findings: { table: 'findings', foreignKey: 'scan_id' },
  entries: { table: 'log_entries', foreignKey: 'log_file_id' },
  scan: { table: 'scans', foreignKey: 'id' },
  repos: { table: 'github_repositories', foreignKey: 'id' },
  repo: { table: 'github_repositories', foreignKey: 'id' },
  settings: { table: 'settings', foreignKey: 'user_id' }
};

const TABLE_ALIASES: Record<string, TableName> = {
  user: 'profiles',
  setting: 'settings',
  scan: 'scans',
  finding: 'findings',
  job: 'jobs',
  logFile: 'log_files',
  logEntry: 'log_entries',
  gitHubRepository: 'github_repositories',
  githubScan: 'github_scans',
  notification: 'notifications',
  apiKey: 'api_keys',
  auditLog: 'audit_logs'
};

function resolveTable(name: string): TableName {
  const table = TABLE_ALIASES[name] ?? (name as TableName);
  if (!TABLE_COLUMNS[table]) {
    throw new Error(`Unknown table "${name}"`);
  }
  return table;
}

/* ------------------------------------------------------------------ *
 * where -> PostgREST filters
 * ------------------------------------------------------------------ */

const UNSUPPORTED = new Set(['AND', 'NOT']);

function applyFilters(builder: any, table: TableName, where: Where | undefined): any {
  if (!where) return builder;

  for (const [field, condition] of Object.entries(where)) {
    if (condition === undefined) continue;

    if (field === 'OR') {
      const clauses = (condition as Where[]).map((clause) => orClause(table, clause));
      builder = builder.or(clauses.join(','));
      continue;
    }

    if (UNSUPPORTED.has(field)) {
      throw new Error(`where.${field} is not supported by the InsForge data layer`);
    }

    // Relations in a where clause are not used by the current routes.
    if (RELATIONS[field]) {
      throw new Error(`Filtering on relation "${field}" is not supported`);
    }

    const column = toColumn(table, field);

    if (condition === null) {
      builder = builder.is(column, null);
    } else if (typeof condition !== 'object') {
      builder = builder.eq(column, condition as string | number | boolean);
    } else {
      const spec = condition as Record<string, unknown>;
      if (Array.isArray(spec.in)) {
        builder = builder.in(column, spec.in as unknown[]);
      } else if (typeof spec.contains === 'string') {
        const pattern = `%${spec.contains}%`;
        builder = spec.mode === 'insensitive' ? builder.ilike(column, pattern) : builder.like(column, pattern);
      } else if (spec.not === null) {
        builder = builder.not.is(column, null);
      } else if ('equals' in spec) {
        builder = builder.eq(column, spec.equals as string);
      } else {
        throw new Error(`Unsupported filter on "${field}": ${JSON.stringify(spec)}`);
      }
    }
  }

  return builder;
}

function orClause(table: TableName, clause: Where): string {
  const parts: string[] = [];
  for (const [field, condition] of Object.entries(clause)) {
    const column = toColumn(table, field);
    if (condition === null) {
      parts.push(`${column}.is.null`);
    } else if (typeof condition !== 'object') {
      parts.push(`${column}.eq.${condition}`);
    } else {
      const spec = condition as Record<string, unknown>;
      if (typeof spec.contains === 'string') {
        parts.push(`${column}.ilike.*${spec.contains}*`);
      } else if ('equals' in spec) {
        parts.push(`${column}.eq.${spec.equals}`);
      } else {
        throw new Error(`Unsupported OR filter on "${field}"`);
      }
    }
  }
  return parts.join('and');
}

/* ------------------------------------------------------------------ *
 * select / include
 * ------------------------------------------------------------------ */

function selectList(table: TableName, select?: Record<string, boolean>): string {
  const fields = Object.entries(select ?? {})
    .filter(([, wanted]) => wanted)
    .map(([field]) => toColumn(table, field));
  return fields.length > 0 ? fields.join(',') : '*';
}

/** Returns [column, direction] pairs, keeping the caller's requested direction. */
function orderArgs(table: TableName, orderBy: FindArgs['orderBy']): Array<[string, 'asc' | 'desc']> {
  if (!orderBy) return [];
  const groups = Array.isArray(orderBy) ? orderBy : [orderBy];
  return groups.flatMap((group) =>
    Object.entries(group).map(
      ([field, direction]) => [toColumn(table, field), direction === 'desc' ? 'desc' : 'asc'] as [string, 'asc' | 'desc']
    )
  );
}

/** Stable multi-key sort; the SDK's `.order()` can only express one key. */
function sortRows<T>(rows: T[], order: Array<[string, 'asc' | 'desc']>): T[] {
  if (order.length === 0) return rows;
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => {
      for (const [column, direction] of order) {
        const left = (a.row as Record<string, unknown>)[column] ?? null;
        const right = (b.row as Record<string, unknown>)[column] ?? null;
        if (left === right) continue;
        if (left === null) return 1;
        if (right === null) return -1;
        const compared = left === right ? 0 : left > right ? 1 : -1;
        if (compared !== 0) return direction === 'desc' ? -compared : compared;
      }
      return a.index - b.index;
    })
    .map((entry) => entry.row);
}

/**
 * Builds the PostgREST `select` string for an `include`, e.g.
 * `{ findings: true }` -> `*,findings(*)` and
 * `{ findings: { orderBy: [{ severity: 'desc' }] } }` ->
 * `*,findings(*,order=severity.desc)`.
 *
 * A nested `where` cannot be expressed here (PostgREST embeds are unfiltered),
 * so those relations are resolved by `attachRelations` instead.
 */
function includeSelect(table: TableName, include?: Record<string, unknown>): string {
  if (!include || Object.keys(include).length === 0) return '*';

  const embedded: string[] = [];
  for (const [relation, spec] of Object.entries(include)) {
    const meta = RELATIONS[relation];
    if (!meta) throw new Error(`Unknown relation "${relation}" on ${table}`);

    const options = (spec ?? {}) as {
      select?: Record<string, boolean>;
      orderBy?: FindArgs['orderBy'];
      where?: Where;
    };

    // InsForge's select parser rejects modifiers such as `order=` inside an
    // embedded resource, so nested ordering is applied by attachRelations()
    // instead, which orders the children it fetches.
    embedded.push(`${relation}(${selectList(meta.table, options.select)})`);
  }

  return ['*', ...embedded].join(',');
}

/**
 * Embedded relations arrive in a single select, where InsForge cannot express
 * `orderBy`. Every child is already in memory here, so sort them before the
 * columns are renamed to camelCase.
 */
function sortEmbedded(table: TableName, row: Row, include?: Record<string, unknown>): void {
  if (!include) return;
  for (const [relation, spec] of Object.entries(include)) {
    const meta = RELATIONS[relation];
    if (!meta) continue;
    const children = row[relation];
    if (!Array.isArray(children)) continue;
    const options = (spec ?? {}) as { orderBy?: FindArgs['orderBy'] };
    row[relation] = sortRows(children as Row[], orderArgs(meta.table, options.orderBy));
  }
}

/** Relations whose `where` forces a second round trip. */
function filteredRelations(include?: Record<string, unknown>): string[] {
  if (!include) return [];
  return Object.entries(include)
    .filter(([, spec]) => {
      const where = spec && typeof spec === 'object' ? (spec as { where?: Where }).where : undefined;
      return Boolean(where && Object.keys(where).length > 0);
    })
    .map(([relation]) => relation);
}

function applyOrder(builder: any, table: TableName, orderBy: FindArgs['orderBy']): any {
  // A second `.order()` call replaces the first, so only the primary key can be
  // pushed to Postgres. That matters because this runs before applyRange().
  const [primary] = orderArgs(table, orderBy);
  if (!primary) return builder;
  const [column, direction] = primary;
  return builder.order(column, { ascending: direction === 'asc' });
}

function applyRange(builder: any, table: TableName, take?: number, skip?: number, ordered = false): any {
  const from = skip ?? 0;
  if (take === undefined && from === 0) return builder;
  // InsForge rejects a range that has no explicit order, so fall back to the
  // primary key. A second `.order()` would replace the caller's, hence the flag.
  if (!ordered) builder = builder.order(toColumn(table, 'id'), { ascending: true });
  const to = take === undefined ? from : from + take - 1;
  return builder.range(from, to);
}

function unwrap<T>(result: any): T {
  if (result?.error) {
    const message = typeof result.error === 'string' ? result.error : result.error.message;
    throw new Error(`InsForge query failed: ${message}`);
  }
  return (result?.data ?? null) as T;
}

/* ------------------------------------------------------------------ *
 * relation stitching
 * ------------------------------------------------------------------ */

/** Embedded children arrive in snake_case, so map them like top-level rows. */
function normaliseEmbedded(table: TableName, row: Row): Row {
  for (const relation of Object.keys(row)) {
    const meta = RELATIONS[relation];
    if (!meta) continue;
    const children = row[relation];
    if (Array.isArray(children)) {
      row[relation] = children.map((child) => toFields(meta.table, child as Row));
    }
  }
  return row;
}

/**
 * PostgREST cannot filter an embedded resource from the parent `select`, so a
 * filtered include is resolved with a second query and stitched in JS.
 */
async function attachRelations(
  table: TableName,
  rows: Row[],
  include: Record<string, unknown> | undefined,
  relations: string[]
): Promise<Row[]> {
  if (relations.length === 0 || rows.length === 0) return rows;

  const ownerColumn = toColumn(table, 'id');

  for (const relation of relations) {
    const meta = RELATIONS[relation];
    if (!meta) continue;

    const options = (include?.[relation] ?? {}) as {
      select?: Record<string, boolean>;
      where?: Where;
      orderBy?: FindArgs['orderBy'];
    };

    const ids = rows
      .map((row) => row[ownerColumn])
      .filter((id): id is string => typeof id === 'string');
    if (ids.length === 0) continue;

    let builder = getAdmin()
      .database.from(meta.table)
      .select(selectList(meta.table, options.select))
      .in(meta.foreignKey, ids);
    builder = applyFilters(builder, meta.table, options.where);
    builder = applyOrder(builder, meta.table, options.orderBy);

    const child = unwrap<Row[]>(await builder) ?? [];

    // Ordering is finished here rather than in the select: InsForge's parser
    // rejects modifiers inside an embedded resource, and every child of every
    // parent is fetched here, so a stable multi-key sort is still correct.
    const ordered = sortRows(child, orderArgs(meta.table, options.orderBy));

    for (const row of rows) {
      const parentId = row[ownerColumn];
      const matches = ordered.filter((entry) => entry[meta.foreignKey] === parentId);
      row[relation] = toRows(meta.table, matches);
    }
  }

  return rows;
}

/* ------------------------------------------------------------------ *
 * repositories
 * ------------------------------------------------------------------ */

/**
 * A Prisma-shaped repository. `R` declares which relations can be `include`d;
 * including one narrows the result to `T & Pick<R, K>` so the call sites keep
 * the precise types they had under Prisma.
 */
export interface Repository<T = Row, R extends Record<string, unknown> = Record<string, unknown>> {
  findMany<K extends keyof R = never>(args?: FindArgs<Extract<keyof R, string>> & { include?: { [P in K]?: IncludeSpec } }): Promise<Array<T & Pick<R, K>>>;
  findUnique<K extends keyof R = never>(args: { where: Where; include?: { [P in K]?: IncludeSpec }; select?: Record<string, boolean> }): Promise<(T & Pick<R, K>) | null>;
  findFirst<K extends keyof R = never>(args?: FindArgs<Extract<keyof R, string>> & { include?: { [P in K]?: IncludeSpec } }): Promise<(T & Pick<R, K>) | null>;
  create(args: { data: Where; select?: Record<string, boolean> }): Promise<T>;
  createMany(args: { data: Where[] }): Promise<{ count: number }>;
  update(args: { where: Where; data: Where; select?: Record<string, boolean> }): Promise<T | null>;
  updateMany(args: { where: Where; data: Where }): Promise<{ count: number }>;
  upsert(args: { where: Where; create: Where; update: Where }): Promise<T>;
  delete(args: { where: Where }): Promise<T | null>;
  deleteMany(args: { where: Where }): Promise<{ count: number }>;
  count(args?: { where?: Where }): Promise<number>;
}

export interface GroupCountRow {
  [key: string]: string | number | null;
  _count: number;
}

export interface GroupByArgs {
  by: string[];
  where?: Where;
  _count?: boolean;
}

export type Groupable = {
  groupBy(args: GroupByArgs): Promise<GroupCountRow[]>;
};

function createRepository<T, R extends Record<string, unknown> = Record<string, unknown>>(
  name: string
): Repository<T, R> {
  const table = resolveTable(name);

  const repo: Record<string, (...args: any[]) => any> = {
    async findMany(args: FindArgs = {}): Promise<Row[]> {
      const deferred = filteredRelations(args.include);
      const select = includeSelect(table, args.include);

      let builder = getAdmin().database.from(table).select(select);
      builder = applyFilters(builder, table, args.where);
      const ordered = applyOrder(builder, table, args.orderBy) !== builder;
      builder = applyRange(builder, table, args.take, args.skip, ordered);

      let rows = unwrap<Row[]>(await builder) ?? [];

      // Relations resolved in a second pass must not also be embedded.
      for (const row of rows) {
        for (const relation of deferred) delete row[relation];
        sortEmbedded(table, row, args.include);
        normaliseEmbedded(table, row);
      }

      rows = await attachRelations(table, rows, args.include, deferred);
      return rows.map((row) => toFields(table, row) as Row);
    },

    async findUnique(args: { where: Where; include?: Record<string, IncludeSpec>; select?: Record<string, boolean> }): Promise<Row | null> {
      const results = await this.findMany({ ...args, take: 1 });
      return results[0] ?? null;
    },

    async findFirst(args: FindArgs = {}): Promise<Row | null> {
      const results = await this.findMany({ ...args, take: 1 });
      return results[0] ?? null;
    },

    async create(args: { data: Where; select?: Record<string, boolean> }): Promise<Row> {
      const payload = toColumns(table, args.data);
      const rows = unwrap<Row[]>(
        await getAdmin().database.from(table).insert([payload]).select(selectList(table, args.select))
      );
      if (!rows?.length) throw new Error(`Insert into ${table} returned no rows`);
      return toFields(table, rows[0]) as Row;
    },

    async createMany(args: { data: Where[] }): Promise<{ count: number }> {
      const payload = args.data.map((row) => toColumns(table, row));
      if (payload.length === 0) return { count: 0 };
      unwrap(await getAdmin().database.from(table).insert(payload));
      return { count: payload.length };
    },

    async update(args): Promise<Row | null> {
      const payload = toColumns(table, args.data);
      let builder = getAdmin().database.from(table).update(payload).select(selectList(table, args.select));
      builder = applyFilters(builder, table, args.where);
      builder = applyRange(builder, table, 1);
      const rows = unwrap<Row[]>(await builder);
      return rows?.[0] ? (toFields(table, rows[0]) as Row) : null;
    },

    async updateMany(args): Promise<{ count: number }> {
      const payload = toColumns(table, args.data);
      let builder = getAdmin().database.from(table).update(payload).select('id');
      builder = applyFilters(builder, table, args.where);
      const rows = unwrap<Row[]>(await builder);
      return { count: rows?.length ?? 0 };
    },

    async upsert(args): Promise<Row> {
      // settings is keyed on user_id rather than a surrogate id.
      const uniqueColumn = table === 'settings' || table === 'github_repositories'
        ? toColumn(table, Object.keys(args.where)[0])
        : 'id';
      const conflictValue = args.where[Object.keys(args.where)[0]];

      const payload = {
        ...toColumns(table, args.create),
        ...toColumns(table, args.update)
      };
      (payload as Row)[uniqueColumn] = conflictValue;

      const rows = unwrap<Row[]>(
        await getAdmin()
          .database.from(table)
          .upsert([payload], { onConflict: uniqueColumn })
          .select('*')
      );
      if (!rows?.length) throw new Error(`Upsert into ${table} returned no rows`);
      return toFields(table, rows[0]) as Row;
    },

    async delete(args): Promise<Row | null> {
      const results = await this.findMany({ where: args.where, take: 1 });
      if (results.length === 0) return null;

      const idColumn = toColumn(table, 'id');
      const idValue = (results[0] as Row)[idColumn];

      let builder: any = getAdmin().database.from(table).delete().select('*');
      if (idValue !== undefined) {
        builder = builder.eq(idColumn, idValue as string);
      } else {
        builder = applyFilters(builder, table, args.where);
      }
      const rows = unwrap<Row[]>(await builder);
      return rows?.[0] ? (toFields(table, rows[0]) as Row) : null;
    },

    async deleteMany(args): Promise<{ count: number }> {
      const matched = await this.findMany({ where: args.where, select: { id: true } });
      if (matched.length === 0) return { count: 0 };

      const idColumn = toColumn(table, 'id');
      const ids = matched.map((row: Row) => row[idColumn]);

      let builder: any = getAdmin().database.from(table).delete().select('id');
      builder = idColumn === 'id' ? builder.in(idColumn, ids) : applyFilters(builder, table, args.where);
      const rows = unwrap<Row[]>(await builder);
      return { count: rows?.length ?? 0 };
    },

    async count(args: { where?: Where } = {}): Promise<number> {
      let builder = getAdmin().database.from(table).select('*', { count: 'exact', head: true });
      builder = applyFilters(builder, table, args.where);
      const result = await builder;
      if (result.error) {
        throw new Error(`InsForge count failed: ${result.error.message}`);
      }
      return result.count ?? 0;
    }
  };

  return repo as unknown as Repository<T, R>;
}

/* ------------------------------------------------------------------ *
 * groupBy -> RPC aggregates
 * ------------------------------------------------------------------ */

const GROUP_BY_RPC: Record<string, { rpc: string; key: string }> = {
  scan: { rpc: 'scan_stats', key: 'type' },
  job: { rpc: 'job_stats', key: 'type' },
  logEntry: { rpc: 'log_services', key: 'service' }
};

async function groupBy(name: string, args: GroupByArgs): Promise<GroupCountRow[]> {
  const table = resolveTable(name);
  const meta = GROUP_BY_RPC[name];
  if (!meta) {
    throw new Error(`groupBy is not supported for "${name}"`);
  }

  const where = args.where ?? {};
  const by = args.by[0];

  // logEntry groups by service within one log file, not by user.
  if (name === 'logEntry') {
    const logFileId = where.logFileId as string;
    const services = unwrap<string[]>(
      await getAdmin().database.rpc(meta.rpc, { p_log_file_id: logFileId })
    ) ?? [];
    return services.map((service) => ({ service, _count: 1 })) as GroupCountRow[];
  }

  const userId = where.userId as string;
  if (!userId) {
    throw new Error(`groupBy on "${name}" requires a userId filter`);
  }

  const stats = unwrap<Record<string, unknown>>(
    await getAdmin().database.rpc(meta.rpc, { p_user_id: userId })
  ) ?? {};

  const groups = (stats[by === 'type' ? 'by_type' : 'by_status'] as Array<Record<string, unknown>>) ?? [];
  return groups.map((group) => ({
    [by]: group[by],
    _count: Number(group.count ?? 0)
  })) as GroupCountRow[];
}

/* ------------------------------------------------------------------ *
 * facade
 * ------------------------------------------------------------------ */

export interface Database {
  user: Repository<User, { settings: Settings }>;
  settings: Repository<Settings>;
  scan: Repository<Scan, { findings: Finding[] }> & Groupable;
  finding: Repository<Finding, { scan: Scan }>;
  job: Repository<Job> & Groupable;
  logFile: Repository<LogFile, { entries: LogEntry[] }>;
  logEntry: Repository<LogEntry> & Groupable;
  gitHubRepository: Repository<GitHubRepository, { scans: GitHubScan[] }>;
  githubScan: Repository<GitHubScan>;
  notification: Repository<Notification>;
  apiKey: Repository<ApiKey>;
  auditLog: Repository<AuditLog>;
}

function withGroupBy<T, R extends Record<string, unknown>>(name: string): Repository<T, R> & Groupable {
  return Object.assign(createRepository<T, R>(name), {
    groupBy: (args: GroupByArgs) => groupBy(name, args)
  });
}

export function createDatabase(): Database {
  return {
    user: createUserRepository(),
    settings: createRepository('settings'),
    scan: withGroupBy('scan'),
    finding: createRepository('finding'),
    job: withGroupBy('job'),
    logFile: createRepository('logFile'),
    logEntry: withGroupBy('logEntry'),
    gitHubRepository: createRepository('gitHubRepository'),
    githubScan: createRepository('githubScan'),
    notification: createRepository('notification'),
    apiKey: createRepository('apiKey'),
    auditLog: createRepository('auditLog')
  };
}

/**
 * `user` is a special case: identity lives in auth.users, which the data API
 * cannot read, so reads go through public.get_user() and writes go to
 * public.profiles. The returned row keeps the camelCase User shape the routes
 * and the frontend already expect, including `email`.
 */
function createUserRepository(): Database['user'] {
  const base = createRepository<User, { settings: Settings }>('user');
  const settingsRepo = createRepository<Settings>('settings');

  const readViaRpc = async (id: string): Promise<Row | null> => {
    const row = unwrap<Row | null>(await getAdmin().database.rpc('get_user', { p_user_id: id }));
    return row ?? null;
  };

  const project = (row: Row | null, select?: Record<string, boolean>): Row | null => {
    if (!row) return null;
    if (!select) return row;
    const out: Row = {};
    for (const [field, wanted] of Object.entries(select)) {
      if (wanted && field in row) out[field] = row[field];
    }
    return out;
  };

  const withIncludes = async (row: Row | null, include?: Record<string, unknown>): Promise<Row | null> => {
    if (!row || !include?.settings) return row;
    const settings = await settingsRepo.findFirst({ where: { userId: row.id as string } });
    return { ...row, settings: settings ?? null };
  };

  const idFrom = (where?: Where): string | undefined => (where?.id ?? where?.userId) as string | undefined;

  const findMany = async (args: FindArgs = {}): Promise<Row[]> => {
    const id = idFrom(args.where);
    if (!id) return [];
    const row = await withIncludes(await readViaRpc(id), args.include);
    const projected = project(row, args.select);
    return projected ? [projected] : [];
  };

  const findUnique = async (args: {
    where: Where;
    include?: Record<string, IncludeSpec>;
    select?: Record<string, boolean>;
  }): Promise<Row | null> => {
    const id = idFrom(args.where);
    if (!id) return null;
    return project(await withIncludes(await readViaRpc(id), args.include), args.select);
  };

  const update = async (args: {
    where: Where;
    data: Where;
    select?: Record<string, boolean>;
  }): Promise<Row | null> => {
    const id = idFrom(args.where);
    if (!id) throw new Error('user.update requires an id');
    await base.update({ where: { id }, data: args.data });
    return project(await readViaRpc(id), args.select);
  };

  return {
    ...base,

    findMany,

    findUnique,

    async findFirst(args: FindArgs = {}) {
      const results = await findMany({ ...args, take: 1 });
      return results[0] ?? null;
    },

    async create() {
      // The auth user is created by InsForge auth; the profile row is provisioned
      // by public.ensure_profile(), so there is nothing to insert here.
      throw new Error('Users are created through InsForge auth, not the data layer');
    },

    update,

    async delete() {
      throw new Error('Users are deleted through InsForge auth, not the data layer');
    },

    async count() {
      return 1;
    },

    groupBy: async () => {
      throw new Error('groupBy is not supported for "user"');
    }
  } as unknown as Database['user'];
}

export const db: Database = createDatabase();
