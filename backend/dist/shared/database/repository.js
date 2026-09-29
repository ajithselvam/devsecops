"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = void 0;
exports.createDatabase = createDatabase;
const insforge_1 = require("./insforge");
const mapper_1 = require("./mapper");
const RELATIONS = {
    findings: { table: 'findings', foreignKey: 'scan_id' },
    entries: { table: 'log_entries', foreignKey: 'log_file_id' },
    scan: { table: 'scans', foreignKey: 'id' },
    repos: { table: 'github_repositories', foreignKey: 'id' },
    repo: { table: 'github_repositories', foreignKey: 'id' },
    settings: { table: 'settings', foreignKey: 'user_id' }
};
const TABLE_ALIASES = {
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
function resolveTable(name) {
    const table = TABLE_ALIASES[name] ?? name;
    if (!mapper_1.TABLE_COLUMNS[table]) {
        throw new Error(`Unknown table "${name}"`);
    }
    return table;
}
/* ------------------------------------------------------------------ *
 * where -> PostgREST filters
 * ------------------------------------------------------------------ */
const UNSUPPORTED = new Set(['AND', 'NOT']);
function applyFilters(builder, table, where) {
    if (!where)
        return builder;
    for (const [field, condition] of Object.entries(where)) {
        if (condition === undefined)
            continue;
        if (field === 'OR') {
            const clauses = condition.map((clause) => orClause(table, clause));
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
        const column = (0, mapper_1.toColumn)(table, field);
        if (condition === null) {
            builder = builder.is(column, null);
        }
        else if (typeof condition !== 'object') {
            builder = builder.eq(column, condition);
        }
        else {
            const spec = condition;
            if (Array.isArray(spec.in)) {
                builder = builder.in(column, spec.in);
            }
            else if (typeof spec.contains === 'string') {
                const pattern = `%${spec.contains}%`;
                builder = spec.mode === 'insensitive' ? builder.ilike(column, pattern) : builder.like(column, pattern);
            }
            else if (spec.not === null) {
                builder = builder.not.is(column, null);
            }
            else if ('equals' in spec) {
                builder = builder.eq(column, spec.equals);
            }
            else {
                throw new Error(`Unsupported filter on "${field}": ${JSON.stringify(spec)}`);
            }
        }
    }
    return builder;
}
function orClause(table, clause) {
    const parts = [];
    for (const [field, condition] of Object.entries(clause)) {
        const column = (0, mapper_1.toColumn)(table, field);
        if (condition === null) {
            parts.push(`${column}.is.null`);
        }
        else if (typeof condition !== 'object') {
            parts.push(`${column}.eq.${condition}`);
        }
        else {
            const spec = condition;
            if (typeof spec.contains === 'string') {
                parts.push(`${column}.ilike.*${spec.contains}*`);
            }
            else if ('equals' in spec) {
                parts.push(`${column}.eq.${spec.equals}`);
            }
            else {
                throw new Error(`Unsupported OR filter on "${field}"`);
            }
        }
    }
    return parts.join('and');
}
/* ------------------------------------------------------------------ *
 * select / include
 * ------------------------------------------------------------------ */
function selectList(table, select) {
    const fields = Object.entries(select ?? {})
        .filter(([, wanted]) => wanted)
        .map(([field]) => (0, mapper_1.toColumn)(table, field));
    return fields.length > 0 ? fields.join(',') : '*';
}
/** Returns [column, direction] pairs, keeping the caller's requested direction. */
function orderArgs(table, orderBy) {
    if (!orderBy)
        return [];
    const groups = Array.isArray(orderBy) ? orderBy : [orderBy];
    return groups.flatMap((group) => Object.entries(group).map(([field, direction]) => [(0, mapper_1.toColumn)(table, field), direction === 'desc' ? 'desc' : 'asc']));
}
/** Stable multi-key sort; the SDK's `.order()` can only express one key. */
function sortRows(rows, order) {
    if (order.length === 0)
        return rows;
    return rows
        .map((row, index) => ({ row, index }))
        .sort((a, b) => {
        for (const [column, direction] of order) {
            const left = a.row[column] ?? null;
            const right = b.row[column] ?? null;
            if (left === right)
                continue;
            if (left === null)
                return 1;
            if (right === null)
                return -1;
            const compared = left === right ? 0 : left > right ? 1 : -1;
            if (compared !== 0)
                return direction === 'desc' ? -compared : compared;
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
function includeSelect(table, include) {
    if (!include || Object.keys(include).length === 0)
        return '*';
    const embedded = [];
    for (const [relation, spec] of Object.entries(include)) {
        const meta = RELATIONS[relation];
        if (!meta)
            throw new Error(`Unknown relation "${relation}" on ${table}`);
        const options = (spec ?? {});
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
function sortEmbedded(table, row, include) {
    if (!include)
        return;
    for (const [relation, spec] of Object.entries(include)) {
        const meta = RELATIONS[relation];
        if (!meta)
            continue;
        const children = row[relation];
        if (!Array.isArray(children))
            continue;
        const options = (spec ?? {});
        row[relation] = sortRows(children, orderArgs(meta.table, options.orderBy));
    }
}
/** Relations whose `where` forces a second round trip. */
function filteredRelations(include) {
    if (!include)
        return [];
    return Object.entries(include)
        .filter(([, spec]) => {
        const where = spec && typeof spec === 'object' ? spec.where : undefined;
        return Boolean(where && Object.keys(where).length > 0);
    })
        .map(([relation]) => relation);
}
function applyOrder(builder, table, orderBy) {
    // A second `.order()` call replaces the first, so only the primary key can be
    // pushed to Postgres. That matters because this runs before applyRange().
    const [primary] = orderArgs(table, orderBy);
    if (!primary)
        return builder;
    const [column, direction] = primary;
    return builder.order(column, { ascending: direction === 'asc' });
}
function applyRange(builder, table, take, skip, ordered = false) {
    const from = skip ?? 0;
    if (take === undefined && from === 0)
        return builder;
    // InsForge rejects a range that has no explicit order, so fall back to the
    // primary key. A second `.order()` would replace the caller's, hence the flag.
    if (!ordered)
        builder = builder.order((0, mapper_1.toColumn)(table, 'id'), { ascending: true });
    const to = take === undefined ? from : from + take - 1;
    return builder.range(from, to);
}
function unwrap(result) {
    if (result?.error) {
        const message = typeof result.error === 'string' ? result.error : result.error.message;
        throw new Error(`InsForge query failed: ${message}`);
    }
    return (result?.data ?? null);
}
/* ------------------------------------------------------------------ *
 * relation stitching
 * ------------------------------------------------------------------ */
/** Embedded children arrive in snake_case, so map them like top-level rows. */
function normaliseEmbedded(table, row) {
    for (const relation of Object.keys(row)) {
        const meta = RELATIONS[relation];
        if (!meta)
            continue;
        const children = row[relation];
        if (Array.isArray(children)) {
            row[relation] = children.map((child) => (0, mapper_1.toFields)(meta.table, child));
        }
    }
    return row;
}
/**
 * PostgREST cannot filter an embedded resource from the parent `select`, so a
 * filtered include is resolved with a second query and stitched in JS.
 */
async function attachRelations(table, rows, include, relations) {
    if (relations.length === 0 || rows.length === 0)
        return rows;
    const ownerColumn = (0, mapper_1.toColumn)(table, 'id');
    for (const relation of relations) {
        const meta = RELATIONS[relation];
        if (!meta)
            continue;
        const options = (include?.[relation] ?? {});
        const ids = rows
            .map((row) => row[ownerColumn])
            .filter((id) => typeof id === 'string');
        if (ids.length === 0)
            continue;
        let builder = (0, insforge_1.getAdmin)()
            .database.from(meta.table)
            .select(selectList(meta.table, options.select))
            .in(meta.foreignKey, ids);
        builder = applyFilters(builder, meta.table, options.where);
        builder = applyOrder(builder, meta.table, options.orderBy);
        const child = unwrap(await builder) ?? [];
        // Ordering is finished here rather than in the select: InsForge's parser
        // rejects modifiers inside an embedded resource, and every child of every
        // parent is fetched here, so a stable multi-key sort is still correct.
        const ordered = sortRows(child, orderArgs(meta.table, options.orderBy));
        for (const row of rows) {
            const parentId = row[ownerColumn];
            const matches = ordered.filter((entry) => entry[meta.foreignKey] === parentId);
            row[relation] = (0, mapper_1.toRows)(meta.table, matches);
        }
    }
    return rows;
}
function createRepository(name) {
    const table = resolveTable(name);
    const repo = {
        async findMany(args = {}) {
            const deferred = filteredRelations(args.include);
            const select = includeSelect(table, args.include);
            let builder = (0, insforge_1.getAdmin)().database.from(table).select(select);
            builder = applyFilters(builder, table, args.where);
            const ordered = applyOrder(builder, table, args.orderBy) !== builder;
            builder = applyRange(builder, table, args.take, args.skip, ordered);
            let rows = unwrap(await builder) ?? [];
            // Relations resolved in a second pass must not also be embedded.
            for (const row of rows) {
                for (const relation of deferred)
                    delete row[relation];
                sortEmbedded(table, row, args.include);
                normaliseEmbedded(table, row);
            }
            rows = await attachRelations(table, rows, args.include, deferred);
            return rows.map((row) => (0, mapper_1.toFields)(table, row));
        },
        async findUnique(args) {
            const results = await this.findMany({ ...args, take: 1 });
            return results[0] ?? null;
        },
        async findFirst(args = {}) {
            const results = await this.findMany({ ...args, take: 1 });
            return results[0] ?? null;
        },
        async create(args) {
            const payload = (0, mapper_1.toColumns)(table, args.data);
            const rows = unwrap(await (0, insforge_1.getAdmin)().database.from(table).insert([payload]).select(selectList(table, args.select)));
            if (!rows?.length)
                throw new Error(`Insert into ${table} returned no rows`);
            return (0, mapper_1.toFields)(table, rows[0]);
        },
        async createMany(args) {
            const payload = args.data.map((row) => (0, mapper_1.toColumns)(table, row));
            if (payload.length === 0)
                return { count: 0 };
            unwrap(await (0, insforge_1.getAdmin)().database.from(table).insert(payload));
            return { count: payload.length };
        },
        async update(args) {
            const payload = (0, mapper_1.toColumns)(table, args.data);
            let builder = (0, insforge_1.getAdmin)().database.from(table).update(payload).select(selectList(table, args.select));
            builder = applyFilters(builder, table, args.where);
            builder = applyRange(builder, table, 1);
            const rows = unwrap(await builder);
            return rows?.[0] ? (0, mapper_1.toFields)(table, rows[0]) : null;
        },
        async updateMany(args) {
            const payload = (0, mapper_1.toColumns)(table, args.data);
            let builder = (0, insforge_1.getAdmin)().database.from(table).update(payload).select('id');
            builder = applyFilters(builder, table, args.where);
            const rows = unwrap(await builder);
            return { count: rows?.length ?? 0 };
        },
        async upsert(args) {
            // settings is keyed on user_id rather than a surrogate id.
            const uniqueColumn = table === 'settings' || table === 'github_repositories'
                ? (0, mapper_1.toColumn)(table, Object.keys(args.where)[0])
                : 'id';
            const conflictValue = args.where[Object.keys(args.where)[0]];
            const payload = {
                ...(0, mapper_1.toColumns)(table, args.create),
                ...(0, mapper_1.toColumns)(table, args.update)
            };
            payload[uniqueColumn] = conflictValue;
            const rows = unwrap(await (0, insforge_1.getAdmin)()
                .database.from(table)
                .upsert([payload], { onConflict: uniqueColumn })
                .select('*'));
            if (!rows?.length)
                throw new Error(`Upsert into ${table} returned no rows`);
            return (0, mapper_1.toFields)(table, rows[0]);
        },
        async delete(args) {
            const results = await this.findMany({ where: args.where, take: 1 });
            if (results.length === 0)
                return null;
            const idColumn = (0, mapper_1.toColumn)(table, 'id');
            const idValue = results[0][idColumn];
            let builder = (0, insforge_1.getAdmin)().database.from(table).delete().select('*');
            if (idValue !== undefined) {
                builder = builder.eq(idColumn, idValue);
            }
            else {
                builder = applyFilters(builder, table, args.where);
            }
            const rows = unwrap(await builder);
            return rows?.[0] ? (0, mapper_1.toFields)(table, rows[0]) : null;
        },
        async deleteMany(args) {
            const matched = await this.findMany({ where: args.where, select: { id: true } });
            if (matched.length === 0)
                return { count: 0 };
            const idColumn = (0, mapper_1.toColumn)(table, 'id');
            const ids = matched.map((row) => row[idColumn]);
            let builder = (0, insforge_1.getAdmin)().database.from(table).delete().select('id');
            builder = idColumn === 'id' ? builder.in(idColumn, ids) : applyFilters(builder, table, args.where);
            const rows = unwrap(await builder);
            return { count: rows?.length ?? 0 };
        },
        async count(args = {}) {
            let builder = (0, insforge_1.getAdmin)().database.from(table).select('*', { count: 'exact', head: true });
            builder = applyFilters(builder, table, args.where);
            const result = await builder;
            if (result.error) {
                throw new Error(`InsForge count failed: ${result.error.message}`);
            }
            return result.count ?? 0;
        }
    };
    return repo;
}
/* ------------------------------------------------------------------ *
 * groupBy -> RPC aggregates
 * ------------------------------------------------------------------ */
const GROUP_BY_RPC = {
    scan: { rpc: 'scan_stats', key: 'type' },
    job: { rpc: 'job_stats', key: 'type' },
    logEntry: { rpc: 'log_services', key: 'service' }
};
async function groupBy(name, args) {
    const table = resolveTable(name);
    const meta = GROUP_BY_RPC[name];
    if (!meta) {
        throw new Error(`groupBy is not supported for "${name}"`);
    }
    const where = args.where ?? {};
    const by = args.by[0];
    // logEntry groups by service within one log file, not by user.
    if (name === 'logEntry') {
        const logFileId = where.logFileId;
        const services = unwrap(await (0, insforge_1.getAdmin)().database.rpc(meta.rpc, { p_log_file_id: logFileId })) ?? [];
        return services.map((service) => ({ service, _count: 1 }));
    }
    const userId = where.userId;
    if (!userId) {
        throw new Error(`groupBy on "${name}" requires a userId filter`);
    }
    const stats = unwrap(await (0, insforge_1.getAdmin)().database.rpc(meta.rpc, { p_user_id: userId })) ?? {};
    const groups = stats[by === 'type' ? 'by_type' : 'by_status'] ?? [];
    return groups.map((group) => ({
        [by]: group[by],
        _count: Number(group.count ?? 0)
    }));
}
function withGroupBy(name) {
    return Object.assign(createRepository(name), {
        groupBy: (args) => groupBy(name, args)
    });
}
function createDatabase() {
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
function createUserRepository() {
    const base = createRepository('user');
    const settingsRepo = createRepository('settings');
    const readViaRpc = async (id) => {
        const row = unwrap(await (0, insforge_1.getAdmin)().database.rpc('get_user', { p_user_id: id }));
        return row ?? null;
    };
    const project = (row, select) => {
        if (!row)
            return null;
        if (!select)
            return row;
        const out = {};
        for (const [field, wanted] of Object.entries(select)) {
            if (wanted && field in row)
                out[field] = row[field];
        }
        return out;
    };
    const withIncludes = async (row, include) => {
        if (!row || !include?.settings)
            return row;
        const settings = await settingsRepo.findFirst({ where: { userId: row.id } });
        return { ...row, settings: settings ?? null };
    };
    const idFrom = (where) => (where?.id ?? where?.userId);
    const findMany = async (args = {}) => {
        const id = idFrom(args.where);
        if (!id)
            return [];
        const row = await withIncludes(await readViaRpc(id), args.include);
        const projected = project(row, args.select);
        return projected ? [projected] : [];
    };
    const findUnique = async (args) => {
        const id = idFrom(args.where);
        if (!id)
            return null;
        return project(await withIncludes(await readViaRpc(id), args.include), args.select);
    };
    const update = async (args) => {
        const id = idFrom(args.where);
        if (!id)
            throw new Error('user.update requires an id');
        await base.update({ where: { id }, data: args.data });
        return project(await readViaRpc(id), args.select);
    };
    return {
        ...base,
        findMany,
        findUnique,
        async findFirst(args = {}) {
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
    };
}
exports.db = createDatabase();
