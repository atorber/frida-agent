import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import initSqlJs from 'sql.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const dataDir = path.resolve(__dirname, '../data')
const dbPath = process.env.APPS_DB_PATH || path.join(dataDir, 'apps.db')

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true })
}

let rawDb
let inTx = false
let dirty = false

function persist(force = false) {
  if (inTx && !force) {
    dirty = true
    return
  }
  const data = rawDb.export()
  fs.writeFileSync(dbPath, Buffer.from(data))
  dirty = false
}

function rowsFrom(stmt) {
  const cols = stmt.getColumnNames()
  const out = []
  while (stmt.step()) {
    const values = stmt.get()
    const row = {}
    cols.forEach((c, i) => {
      row[c] = values[i]
    })
    out.push(row)
  }
  stmt.free()
  return out
}

function tableColumns(table) {
  try {
    return rawDb.exec(`PRAGMA table_info(${table})`)[0]?.values?.map((r) => r[1]) || []
  } catch {
    return []
  }
}

function ensureColumn(table, column, ddl) {
  const cols = tableColumns(table)
  if (!cols.includes(column)) {
    rawDb.run(`ALTER TABLE ${table} ADD COLUMN ${ddl}`)
  }
}

/** 简易封装：all / get / run */
export const db = {
  prepare(sql) {
    return {
      all(...params) {
        const stmt = rawDb.prepare(sql)
        if (params.length) stmt.bind(params)
        return rowsFrom(stmt)
      },
      get(...params) {
        const stmt = rawDb.prepare(sql)
        if (params.length) stmt.bind(params)
        const rows = rowsFrom(stmt)
        return rows[0]
      },
      run(...params) {
        rawDb.run(sql, params)
        const changes = rawDb.getRowsModified()
        persist()
        return { changes }
      },
    }
  },
  exec(sql) {
    rawDb.run(sql)
    persist()
  },
  transaction(fn) {
    return (...args) => {
      inTx = true
      rawDb.run('BEGIN')
      try {
        const result = fn(...args)
        rawDb.run('COMMIT')
        inTx = false
        if (dirty) persist(true)
        return result
      } catch (e) {
        try {
          rawDb.run('ROLLBACK')
        } catch {
          /* ignore */
        }
        inTx = false
        dirty = false
        throw e
      }
    }
  },
}

export async function initDb() {
  const SQL = await initSqlJs()
  if (fs.existsSync(dbPath)) {
    const buf = fs.readFileSync(dbPath)
    rawDb = new SQL.Database(new Uint8Array(buf))
  } else {
    rawDb = new SQL.Database()
  }

  rawDb.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      talker TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER,
      pinned INTEGER DEFAULT 0,
      tags TEXT DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_notes_talker ON notes(talker);

    CREATE TABLE IF NOT EXISTS assistant_messages (
      id TEXT PRIMARY KEY,
      talker TEXT NOT NULL,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_assistant_talker ON assistant_messages(talker);

    CREATE TABLE IF NOT EXISTS assistant_analysis (
      talker TEXT PRIMARY KEY,
      fingerprint TEXT NOT NULL,
      insights_json TEXT NOT NULL,
      suggestions_json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS toolkit_runs (
      id TEXT PRIMARY KEY,
      talker TEXT NOT NULL,
      tool_id TEXT NOT NULL,
      result TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_toolkit_talker ON toolkit_runs(talker);
  `)

  ensureColumn('notes', 'updated_at', 'updated_at INTEGER')
  ensureColumn('notes', 'pinned', 'pinned INTEGER DEFAULT 0')
  ensureColumn('notes', 'tags', "tags TEXT DEFAULT '[]'")

  persist(true)
  return db
}

export function ok(data, msg = 'ok') {
  return { code: 1, data, msg }
}

export function fail(msg, code = 0) {
  return { code, data: null, msg }
}

export function newId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
}

export function fingerprint(text) {
  const s = String(text || '')
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return (h >>> 0).toString(16) + '_' + s.length
}
