const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

// SQLite 相关常量
const SQLITE_OK = 0;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_INTEGER = 1;
const SQLITE_FLOAT = 2;
const SQLITE_TEXT = 3;
const SQLITE_BLOB = 4;
const SQLITE_NULL = 5;

// 数据库偏移量
const OFFSET_DB_INSTANCE = 0x5A40598;
const OFFSET_DB_MICROMSG = 0xb8;
const OFFSET_DB_CHAT_MSG = 0x2c8;
const OFFSET_DB_MISC = 0x5f0;
const OFFSET_DB_EMOTION = 0x15f0;
const OFFSET_DB_MEDIA = 0xF48;
const OFFSET_DB_BIZCHAT_MSG = 0x1A70;
const OFFSET_DB_FUNCTION_MSG = 0x1b98;
const OFFSET_DB_NAME = 0x28;
const OFFSET_DB_MSG_MGR = 0x5ABB5D8;

// SQLite 函数偏移量
const SQLITE3_EXEC_OFFSET = 0x3AFBCE0;
const SQLITE3_PREPARE_OFFSET = 0x3B03990;
const SQLITE3_STEP_OFFSET = 0x3ABFCE0;
const SQLITE3_COLUMN_COUNT_OFFSET = 0x3AC0500;
const SQLITE3_COLUMN_NAME_OFFSET = 0x3AC0F00;
const SQLITE3_COLUMN_TYPE_OFFSET = 0x3AC0D50;
const SQLITE3_COLUMN_BLOB_OFFSET = 0x3AC0530;
const SQLITE3_COLUMN_BYTES_OFFSET = 0x3AC0620;
const SQLITE3_FINALIZE_OFFSET = 0x3ABED90;
const SQLITE3_COLUMN_BYTESTRING_OFFSET = 0x3AC0530;

// 数据库句柄映射
const dbMap = new Map<string, NativePointer>();

// 获取数据库句柄
export const getDbHandle = (base: NativePointer, offset: number) => {
    const dbNamePtr = base.add(offset + OFFSET_DB_NAME).readPointer();
    const dbName = dbNamePtr.readUtf16String(); // 使用 readUtf16String
    const dbHandle = base.add(offset).readPointer();
    if (dbName) {
        dbMap.set(dbName, dbHandle);
    }
}

// 获取消息数据库句柄
export const getMsgDbHandle = (msgMgrAddr: NativePointer) => {
    const dbIndex = msgMgrAddr.add(0x68).readU32();
    const pStart = msgMgrAddr.add(0x50).readPointer();

    for (let i = 0; i < dbIndex; i++) {
        const dbAddr = pStart.add(i * 0x08).readPointer();
        if (!dbAddr.isNull()) {
            // WCF: GET_WSTRING(dbAddr) = *(wchar_t**)dbAddr
            const dbNamePtr = dbAddr.readPointer();
            const dbName = dbNamePtr && !dbNamePtr.isNull() ? (dbNamePtr.readUtf16String() || '') : '';
            const dbHandle = dbAddr.add(0x78).readPointer();
            if (dbName) {
                dbMap.set(dbName, dbHandle);
            }

            // MediaMsgi.db
            const mmdbAddr = dbAddr.add(0x20).readPointer();
            if (mmdbAddr && !mmdbAddr.isNull()) {
                const mmdbNamePtr = mmdbAddr.add(0x78).readPointer();
                const mmdbName = mmdbNamePtr && !mmdbNamePtr.isNull() ? (mmdbNamePtr.readUtf16String() || '') : '';
                const mmdbHandle = mmdbAddr.add(0x50).readPointer();
                if (mmdbName) {
                    dbMap.set(mmdbName, mmdbHandle);
                }
            }
        }
    }
}

// 获取所有数据库句柄
export const getDbHandles = (): Map<string, NativePointer> => {
    dbMap.clear();

    const dbInstanceAddr = moduleBaseAddress.add(OFFSET_DB_INSTANCE).readPointer();

    getDbHandle(dbInstanceAddr, OFFSET_DB_MICROMSG);     // MicroMsg.db
    getDbHandle(dbInstanceAddr, OFFSET_DB_CHAT_MSG);     // ChatMsg.db
    getDbHandle(dbInstanceAddr, OFFSET_DB_MISC);         // Misc.db
    getDbHandle(dbInstanceAddr, OFFSET_DB_EMOTION);      // Emotion.db
    getDbHandle(dbInstanceAddr, OFFSET_DB_MEDIA);        // Media.db
    getDbHandle(dbInstanceAddr, OFFSET_DB_FUNCTION_MSG); // Function.db

    getMsgDbHandle(moduleBaseAddress.add(OFFSET_DB_MSG_MGR).readPointer()); // MSGi.db & MediaMsgi.db

    // console.log('dbMap:', dbMap)
    return dbMap;
}

// console.log('getDbHandles() res:\n', JSON.stringify(getDbHandles()))

// 获取数据库名称列表
export const getDbNames = (): string[] => {
    if (dbMap.size === 0) {
        getDbHandles();
    }
    const keys = dbMap.keys()

    // for (const key of keys) {
    //     console.log('key string:', key)
    // }
    return Array.from(keys);
}

// console.log('getDbNames() res:\n', JSON.stringify(getDbNames()))

// 获取数据库表结构
export const getDbTables = (db: string): Array<{ name: string, sql: string }> => {
    const tables: Array<{ name: string, sql: string }> = [];
    
    if (dbMap.size === 0) {
        getDbHandles();
    }

    const dbHandle = dbMap.get(db);
    if (!dbHandle) {
        return tables;
    }

    const sql = "select name, sql from sqlite_master where type=\"table\";";
    const sqlite3Exec = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_EXEC_OFFSET),
        'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']
    );

    const callback = new NativeCallback((ret: NativePointer, argc: number, argv: NativePointer, azColName: NativePointer) => {
        const table: { name: string, sql: string } = { name: '', sql: '' };
        
        for (let i = 0; i < argc; i++) {
            const colName = azColName.add(i * Process.pointerSize).readPointer().readUtf8String();
            const value = argv.add(i * Process.pointerSize).readPointer().readUtf8String();
            
            if (colName === 'name') {
                table.name = value || '';
            } else if (colName === 'sql') {
                table.sql = (value || '').replace(/\t/g, '');
            }
        }
        tables.push(table);
        return 0;
    }, 'int', ['pointer', 'int', 'pointer', 'pointer']);

    sqlite3Exec(dbHandle, Memory.allocUtf8String(sql), callback, ptr(0), ptr(0));

    return tables;
}

// console.log('getDbTables() res:\n', JSON.stringify(getDbTables('MicroMsg.db')))

// 执行 SQL 查询
export const execDbQuery = (db: string, sql: string): Array<{ [key: string]: Uint8Array | string }> => {
    const rowsObj: Array<{ [key: string]: Uint8Array | string }> = [];

    if (dbMap.size === 0) {
        getDbHandles();
    }

    const dbHandle = dbMap.get(db);
    if (!dbHandle) {
        return rowsObj;
    }

    const sqlite3Prepare = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_PREPARE_OFFSET),
        'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer']
    );
    const sqlite3Step = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_STEP_OFFSET),
        'int', ['pointer']
    );
    const sqlite3ColumnCount = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_COLUMN_COUNT_OFFSET),
        'int', ['pointer']
    );
    const sqlite3ColumnName = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_COLUMN_NAME_OFFSET),
        'pointer', ['pointer', 'int']
    );
    const sqlite3ColumnType = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_COLUMN_TYPE_OFFSET),
        'int', ['pointer', 'int']
    );
    const sqlite3ColumnBlob = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_COLUMN_BLOB_OFFSET),
        'pointer', ['pointer', 'int']
    );
    const sqlite3ColumnBytes = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_COLUMN_BYTES_OFFSET),
        'int', ['pointer', 'int']
    );
    const sqlite3Finalize = new NativeFunction(
        moduleBaseAddress.add(SQLITE3_FINALIZE_OFFSET),
        'int', ['pointer']
    );

    const stmtPtr = Memory.alloc(Process.pointerSize);
    const sqlPtr = Memory.allocUtf8String(sql);

    if (sqlite3Prepare(dbHandle, sqlPtr, -1, stmtPtr, ptr(0)) !== SQLITE_OK) {
        return rowsObj;
    }

    const stmt = stmtPtr.readPointer();
    while (sqlite3Step(stmt) === SQLITE_ROW) {
        const rowObj: { [key: string]: Uint8Array | string } = {};
        const colCount = sqlite3ColumnCount(stmt);

        for (let i = 0; i < colCount; i++) {
            const type = sqlite3ColumnType(stmt, i);
            const columnNamePtr = sqlite3ColumnName(stmt, i);
            const column = columnNamePtr ? columnNamePtr.readUtf8String() || '' : '';
            const length = sqlite3ColumnBytes(stmt, i);
            const blob = sqlite3ColumnBlob(stmt, i);

            let content: Uint8Array | string = '';
            if (type !== SQLITE_NULL) {
                if (type === SQLITE_TEXT) {
                    if (length > 0 && blob) {
                        content = blob.readCString() || '';
                    }
                } else if (type === SQLITE_INTEGER || type === SQLITE_FLOAT) {
                    // SQLite 对 INTEGER/FLOAT 的 column_blob 返回十进制文本（与 WCF 一致）
                    if (length > 0 && blob) {
                        content = blob.readUtf8String(length) || blob.readCString() || '';
                    }
                } else if (length > 0 && blob) {
                    const buffer = blob.readByteArray(length);
                    if (buffer) {
                        content = new Uint8Array(buffer);
                    }
                }
            }

            rowObj[column] = content;
        }
        rowsObj.push(rowObj);
    }

    sqlite3Finalize(stmt);
    return rowsObj;
}

// 获取本地ID和数据库索引（msgId 可能超过 JS 安全整数，请传 string）
export const getLocalIdAndDbIdx = (id: number | string): { localId: number, dbIdx: number } | null => {
    const msgIdStr = String(id).trim()
    if (!/^\d+$/.test(msgIdStr)) {
        console.error('getLocalIdAndDbIdx: 无效 msgId', id)
        return null
    }

    const msgMgrAddr = moduleBaseAddress.add(OFFSET_DB_MSG_MGR).readPointer();
    const dbIndex = msgMgrAddr.add(0x68).readU32();
    const pStart = msgMgrAddr.add(0x50).readPointer();

    for (let i = dbIndex - 1; i >= 0; i--) {
        const dbAddr = pStart.add(i * 0x08).readPointer();
        if (dbAddr.isNull()) {
            continue
        }
        // WCF GET_WSTRING(dbAddr) = *(wchar_t **)dbAddr
        let dbName = ''
        try {
            const namePtr = dbAddr.readPointer()
            dbName = namePtr && !namePtr.isNull() ? (namePtr.readUtf16String() || '') : ''
        } catch (e) {
            continue
        }
        if (!dbName) {
            continue
        }

        dbMap.set(dbName, dbAddr.add(0x78).readPointer());
        const rows = execDbQuery(dbName, `SELECT localId FROM MSG WHERE MsgSvrID=${msgIdStr};`);
        if (rows.length === 0) {
            continue
        }

        const raw = rows[0].localId
        let localId = 0
        if (typeof raw === 'number') {
            localId = raw
        } else if (typeof raw === 'string') {
            // INTEGER 经 column_blob 得到十进制文本
            localId = parseInt(raw, 10)
        } else if (raw instanceof Uint8Array) {
            const s = Array.from(raw).map(b => String.fromCharCode(b)).join('')
            localId = parseInt(s, 10)
        }
        if (!localId) {
            continue
        }

        // WCF: dbIdx = (*(QWORD*)(*(QWORD*)(dbAddr+0x28)+0x1E8)) >> 32
        const dbIdx = dbAddr.add(0x28).readPointer().add(0x1E8 + 4).readU32()
        console.log(`getLocalIdAndDbIdx: msgId=${msgIdStr} db=${dbName} localId=${localId} dbIdx=${dbIdx}`)
        return { localId, dbIdx }
    }

    console.warn(`getLocalIdAndDbIdx: 未找到消息 MsgSvrID=${msgIdStr}`)
    return null;
}

/** SQL 字符串转义（单引号加倍） */
const sqlEscape = (s: string): string => String(s).replace(/'/g, "''")

const cellToString = (v: Uint8Array | string | undefined): string => {
    if (v === undefined || v === null) return ''
    if (typeof v === 'string') return v
    if (v instanceof Uint8Array) {
        try {
            return Array.from(v).map(b => String.fromCharCode(b)).join('')
        } catch (e) {
            return ''
        }
    }
    return String(v)
}

export interface ChatHistoryQuery {
    /** 会话 ID：好友 wxid 或群 ID（StrTalker） */
    talker: string
    /** 返回条数，默认 50，最大 200 */
    limit?: number
    /** 跳过条数，默认 0 */
    offset?: number
    /** 时间排序，默认 desc（新→旧） */
    order?: 'asc' | 'desc'
    /** 可选：消息 Type 过滤 */
    type?: number
    /** 可选：CreateTime 下界（含） */
    fromTime?: number
    /** 可选：CreateTime 上界（含） */
    toTime?: number
}

export interface ChatHistoryItem {
    localId: string
    msgId: string
    type: number
    subType: number
    isSender: number
    createTime: number
    createTimeText: string
    talker: string
    content: string
    displayContent: string
    dbName: string
}

/**
 * 查询与某人/某群的聊天记录（扫描全部 MSG*.db，合并后分页）
 */
export const queryChatHistory = (opts: ChatHistoryQuery): {
    talker: string
    total: number
    limit: number
    offset: number
    order: 'asc' | 'desc'
    items: ChatHistoryItem[]
} => {
    const talker = String(opts.talker || '').trim()
    if (!talker) {
        return { talker: '', total: 0, limit: 0, offset: 0, order: 'desc', items: [] }
    }

    let limit = Number(opts.limit)
    if (!Number.isFinite(limit) || limit <= 0) limit = 50
    if (limit > 200) limit = 200

    let offset = Number(opts.offset)
    if (!Number.isFinite(offset) || offset < 0) offset = 0

    const order: 'asc' | 'desc' = opts.order === 'asc' ? 'asc' : 'desc'
    const talkerEsc = sqlEscape(talker)

    const where: string[] = [`StrTalker='${talkerEsc}'`]
    if (opts.type !== undefined && opts.type !== null && String(opts.type) !== '') {
        const t = Number(opts.type)
        if (Number.isFinite(t)) where.push(`Type=${t}`)
    }
    if (opts.fromTime !== undefined && Number.isFinite(Number(opts.fromTime))) {
        where.push(`CreateTime>=${Number(opts.fromTime)}`)
    }
    if (opts.toTime !== undefined && Number.isFinite(Number(opts.toTime))) {
        where.push(`CreateTime<=${Number(opts.toTime)}`)
    }
    const whereSql = where.join(' AND ')

    if (dbMap.size === 0) {
        getDbHandles()
    }
    const msgDbs = getDbNames().filter(n => /^MSG\d+\.db$/i.test(n))
    // 兜底：有时只有 MSG0
    const dbs = msgDbs.length > 0 ? msgDbs : getDbNames().filter(n => /^MSG/i.test(n) && !/^MediaMSG/i.test(n))

    // 每库多取一些再合并，避免跨库分页漏消息
    const fetchN = Math.min(500, offset + limit)
    const merged: ChatHistoryItem[] = []

    for (const dbName of dbs) {
        const sql =
            `SELECT localId, MsgSvrID, Type, SubType, IsSender, CreateTime, ` +
            `StrTalker, StrContent, DisplayContent ` +
            `FROM MSG WHERE ${whereSql} ` +
            `ORDER BY CreateTime DESC LIMIT ${fetchN};`
        let rows: Array<{ [key: string]: Uint8Array | string }> = []
        try {
            rows = execDbQuery(dbName, sql)
        } catch (e) {
            console.error('queryChatHistory db error:', dbName, e)
            continue
        }
        for (const row of rows) {
            const createTime = parseInt(cellToString(row.CreateTime), 10) || 0
            const type = parseInt(cellToString(row.Type), 10) || 0
            const subType = parseInt(cellToString(row.SubType), 10) || 0
            const isSender = parseInt(cellToString(row.IsSender), 10) || 0
            const content = cellToString(row.StrContent)
            const displayContent = cellToString(row.DisplayContent)
            const d = new Date(createTime * 1000)
            const pad = (n: number) => (n < 10 ? '0' + n : String(n))
            const createTimeText = Number.isFinite(d.getTime())
                ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
                  `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
                : ''
            merged.push({
                localId: cellToString(row.localId),
                msgId: cellToString(row.MsgSvrID),
                type,
                subType,
                isSender,
                createTime,
                createTimeText,
                talker: cellToString(row.StrTalker) || talker,
                content,
                displayContent,
                dbName,
            })
        }
    }

    merged.sort((a, b) =>
        order === 'asc' ? a.createTime - b.createTime : b.createTime - a.createTime
    )

    // total：粗略为合并后条数（各库各取 fetchN，可能小于真实总量）
    const total = merged.length
    const items = merged.slice(offset, offset + limit)

    return { talker, total, limit, offset, order, items }
}

// console.log('getLocalIdAndDbIdx() res:\n', JSON.stringify(getLocalIdAndDbIdx(1234567890)))

// 获取音频数据
export function getAudioData(id: number | string): Uint8Array | null {
    const msgMgrAddr = moduleBaseAddress.add(OFFSET_DB_MSG_MGR).readPointer();
    const dbIndex = msgMgrAddr.add(0x68).readU32();
    const idStr = String(id).trim()
    if (!/^\d+$/.test(idStr)) {
        return null
    }

    const sql = `SELECT Buf FROM Media WHERE Reserved0=${idStr};`;
    for (let i = dbIndex - 1; i >= 0; i--) {
        const dbName = `MediaMSG${i}.db`;
        const rows = execDbQuery(dbName, sql);

        if (rows.length > 0) {
            const row = rows[0];
            if (row.Buf instanceof Uint8Array) {
                // 首字节为 0x02，估计是混淆用的，去掉
                return row.Buf.slice(1);
            }
        }
    }

    return null;
}