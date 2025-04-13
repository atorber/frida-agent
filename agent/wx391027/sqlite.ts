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
            // MSGi.db
            const dbName = dbAddr.readUtf16String(); // 使用 readUtf16String
            const dbHandle = dbAddr.add(0x78).readPointer();
            if (dbName) {
                dbMap.set(dbName, dbHandle);
            }

            // MediaMsgi.db
            const mmdbAddr = dbAddr.add(0x20).readPointer();
            const mmdbName = mmdbAddr.add(0x78).readUtf16String(); // 使用 readUtf16String
            const mmdbHandle = mmdbAddr.add(0x50).readPointer();
            if (mmdbName) {
                dbMap.set(mmdbName, mmdbHandle);
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
            if (length > 0 && type !== SQLITE_NULL && blob) {
                if (type === SQLITE_TEXT) {
                    // 使用 readCString 处理 UTF-8 编码
                    content = blob.readCString() || '';
                } else {
                    // 其他类型保持为 Uint8Array
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

// 获取本地ID和数据库索引
export const getLocalIdAndDbIdx = (id: number): { localId: number, dbIdx: number } | null => {
    const msgMgrAddr = moduleBaseAddress.add(OFFSET_DB_MSG_MGR).readPointer();
    const dbIndex = msgMgrAddr.add(0x68).readU32();
    const pStart = msgMgrAddr.add(0x50).readPointer();

    for (let i = dbIndex - 1; i >= 0; i--) {
        const dbAddr = pStart.add(i * 0x08).readPointer();
        if (!dbAddr.isNull()) {
            const dbName = dbAddr.readUtf8String();
            if (dbName) {
                dbMap.set(dbName, dbAddr.add(0x78).readPointer());
                const sql = `SELECT localId FROM MSG WHERE MsgSvrID=${id};`;
                const rows = execDbQuery(dbName, sql);

                if (rows.length > 0) {
                    const row = rows[0];
                    if (row.localId) {
                        const localId = parseInt(row.localId as string);
                        const dbIdx = dbAddr.add(0x28).readPointer().add(0x1E8).readU32();
                        return { localId, dbIdx };
                    }
                }
            }
        }
    }

    return null;
}

// console.log('getLocalIdAndDbIdx() res:\n', JSON.stringify(getLocalIdAndDbIdx(1234567890)))

// 获取音频数据
export function getAudioData(id: number): Uint8Array | null {
    const msgMgrAddr = moduleBaseAddress.add(OFFSET_DB_MSG_MGR).readPointer();
    const dbIndex = msgMgrAddr.add(0x68).readU32();

    const sql = `SELECT Buf FROM Media WHERE Reserved0=${id};`;
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