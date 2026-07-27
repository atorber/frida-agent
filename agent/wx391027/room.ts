import {
    writeWStringPtr,
    readWStringPtr,
    ReadSKBuiltinString,
    ReadWeChatStr,
    WeChatMessage,
    hasPath,
    uint8ArrayToString,
    stringToUint8Array,
    readAll,
    findIamgePathAddr,
    readString,
    readWideString,
    readStringPtr,
    getStringByStrAddr,
    initStruct,
    initidStruct,
    initmsgStruct,
    parseContact,
    createWxString,
    createWxStringChars,
    createWxStringVector,
    createMsvcWStringVector,
} from './utils.js'

import {
    Contact,
    Message,
} from './types.js'

import { offsets } from './offset.js'
import { execDbQuery, lookupContactAvatars } from './sqlite.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

function splitWxids(wxids: string): string[] {
    return wxids.split(',').map(s => s.trim()).filter(Boolean)
}

function sqlEscape(s: string): string {
    return s.replace(/'/g, "''")
}

function rowText(row: { [key: string]: Uint8Array | string }, key: string): string {
    const v = row[key]
    if (v == null) return ''
    if (typeof v === 'string') return v
    try {
        return uint8ArrayToString(v)
    } catch (e) {
        return ''
    }
}

/**
 * 将 Alias / 输入 ID 解析为 Contact.UserName（踢人必须用 UserName）
 */
export function resolveContactUserName(id: string): string {
    const q = sqlEscape(id)
    // 1) 已是 UserName
    let rows = execDbQuery(
        'MicroMsg.db',
        `SELECT UserName, Alias, NickName FROM Contact WHERE UserName='${q}' LIMIT 1;`
    )
    if (rows.length > 0) {
        const userName = rowText(rows[0], 'UserName')
        if (userName) {
            return userName
        }
    }
    // 2) Alias（微信号）
    rows = execDbQuery(
        'MicroMsg.db',
        `SELECT UserName, Alias FROM Contact WHERE Alias='${q}' LIMIT 1;`
    )
    if (rows.length > 0) {
        const userName = rowText(rows[0], 'UserName')
        if (userName) {
            console.log(`resolveContactUserName: Alias ${id} -> UserName ${userName}`)
            return userName
        }
    }
    // 3) Remark / NickName（兜底，可能重名）
    rows = execDbQuery(
        'MicroMsg.db',
        `SELECT UserName, NickName, Remark FROM Contact WHERE Remark='${q}' OR NickName='${q}' LIMIT 2;`
    )
    if (rows.length === 1) {
        const userName = rowText(rows[0], 'UserName')
        if (userName) {
            console.log(`resolveContactUserName: Nick/Remark ${id} -> UserName ${userName}`)
            return userName
        }
    }
    console.warn(`resolveContactUserName: 未解析到 UserName，沿用原值: ${id}`)
    return id
}

/** 读取群成员 UserName 列表（ChatRoom.UserNameList 分隔符为 ^G 或 \\x07） */
export function getRoomMemberUserNames(roomId: string): string[] {
    const rows = execDbQuery(
        'MicroMsg.db',
        `SELECT UserNameList FROM ChatRoom WHERE ChatRoomName='${sqlEscape(roomId)}' LIMIT 1;`
    )
    if (rows.length === 0) {
        return []
    }
    const list = rowText(rows[0], 'UserNameList')
    if (!list) {
        return []
    }
    // 微信库常见：id1^Gid2^Gid3（字面 ^G）或 id1\x07id2（ASCII BEL）
    // 切勿只按 ^ 分割，否则后续成员会残留前缀 G（如 Gwxxxx）
    return list
        .split(/\^G|\x07/)
        .map(s => s.replace(/^[G\^;,\s]+|[;,\s]+$/g, '').trim())
        .filter(Boolean)
}

/** 仅使用 WCF 对齐的 wx32；调用前校验字符串可读 */
function buildMembersVector(wxids: string[]): NativePointer {
    if (wxids.length === 0) {
        throw new Error('wxids 为空')
    }
    return createWxStringVector(wxids, false)
}

function readWxStringDebug(p: NativePointer): { ptr: NativePointer, size: number, cap: number, str: string } {
    const dataPtr = p.readPointer()
    const size = p.add(8).readU32()
    const cap = p.add(12).readU32()
    let str = ''
    try {
        const n = size > 0 && size < 4096 ? size : -1
        str = (n > 0 ? dataPtr.readUtf16String(n) : dataPtr.readUtf16String()) || ''
    } catch (e) {
        str = '<unreadable>'
    }
    return { ptr: dataPtr, size, cap, str }
}

function prepareRoomMemberArgs(
    roomId: string,
    wxids: string[],
    memberLayout: 'wx' | 'wstr' = 'wx',
): {
    roomIdStr: NativePointer
    vMembers: NativePointer
} {
    const roomIdStr = createWxStringChars(roomId)
    const vMembers = memberLayout === 'wstr'
        ? createMsvcWStringVector(wxids)
        : buildMembersVector(wxids)
    const start = vMembers.readPointer()
    const roomDbg = readWxStringDebug(roomIdStr)

    let memStr = ''
    let memPtr: NativePointer = ptr(0)
    let memSize = 0
    try {
        memPtr = start.readPointer()
        if (memberLayout === 'wstr') {
            memSize = start.add(16).readU32()
            memStr = memPtr.readUtf16String(memSize) || ''
        } else {
            const memDbg = readWxStringDebug(start)
            memPtr = memDbg.ptr
            memSize = memDbg.size
            memStr = memDbg.str
        }
    } catch (e) {
        memStr = '<unreadable>'
    }

    console.log(`roomMemberArgs layout=${memberLayout} room: ptr=${roomDbg.ptr} size=${roomDbg.size} str="${roomDbg.str}"`)
    console.log(`roomMemberArgs layout=${memberLayout} member0: ptr=${memPtr} size=${memSize} str="${memStr}"`)

    if (roomDbg.str !== roomId) {
        throw new Error(`room WxString 校验失败: expect="${roomId}" got="${roomDbg.str}"`)
    }
    if (memStr !== wxids[0]) {
        throw new Error(`member 字符串校验失败: expect="${wxids[0]}" got="${memStr}"`)
    }
    if (roomDbg.ptr.equals(memPtr)) {
        throw new Error('room/member 共用了同一个数据指针，字符串构造异常')
    }
    return { roomIdStr, vMembers }
}

function normalizeNativeStatus(ret: number): number {
    // x64 下 bool/小整数常只保证 AL 有效，高位可能是脏数据
    return ret & 0xff
}

function callDelMembers(roomId: string, wxids: string[]): number {
    const GetChatRoomMgr = new NativeFunction(
        moduleBaseAddress.add(offsets.kChatRoomMgr),
        'pointer',
        []
    )
    const DelChatroomMember = new NativeFunction(
        moduleBaseAddress.add(offsets.kDelChatroomMember),
        'int',
        ['pointer', 'pointer', 'pointer']
    )

    const mgrPtr = GetChatRoomMgr()
    if (!mgrPtr || mgrPtr.isNull()) {
        throw new Error('GetChatRoomMgr 返回空指针')
    }

    const { roomIdStr, vMembers } = prepareRoomMemberArgs(roomId, wxids, 'wx')
    console.log(`roomDel mgr=${mgrPtr} members=${vMembers}`)
    const raw = DelChatroomMember(mgrPtr, vMembers, roomIdStr) as number
    const status = normalizeNativeStatus(raw)
    console.log(`roomDel native raw=${raw} status=${status}`)
    return status
}

function dumpNativePrologue(label: string, addr: NativePointer, count = 24) {
    try {
        let p = addr
        const lines: string[] = []
        for (let i = 0; i < count; i++) {
            const insn = Instruction.parse(p)
            lines.push(`${p}: ${insn}`)
            p = insn.next
        }
        console.log(`${label} disasm(${count}):\n  ${lines.join('\n  ')}`)
    } catch (e) {
        console.log(`${label} disasm failed:`, e)
    }
}

let addCallHookInstalled = false
let addCallFromUs = false
let inviteCallFromUs = false

function describeMemberVec(tag: string, vec: NativePointer) {
    if (!vec || vec.isNull()) {
        return
    }
    try {
        const start = vec.readPointer()
        const finish = vec.add(Process.pointerSize).readPointer()
        const bytes = finish.sub(start).toInt32()
        console.log(`${tag} vector start=${start} finish=${finish} bytes=${bytes}`)
        if (bytes >= 0x10 && bytes <= 0x2000) {
            try {
                const wx = readWxStringDebug(start)
                console.log(`${tag} member0 size=${wx.size} str="${wx.str}"`)
            } catch (e) {}
            const head = start.readByteArray(Math.min(bytes, 0x40))
            if (head) {
                const arr = Array.from(new Uint8Array(head))
                console.log(`${tag} memberHex=${arr.map(b => b.toString(16).padStart(2, '0')).join(' ')}`)
            }
        }
    } catch (e) {
        console.log(`${tag} vector describe failed:`, e)
    }
}

/** 拦截 Add/Invite/Del：确认微信 UI 实际走哪条原生路径 */
export function installAddMemberHook(): void {
    if (addCallHookInstalled) {
        return
    }
    addCallHookInstalled = true

    Interceptor.attach(moduleBaseAddress.add(offsets.kAddChatroomMember), {
        onEnter(args) {
            const tag = addCallFromUs ? 'Add[api]' : 'Add[ui]'
            console.log(`${tag} mgr=${args[0]} vec=${args[1]} room=${args[2]} temp=${args[3]}`)
            try {
                console.log(`${tag} mgr+0x151=${args[0].add(0x151).readU8()}`)
            } catch (e) {}
            describeMemberVec(tag, args[1])
            try {
                const rd = readWxStringDebug(args[2])
                console.log(`${tag} room size=${rd.size} str="${rd.str}"`)
            } catch (e) {}
        },
        onLeave(retval) {
            const tag = addCallFromUs ? 'Add[api]' : 'Add[ui]'
            console.log(`${tag} retval low8=${retval.toInt32() & 0xff}`)
        },
    })

    Interceptor.attach(moduleBaseAddress.add(offsets.kInviteChatroomMember), {
        onEnter(args) {
            const tag = inviteCallFromUs ? 'Invite[api]' : 'Invite[ui]'
            console.log(`${tag} a0=${args[0]} vec=${args[1]} room=${args[2]} temp=${args[3]}`)
            try {
                console.log(`${tag} a0 wchar=${args[0].readUtf16String()}`)
            } catch (e) {}
            describeMemberVec(tag, args[1])
        },
        onLeave(retval) {
            const tag = inviteCallFromUs ? 'Invite[api]' : 'Invite[ui]'
            console.log(`${tag} retval low8=${retval.toInt32() & 0xff}`)
        },
    })

    Interceptor.attach(moduleBaseAddress.add(offsets.kDelChatroomMember), {
        onEnter(args) {
            console.log(`Del[native] mgr=${args[0]} vec=${args[1]} room=${args[2]}`)
            describeMemberVec('Del[native]', args[1])
        },
        onLeave(retval) {
            console.log(`Del[native] retval low8=${retval.toInt32() & 0xff}`)
        },
    })

    console.log('已安装 Add/Invite/Del 钩子：UI 手动踢人/拉人时看 Add[ui] 还是 Invite[ui]')
}

function heapAlloc(size: number): NativePointer {
    const GetProcessHeap = new NativeFunction(
        Module.getExportByName('kernel32.dll', 'GetProcessHeap'),
        'pointer',
        []
    )
    const HeapAlloc = new NativeFunction(
        Module.getExportByName('kernel32.dll', 'HeapAlloc'),
        'pointer',
        ['pointer', 'uint32', 'ulong']
    )
    const HEAP_ZERO_MEMORY = 0x8
    const p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
    if (!p || p.isNull()) {
        throw new Error(`HeapAlloc(${size}) failed`)
    }
    return p
}

/** 完全对齐 WCF NewWxStringFromWstr：ProcessHeap + 字符长度 */
function createWxStringHeap(str: string): NativePointer {
    const dataPtr = heapAlloc((str.length + 1) * 2)
    dataPtr.writeUtf16String(str)
    const structPtr = heapAlloc(0x20)
    structPtr.writePointer(dataPtr)
    structPtr.add(8).writeU32(str.length)
    structPtr.add(12).writeU32(str.length)
    return structPtr
}

function createWxStringVectorHeap(ids: string[]): NativePointer {
    const count = ids.length
    const arrayPtr = heapAlloc(0x20 * count)
    for (let i = 0; i < count; i++) {
        const dataPtr = heapAlloc((ids[i].length + 1) * 2)
        dataPtr.writeUtf16String(ids[i])
        const slot = arrayPtr.add(i * 0x20)
        slot.writePointer(dataPtr)
        slot.add(8).writeU32(ids[i].length)
        slot.add(12).writeU32(ids[i].length)
    }
    const rawVector = heapAlloc(Process.pointerSize * 3)
    const finish = arrayPtr.add(0x20 * count)
    rawVector.writePointer(arrayPtr)
    rawVector.add(Process.pointerSize).writePointer(finish)
    rawVector.add(Process.pointerSize * 2).writePointer(finish)
    return rawVector
}

function callAddMembers(roomId: string, wxids: string[]): number {
    installAddMemberHook()
    const addAddr = moduleBaseAddress.add(offsets.kAddChatroomMember)

    const GetChatRoomMgr = new NativeFunction(
        moduleBaseAddress.add(offsets.kChatRoomMgr),
        'pointer',
        []
    )
    const AddChatroomMember = new NativeFunction(
        addAddr,
        'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    )

    const mgrPtr = GetChatRoomMgr()
    if (!mgrPtr || mgrPtr.isNull()) {
        throw new Error('GetChatRoomMgr 返回空指针')
    }

    // 反汇编：cmp byte ptr [rcx+0x151], 0 / je fail —— 该标志为 0 时 Add 直接失败
    const flagAddr = mgrPtr.add(0x151)
    const flagBefore = flagAddr.readU8()
    console.log(`roomAdd mgr=${mgrPtr} flag@+0x151=${flagBefore}`)
    if (flagBefore === 0) {
        console.warn('mgr+0x151=0，Add 会走失败分支；临时置 1 后重试')
        flagAddr.writeU8(1)
        console.log(`roomAdd flag@+0x151 已改为 ${flagAddr.readU8()}`)
    }

    const room = createWxStringHeap(roomId)
    const members = createWxStringVectorHeap(wxids)
    const temp = heapAlloc(Process.pointerSize * 2)
    const roomDbg = readWxStringDebug(room)
    const memDbg = readWxStringDebug(members.readPointer())
    console.log(`roomAdd heap-wx room="${roomDbg.str}" member0="${memDbg.str}"`)

    addCallFromUs = true
    let raw = 0
    try {
        raw = AddChatroomMember(mgrPtr, members, room, temp) as number
    } finally {
        addCallFromUs = false
        // 恢复标志，避免影响微信其它逻辑
        if (flagBefore === 0) {
            try {
                flagAddr.writeU8(0)
            } catch (e) {}
        }
    }
    const status = normalizeNativeStatus(raw)
    console.log(`roomAdd heap-wx raw=${raw} status=${status}`)
    return status
}

function callInviteMembers(roomId: string, wxids: string[]): number {
    const InviteChatroomMember = new NativeFunction(
        moduleBaseAddress.add(offsets.kInviteChatroomMember),
        'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    )

    const { roomIdStr, vMembers } = prepareRoomMemberArgs(roomId, wxids, 'wx')
    const wsRoomidCstr = Memory.allocUtf16String(roomId)
    const temp = Memory.alloc(Process.pointerSize * 2)
    console.log(`roomInvite members=${vMembers}`)
    inviteCallFromUs = true
    let raw = 0
    try {
        raw = InviteChatroomMember(wsRoomidCstr, vMembers, roomIdStr, temp) as number
    } finally {
        inviteCallFromUs = false
    }
    const status = normalizeNativeStatus(raw)
    console.log(
        `roomInvite native raw=${raw} status=${status} temp=[${temp.readU64()}, ${temp.add(8).readU64()}]`
    )
    return status
}

/*
获取群列表
*/
export function roomList() {
    // 使用NativeFunction调用相关函数
    const getContactMgrInstance = new NativeFunction(
        moduleBaseAddress.add(offsets.kGetContactMgr),
        'pointer', []
    );
    const getContactListFunction = new NativeFunction(
        moduleBaseAddress.add(offsets.kGetContactList),
        'int64', ['pointer', 'pointer']
    );

    // 获取联系人管理器的实例
    const contactMgrInstance = getContactMgrInstance();

    // 准备用于存储联系人信息的数组
    const contacts: Contact[] = [];
    const contactVecPlaceholder: any = Memory.alloc(Process.pointerSize * 3);
    contactVecPlaceholder.writePointer(ptr(0));  // 初始化指针数组

    const success = getContactListFunction(contactMgrInstance, contactVecPlaceholder);
    const contactVecPtr = contactVecPlaceholder.readU32();

    // 解析联系人信息
    if (success) {
        const contactPtr = contactVecPlaceholder;
        let start = contactPtr.readPointer();
        const end = contactPtr.add(Process.pointerSize * 2).readPointer();

        const CONTACT_SIZE = 0x6A8; // 假设每个联系人数据结构的大小

        while (start.compare(end) < 0) {
            try {
                // console.log('start:', start)
                const contact = parseContact(start);
                // console.log('contact:', JSON.stringify(contact, null, 2))
                if (contact.id && (contact.id.endsWith('chatroom'))) {
                    contacts.push(contact);
                }
            } catch (error) {
                console.log('contactList() error:', error)
            }
            start = start.add(CONTACT_SIZE);
        }
    }
    try {
        const avatarMap = lookupContactAvatars(contacts.map((c) => c.id))
        for (const c of contacts) {
            const url = avatarMap.get(c.id)
            if (url) c.avatar = url
        }
    } catch (e) {
        console.log('roomList() avatar enrich error:', e)
    }
    return contacts;
};

/*
获取群详情
从群列表中查找指定的群并返回群信息
*/
export function roomRawPayload(roomId: string) {
    try {
        console.log(`[ROOM] [${new Date().toISOString()}] 开始查找群详情，roomId: ${roomId}`);
        
        // 从群列表中查找指定的群
        const rooms = roomList();
        console.log(`[ROOM] [${new Date().toISOString()}] 群列表总数: ${rooms.length}`);
        
        // 查找匹配的群（支持完整匹配和部分匹配）
        const matchedRoom = rooms.find(room => {
            // 完全匹配
            if (room.id === roomId) {
                return true;
            }
            // 如果 roomId 不包含 @chatroom，尝试添加后缀匹配
            if (!roomId.includes('@chatroom') && room.id === `${roomId}@chatroom`) {
                return true;
            }
            // 如果 roomId 包含 @chatroom，尝试去掉后缀匹配
            if (roomId.includes('@chatroom') && room.id === roomId.replace('@chatroom', '')) {
                return true;
            }
            return false;
        });
        
        if (!matchedRoom) {
            console.error(`[ROOM] [${new Date().toISOString()}] 未找到群: ${roomId}`);
            // 输出前几个群的ID，方便调试
            if (rooms.length > 0) {
                console.log(`[ROOM] [${new Date().toISOString()}] 前5个群ID示例:`, rooms.slice(0, 5).map(r => r.id));
            }
            return {
                error: true,
                message: `未找到群: roomId=${roomId}`,
                roomId: roomId
            } as any;
        }
        
        console.log(`[ROOM] [${new Date().toISOString()}] 找到群信息:`, {
            id: matchedRoom.id,
            name: matchedRoom.name,
            type: matchedRoom.type
        });
        
        // 返回群信息，保持与原有接口兼容的格式
        const info: any = {
            id: matchedRoom.id,
            name: matchedRoom.name || '',
            topic: matchedRoom.name || '', // 群名称
            type: matchedRoom.type || 0,
            alias: matchedRoom.alias || '',
            remark: matchedRoom.alias || '',
            // 以下字段从群列表中无法获取，设置为空或默认值
            notice: '', // 群公告需要其他方式获取
            admin: '', // 群主需要其他方式获取
            xml: '', // XML信息需要其他方式获取
        };
        
        return info;
    } catch (e: any) {
        console.error(`[ROOM] [${new Date().toISOString()}] roomRawPayload 异常:`, e);
        return {
            error: true,
            message: `获取群详情异常: roomId=${roomId}, 错误=${e.message || String(e)}`,
            roomId: roomId
        } as any;
    }
};

/*
从群里删除成员（对齐 WCF DelChatroomMember，支持逗号分隔多人）
会先把 Alias/昵称解析为 Contact.UserName。
*/
export function roomDel(
    roomId: string,
    contactId: string,
): boolean {
    console.log('roomDel:', roomId, contactId)
    try {
        const inputWxids = splitWxids(contactId)
        if (!roomId || inputWxids.length === 0) {
            console.error('roomId 或 wxids 为空')
            return false
        }

        const resolvedWxids = inputWxids.map(resolveContactUserName)
        const members = getRoomMemberUserNames(roomId)
        console.log(`roomDel 群成员数=${members.length}, 解析结果:`, inputWxids.map((a, i) => `${a}=>${resolvedWxids[i]}`))

        const notInRoom = members.length > 0
            ? resolvedWxids.filter(id => !members.includes(id))
            : []
        if (notInRoom.length > 0) {
            console.warn('roomDel 以下 ID 不在 ChatRoom.UserNameList 中（仍会调用原生）:', notInRoom)
        }

        const status = callDelMembers(roomId, resolvedWxids)
        console.log('从群删除成员结果:', status, 'toKick=', resolvedWxids)
        return status === 1
    } catch (error: any) {
        console.error('roomDel failed:', error)
        return false
    }
}

/*
获取群头像
*/
export async function roomAvatar(roomId: string) {
    // 实现获取群头像的功能
    // 这里可能需要调用WeChatWin.dll中的相关函数
    console.log('获取群头像, roomId:', roomId);
    return '';
}

/*
添加成员到群：先走原生 Add，失败再回退 Invite。
*/
export function roomAdd(
    roomId: string,
    wxids: string,
): boolean {
    console.log('roomAdd:', roomId, wxids)
    try {
        const inputWxids = splitWxids(wxids)
        if (!roomId || inputWxids.length === 0) {
            console.error('房间ID或微信ID为空')
            return false
        }
        const resolvedWxids = inputWxids.map(resolveContactUserName)
        const addStatus = callAddMembers(roomId, resolvedWxids)
        if (addStatus === 1) {
            console.log('添加成员到群成功(Add):', resolvedWxids)
            return true
        }
        console.warn(`原生 Add 返回 ${addStatus}，回退 Invite`)
        const invStatus = callInviteMembers(roomId, resolvedWxids)
        console.log('添加成员到群结果(Invite):', invStatus, 'wxids=', resolvedWxids)
        return invStatus === 1
    } catch (error) {
        console.error('添加成员到群出错:', error)
        return false
    }
}

/*
邀请成员进群（对齐 WCF InviteChatroomMember）
*/
export function roomInvite(
    roomId: string,
    wxids: string,
): boolean {
    console.log('roomInvite:', roomId, wxids)
    try {
        const inputWxids = splitWxids(wxids)
        if (!roomId || inputWxids.length === 0) {
            console.error('房间ID或微信ID为空')
            return false
        }
        const resolvedWxids = inputWxids.map(resolveContactUserName)
        const status = callInviteMembers(roomId, resolvedWxids)
        console.log('邀请成员进群结果:', status, 'wxids=', resolvedWxids)
        return status === 1
    } catch (error) {
        console.error('邀请成员进群出错:', error)
        return false
    }
}

/*
设置群名称
*/
export function roomTopic(roomId: string, topic: string): number {
    try {
        const Instance = new NativeFunction(moduleBaseAddress.add(offsets.kOpLogMgr), 'pointer', [])
        const ModChatRoomTopic = new NativeFunction(
            moduleBaseAddress.add(offsets.kModChatRoomTopic),
            'uint64',
            ['pointer', 'pointer', 'pointer']
        )

        const instancePtr = Instance()
        const roomIdStrPtr = createWxStringChars(roomId)
        const topicStrPtr = createWxStringChars(topic)
        const result = ModChatRoomTopic(instancePtr, roomIdStrPtr, topicStrPtr)
        console.log('ModChatRoomTopic result:', result)
        return Number(result)
    } catch (error) {
        console.error('roomTopic failed:', error)
        return -1
    }
}

/*
创建群
*/
export async function roomCreate(
    contactIdList: string[],
    topic: string,
) {
    // 实现创建群聊的功能
    console.log('创建群聊，成员:', contactIdList, '主题:', topic);
    
    // 这里需要调用WeChatWin.dll中的相关函数创建群聊
    // 暂时返回模拟数据
    return 'mock_room_id';
}

/*
退出群
*/
export async function roomQuit(roomId: string): Promise<boolean> {
    // 调用DelChatroomMember函数，传入自己的wxid来退出群
    const getMySelfInfoAddr = moduleBaseAddress.add(offsets.kGetContactMgr); // 使用获取联系人管理器来获取自己的信息
    const GetMySelfInfo = new NativeFunction(getMySelfInfoAddr, 'pointer', []);
    
    // 获取自己的wxid
    const mySelfInfo = GetMySelfInfo();
    if (!mySelfInfo) {
        console.error('获取自己的信息失败');
        return false;
    }
    
    // 假设我们能够从mySelfInfo获取到自己的wxid
    // 这里需要根据实际情况调整获取wxid的方法
    const myWxid = "self_wxid"; // 这里需要替换成实际获取wxid的方法
    
    // 调用roomDel方法删除自己
    const result = roomDel(roomId, myWxid);
    
    return result;
}

/*
获取群二维码
*/
export async function roomQRCode(roomId: string): Promise<string> {
    console.log('获取群二维码, roomId:', roomId);
    // 实现获取群二维码的功能
    return roomId + ' mock qrcode';
}

function normalizeRoomId(roomId: string): string {
    const s = (roomId || '').trim()
    if (!s) return s
    if (s.includes('@chatroom')) return s
    return `${s}@chatroom`
}

/** ChatRoom.DisplayNameList 与 UserNameList 一一对应（群内昵称） */
function getRoomMemberDisplayNames(roomId: string): string[] {
    try {
        const rows = execDbQuery(
            'MicroMsg.db',
            `SELECT DisplayNameList FROM ChatRoom WHERE ChatRoomName='${sqlEscape(roomId)}' LIMIT 1;`
        )
        if (rows.length === 0) {
            return []
        }
        const list = rowText(rows[0], 'DisplayNameList')
        if (!list) {
            return []
        }
        return list
            .split(/\^G|\x07/)
            .map(s => s.replace(/^[G\^;,\s]+|[;,\s]+$/g, '').trim())
    } catch (e) {
        return []
    }
}

function lookupContactBrief(wxid: string): {
    alias: string
    name: string
    remark: string
    bigHeadImgUrl: string
    smallHeadImgUrl: string
} {
    const empty = { alias: '', name: '', remark: '', bigHeadImgUrl: '', smallHeadImgUrl: '' }
    try {
        const rows = execDbQuery(
            'MicroMsg.db',
            `SELECT UserName, Alias, NickName, Remark, BigHeadImgUrl, SmallHeadImgUrl ` +
            `FROM Contact WHERE UserName='${sqlEscape(wxid)}' LIMIT 1;`
        )
        if (rows.length === 0) {
            return empty
        }
        const r = rows[0]
        return {
            alias: rowText(r, 'Alias'),
            name: rowText(r, 'NickName'),
            remark: rowText(r, 'Remark'),
            bigHeadImgUrl: rowText(r, 'BigHeadImgUrl'),
            smallHeadImgUrl: rowText(r, 'SmallHeadImgUrl'),
        }
    } catch (e) {
        return empty
    }
}

/*
获取群成员列表（MicroMsg.db ChatRoom.UserNameList + Contact 补充信息）
*/
export function roomMemberList(roomId: string): Array<{
    wxid: string
    alias: string
    name: string
    remark: string
    displayName: string
    bigHeadImgUrl: string
    smallHeadImgUrl: string
}> {
    const rid = normalizeRoomId(roomId)
    console.log('roomMemberList:', rid)

    const wxids = getRoomMemberUserNames(rid)
    const displayNames = getRoomMemberDisplayNames(rid)

    return wxids.map((wxid, i) => {
        const contact = lookupContactBrief(wxid)
        return {
            wxid,
            alias: contact.alias,
            name: contact.name,
            remark: contact.remark,
            displayName: displayNames[i] || '',
            bigHeadImgUrl: contact.bigHeadImgUrl,
            smallHeadImgUrl: contact.smallHeadImgUrl,
        }
    })
}

/*
获取单个群成员详情
*/
export function roomMemberRawPayload(roomId: string, contactId: string): {
    roomId: string
    wxid: string
    alias: string
    name: string
    remark: string
    displayName: string
    bigHeadImgUrl: string
    smallHeadImgUrl: string
    inRoom: boolean
} {
    const rid = normalizeRoomId(roomId)
    const wxid = resolveContactUserName(contactId)
    const members = getRoomMemberUserNames(rid)
    const idx = members.indexOf(wxid)
    const displayNames = getRoomMemberDisplayNames(rid)
    const contact = lookupContactBrief(wxid)
    return {
        roomId: rid,
        wxid,
        alias: contact.alias,
        name: contact.name,
        remark: contact.remark,
        displayName: idx >= 0 ? (displayNames[idx] || '') : '',
        bigHeadImgUrl: contact.bigHeadImgUrl,
        smallHeadImgUrl: contact.smallHeadImgUrl,
        inRoom: idx >= 0,
    }
}

/*
设置群公告
*/
export async function roomAnnounce(roomId: string, text?: string): Promise<void | string> {
    console.log('设置群公告, roomId:', roomId, 'text:', text);
    
    if (text) {
        // 设置群公告
        // 这里需要调用WeChatWin.dll中的相关函数设置群公告
        return;
    }
    
    // 获取群公告
    return 'mock announcement for ' + roomId;
}