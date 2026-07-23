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
    createWxStringVector,
} from './utils.js'

import {
    Contact,
    Message,
} from './types.js'

import { offsets } from './offset.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

function splitWxids(wxids: string): string[] {
    return wxids.split(',').map(s => s.trim()).filter(Boolean)
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
*/
export function roomDel(
    roomId: string,
    contactId: string,
): boolean {
    console.log('roomDel:', roomId, contactId)
    try {
        if (!roomId || !contactId) {
            return false
        }

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

        const roomIdStr = createWxString(roomId)
        const vMembers = createWxStringVector(splitWxids(contactId))
        const mgrPtr = GetChatRoomMgr()
        const status = DelChatroomMember(mgrPtr, vMembers, roomIdStr)
        console.log('从群删除成员结果:', status)
        return status === 1
    } catch (error) {
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
添加成员到群（对齐 WCF AddChatroomMember，支持逗号分隔多人）
*/
export function roomAdd(
    roomId: string,
    wxids: string,
): boolean {
    try {
        if (!roomId || !wxids) {
            console.error("房间ID或微信ID为空");
            return false;
        }

        const GetChatRoomMgr = new NativeFunction(
            moduleBaseAddress.add(offsets.kChatRoomMgr),
            'pointer',
            []
        )
        const AddChatroomMember = new NativeFunction(
            moduleBaseAddress.add(offsets.kAddChatroomMember),
            'int',
            ['pointer', 'pointer', 'pointer', 'pointer']
        )

        const mgrPtr = GetChatRoomMgr();
        if (!mgrPtr || mgrPtr.isNull()) {
            console.error('获取聊天室管理器失败');
            return false;
        }

        const roomIdStr = createWxString(roomId)
        const vMembers = createWxStringVector(splitWxids(wxids))
        const temp = Memory.alloc(Process.pointerSize * 2)
        temp.writeByteArray(Array(Process.pointerSize * 2).fill(0))

        const status = AddChatroomMember(mgrPtr, vMembers, roomIdStr, temp)
        console.log('添加成员到群结果:', status)
        return status === 1
    } catch (error) {
        console.error('添加成员到群出错:', error);
        return false;
    }
}

/*
邀请成员进群（对齐 WCF InviteChatroomMember）
*/
export function roomInvite(
    roomId: string,
    wxids: string,
): boolean {
    try {
        if (!roomId || !wxids) {
            console.error("房间ID或微信ID为空");
            return false;
        }

        const InviteChatroomMember = new NativeFunction(
            moduleBaseAddress.add(offsets.kInviteChatroomMember),
            'int',
            ['pointer', 'pointer', 'pointer', 'pointer']
        )

        // WCF: InviteMembers(wsRoomid.c_str(), pMembers, pWxRoomid, temp)
        const wsRoomidCstr = Memory.allocUtf16String(roomId)
        const pWxRoomid = createWxString(roomId)
        const vMembers = createWxStringVector(splitWxids(wxids))
        const temp = Memory.alloc(Process.pointerSize * 2)
        temp.writeByteArray(Array(Process.pointerSize * 2).fill(0))

        const status = InviteChatroomMember(wsRoomidCstr, vMembers, pWxRoomid, temp)
        console.log('邀请成员进群结果:', status)
        return status === 1
    } catch (error) {
        console.error('邀请成员进群出错:', error);
        return false;
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
        const roomIdStrPtr = createWxString(roomId)
        const topicStrPtr = createWxString(topic)
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

/*
获取群成员列表
*/
export async function roomMemberList(roomId: string) {
    console.log('获取群成员列表, roomId:', roomId);
    // 实现获取群成员列表的功能
    // 这里可能需要获取群详情，然后解析成员信息
    
    // 先获取群详情
    const roomInfo = roomRawPayload(roomId);
    // 从群详情中解析成员列表
    // 暂时返回空数组
    return [];
}

/*
获取群成员详情
*/
export async function roomMemberRawPayload(roomId: string, contactId: string) {
    console.log('获取群成员详情, roomId:', roomId, 'contactId:', contactId);
    // 实现获取群成员详情的功能
    
    // 暂时返回空对象
    return {};
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