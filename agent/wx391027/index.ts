/**
 * WeChat 3.9.10.27
 * 
 */
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
    log
} from './utils.js'
import {
    Contact,
    Message,
} from './types.js'

import {
    checkLogin,
    getHomePath,
    getSelfWxid,
    getUserInfo
} from './login.js'
import {
    contactSelfInfo,
    contactList,
    contactRawPayload
} from './contact.js'

import {
    roomList,
    roomRawPayload,
    roomAdd,
    roomInvite,
    roomDel
} from './room.js'

import {
    messageSendText,
    messageSendImage,
    messageSendFile,
    messageSendPat,
    messageForward,
    getFirstPage,
    getNextPage,
    decryptImage,
    downloadAttach
} from './message.js'

import {
    getDbHandles,
    getMsgDbHandle,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
} from './sqlite.js'

/*
偏移地址
*/
const offsets = {
    kDoAddMsg: 0x2205510, // 3.9.10.27
}

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

let selfInfo: any = {}

const homePath = getHomePath()
log('homePath', 'homePath:', homePath)

selfInfo = getUserInfo()
log('selfInfo', 'selfInfo:', JSON.stringify(selfInfo))

const wxid = getSelfWxid()
log('wxid', 'wxid:', wxid)

// const firstPage = getFirstPage()
// log('firstPage', 'firstPage:', firstPage)

// const nextPage = getNextPage(firstPage)
// log('nextPage', 'nextPage:', nextPage)

/*---------------------Contact---------------------*/

// log('contact', '查询登录状态/checkLogin done:', checkLogin())

// log('contact', '获取登录账号信息/contactSelfInfo done:', JSON.stringify(contactSelfInfo()))

// log('contact', '获取联系人/contactList done:', JSON.stringify(contactList().length))

// log('contact', 'call contactRawPayload() res:\n', JSON.stringify(contactRawPayload('ledongmao')))

/*---------------------Room---------------------*/

// log('room', 'call roomList() res:\n', JSON.stringify(roomList().length))

// log('room', 'call roomRawPayload() res:\n', JSON.stringify(roomRawPayload('21341182572@chatroom')))


// roomTopic('21341182572@chatroom', '大师是群主111')

// roomMemberList('21341182572@chatroom')

/*---------------------Room Invitation---------------------*/


/*---------------------Friendship---------------------*/


/*---------------------Tag---------------------*/


/*---------------------Message---------------------*/
// messageSendText('filehelper', `hello world ${new Date().toLocaleString()}`)
// messageSendText('21341182572@chatroom', `hello world ${new Date().toLocaleString()}`, ['notify@all'])
// messageSendText('21341182572@chatroom', 'hello world all', ['notify@all'])
// messageSendText('21341182572@chatroom', 'hello world', ['ledongmao', 'wxid_pnza7m7kf9tq12'])
// messageSendText('21341182572@chatroom', 'hello world', ['ledongmao'])
// messageSendText('21341182572@chatroom', `hello world ${Math.random().toString(4).substring(2, 4)} ${new Date().toLocaleString()}`, ['ledongmao'])

const path = 'C:\\GitHub\\frida-agent\\agent\\1.jpg'
// messageSendImage('21341182572@chatroom', path)

// messageSendFile('21341182572@chatroom', path)

// messageSendPat('21341182572@chatroom', 'ledongmao')

// roomAdd('25172281579@chatroom', 'ledongmao')
// roomInvite('25172281579@chatroom', 'ledongmao')
// messageSendText('25172281579@chatroom', 'hello world')

// roomDel('21341182572@chatroom', 'ledongmao')
// messageSendText('21341182572@chatroom', 'hello world')

/*---------------------Hook---------------------*/
/*
接收消息回调 3.9.10.27
*/
const recvMsgNativeCallback = (() => {

    const nativeCallback = new NativeCallback(() => { }, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])
    const nativeativeFunction = new NativeFunction(nativeCallback, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])

    try {
        Interceptor.attach(
            moduleBaseAddress.add(offsets.kDoAddMsg), {
            onEnter(args) {
                try {
                    // 参数打印
                    // console.log("doAddMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2]);

                    // 调用处理函数
                    const msg = HandleSyncMsg(args[0], args[1], args[2]);
                    // console.log("msg: " + JSON.stringify(msg, null, 2));
                    let room = ''
                    let talkerId = ''
                    let listenerId = ''
                    const text = msg.content
                    const signature = msg.signature
                    const msgType = msg.type
                    const isSelf = msg.isSelf
                    let filename = ''

                    if (msg.fromUser.indexOf('@') !== -1) {
                        room = msg.fromUser
                    } else if (msg.toUser && msg.toUser.indexOf('@') !== -1) {
                        room = msg.toUser
                        talkerId = msg.fromUser
                    }

                    if (room && msg.toUser) {
                        talkerId = msg.toUser
                    } else if (room && !msg.toUser) {
                        talkerId = ''
                    } else {
                        if (msg.isSelf) {
                            talkerId = ''
                            listenerId = msg.fromUser

                        } else {
                            talkerId = msg.fromUser
                        }
                    }

                    if (msgType === 3) {
                        filename = JSON.parse(msg.content)[0]
                    }

                    if (msgType === 49) {
                        const content = msg.content as string
                        // <title>example_upsert.json</title>\n        <des></des>\n        <action>view</action>\n        <type>6</type>\n   
                        // 使用正则提取出文件名和type
                        const subType = content.match(/<type>(\d+)<\/type>/)
                        if (subType && subType[1] === '6') {
                            const filenames = content.match(/<title>(.*)<\/title>/)
                            if (filenames) {
                                const curTime = new Date()
                                filename = `${selfInfo.id}\\FileStorage\\File\\${curTime.getFullYear()}-${curTime.getMonth() < 9 ? '0' : ''}${curTime.getMonth() + 1}\\${filenames[1]}`
                                console.log('filename:', filename)
                            }
                        }
                    }

                    const message: Message = {
                        id: msg.msgId,
                        filename, // 只有在发送文件时需要
                        text,
                        timestamp: msg.createTime,
                        type: msgType,
                        talkerId,
                        roomId: room,
                        mentionIds: [],
                        listenerId, // 在一对一聊天中使用
                        isSelf,
                    }

                    handleMsg(message)

                    if (room === '21341182572@chatroom' && text === 'ding') {
                        messageSendText(room, 'dong', [talkerId])
                    }
                    console.log('message:', JSON.stringify(message, null, 2))

                    // send(message)
                    const myContentPtr = Memory.alloc(text.length * 2 + 1)
                    myContentPtr.writeUtf16String(text)

                    const myTalkerIdPtr = Memory.alloc(talkerId.length * 2 + 1)
                    myTalkerIdPtr.writeUtf16String(talkerId)

                    const myGroupMsgSenderIdPtr = Memory.alloc(room.length * 2 + 1)
                    myGroupMsgSenderIdPtr.writeUtf16String(room)

                    const myXmlContentPtr = Memory.alloc(signature.length * 2 + 1)
                    myXmlContentPtr.writeUtf16String(signature)

                    const isMyMsg = 0
                    const newMsg = {
                        msgType, talkerId, text, room, signature, isMyMsg
                    }
                    // console.log('agent 回调消息:', JSON.stringify(newMsg))
                    setImmediate(() => nativeativeFunction(msgType, myTalkerIdPtr, myContentPtr, myGroupMsgSenderIdPtr, myXmlContentPtr, isMyMsg))

                } catch (e: any) {
                    console.error('接收消息回调失败：', e)
                    throw new Error(e)
                }
            },
        })
        return nativeCallback
    } catch (e) {
        console.error('回调消息失败：')
        return null
    }

})()

const handleMsg = (msg: Message) => {
    console.log('handleMsg:', JSON.stringify(msg, null, 2))
    const id = msg.id
    const type = msg.type
    const isSelf = msg.isSelf
    const timestamp = msg.timestamp
    const roomId = msg.roomId
    const talkerId = msg.talkerId
    const listenerId = msg.listenerId
    const text = msg.text
    if (msg.type === 3) {
        const filename = `C:\\GitHub\\frida-agent\\agent\\${id}.jpg`
        // 等待5s
        // setTimeout(() => {
        //     const textJson = JSON.parse(text)
        //     console.log('textJson:', textJson)
        //     const thumb = homePath + textJson[1]
        //     console.log('thumb:', thumb)
        //     decryptImage(thumb, filename)
        // }, 5000)
        downloadAttach(Number(id), '', filename)
    }
}

function HandleSyncMsg(param1: NativePointer, param2: any, param3: any) {
    console.log("HandleSyncMsg called with param2: " + param2);
    // findIamgePathAddr(param2)

    /* Receive Message:
        Hook,  call, msgId, type, isSelf, ts, roomId, content, wxid, sign, thumb, extra, msgXml */
    // { 0x00, 0x2205510, 0x30, 0x38, 0x3C, 0x44, 0x48, 0x88, 0x240, 0x260, 0x280, 0x2A0, 0x308 },

    const msg: WeChatMessage = {
        fromUser: '',
        toUser: '',
        content: '',
        signature: '',
        msgId: '',
        msgSequence: 0,
        createTime: 0,
        displayFullContent: '',
        type: 0,
        isSelf: false,
    }

    msg.msgId = param2.add(0x30).readS64() // 消息ID
    // console.log("msg.msgId: " + msg.msgId);
    msg.type = param2.add(0x38).readS32(); // 消息类型
    // console.log("msg.type: " + msg.type);
    msg.isSelf = param2.add(0x3C).readS32() === 1; // 是否自己发送的消息
    // console.log("msg.isSelf: " + msg.isSelf);
    msg.createTime = param2.add(0x44).readS32() // 创建时间
    // console.log("msg.createTime: " + msg.createTime);
    msg.content = readWideString(param2.add(0x88)) // 消息内容
    // console.log("msg.content: " + msg.content);
    msg.toUser = readWideString(param2.add(0x240)) // 消息签名
    // console.log("msg.toUser: " + msg.toUser);
    msg.fromUser = readWideString(param2.add(0x48)) // 发送者
    // console.log("msg.fromUser: " + msg.fromUser);
    msg.signature = ReadWeChatStr(param2.add(0x260)) // 消息签名
    // console.log("msg.signature: " + msg.signature);

    const msgXml = getStringByStrAddr(param2.add(0x308)) // 消息签名
    console.log("msg.msgXml: " + msgXml);

    // 根据消息类型处理图片消息
    if (msg['type'] == 3) {
        const thumb = getStringByStrAddr(param2.add(0x280)) // 消息签名
        // console.log("msg.thumb: " + thumb);

        const extra = getStringByStrAddr(param2.add(0x2A0)) // 消息签名
        // console.log("msg.extra: " + extra);
        // const img = ReadSKBuiltinBuffer(param2.add(0x40).readS64()); // 读取图片数据
        // console.log("img: " + img);
        // msg.base64Img = img; // 将图片数据编码为Base64字符串
        // findIamgePathAddr(param2)
        msg.base64Img = ''
        msg.content = JSON.stringify([
            thumb, //  PUPPET.types.Image.Unknown
            thumb, //  PUPPET.types.Image.Thumbnail
            extra, //  PUPPET.types.Image.HD
            extra, //  PUPPET.types.Image.Artwork
        ])

    }
    // console.log("HandleSyncMsg msg: " + JSON.stringify(msg, null, 2));
    return msg;
}

/*---------------------SQLite---------------------*/
// log('sqlite', 'call getDbHandles() res:\n', JSON.stringify(getDbHandles()))

const dbNames = getDbNames()
// log('sqlite', '获取可查询数据库/getDbNames() done:\n', JSON.stringify(dbNames))

// log('sqlite', '获取数据库所有表/getDbTables() done:\n', JSON.stringify(getDbTables('MicroMsg.db')))

const sql = 'select UserName,Alias,NickName,Remark,LabelIDList,DomainList,ChatRoomType,BigHeadImgUrl,SmallHeadImgUrl,ChatRoomNotify from Contact where NickName!="" limit 2;'

// log('sqlite', 'execDbQuery() done:\n', JSON.stringify(execDbQuery('MicroMsg.db', sql), null, 2))

export {
    checkLogin,
    contactSelfInfo,
    contactList,
    contactRawPayload,
    roomList,
    roomRawPayload,
    messageSendText,
    getDbHandles,
    getMsgDbHandle,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
}
