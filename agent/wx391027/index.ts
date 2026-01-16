/**
 * WeChat 3.9.10.27
 * 
 */
// @ts-ignore
import net from '@frida/net';
// @ts-ignore
import { HTTPParser } from 'http-parser-js';
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

import { offsets } from './offset.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

let selfInfo: any = {}

// 延迟初始化，避免在脚本加载时访问可能未初始化的内存
let homePath = ''
let wxid = ''

// 消息推送配置
interface PushConfig {
    enabled: boolean;
    callbackUrl: string;
}

let pushConfig: PushConfig = {
    enabled: false,
    callbackUrl: ''
}

// 初始化函数，延迟执行
function initializeUserInfo() {
    try {
        homePath = getHomePath()
        log('homePath', 'homePath:', homePath)
    } catch (e) {
        console.error('初始化 homePath 失败:', e)
    }
    
    try {
        selfInfo = getUserInfo()
        log('selfInfo', 'selfInfo:', JSON.stringify(selfInfo))
    } catch (e) {
        console.error('初始化 selfInfo 失败:', e)
        selfInfo = {}
    }
    
    try {
        wxid = getSelfWxid()
        log('wxid', 'wxid:', wxid)
    } catch (e) {
        console.error('初始化 wxid 失败:', e)
        wxid = ''
    }
}

// 延迟执行初始化（在下一个事件循环）
setImmediate(() => {
    try {
        initializeUserInfo()
        // 初始化完成后，再初始化消息 Hook
        setTimeout(() => {
            initializeMessageHook()
        }, 1000) // 延迟1秒，确保微信完全初始化
    } catch (e) {
        console.error('初始化失败:', e)
    }
})

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
// messageSendText('21341182572@chatroom', `hello world ${Math.random().toString(4).substring(2, 4)} ${new Date().toLocaleString()}`, ['tyutluyc'])
// messageSendText('21341182572@chatroom', `hello world ${Math.random().toString(4).substring(2, 4)} ${new Date().toLocaleString()}`, ['ledongmao'])

const path = 'C:\\GitHub\\frida-agent\\agent\\1.jpg'
// messageSendImage('21341182572@chatroom', path)

// messageSendFile('21341182572@chatroom', path)

// messageSendPat('21341182572@chatroom', 'ledongmao')

// roomAdd('25172281579@chatroom', 'ledongmao')
// roomInvite('25172281579@chatroom', 'ledongmao')
// messageSendText('25172281579@chatroom', 'hello world',['notify@all'])

// roomDel('21341182572@chatroom', 'ledongmao')
// messageSendText('21341182572@chatroom', 'hello world')

/*---------------------Hook---------------------*/
/*
接收消息回调 3.9.10.27
延迟初始化，避免在脚本加载时立即 Hook
*/
let recvMsgNativeCallback: any = null;

function initializeMessageHook() {
    try {
        const nativeCallback = new NativeCallback(() => { }, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])
        const nativeativeFunction = new NativeFunction(nativeCallback, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])

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
        recvMsgNativeCallback = nativeCallback
        console.log('消息 Hook 初始化成功')
    } catch (e) {
        console.error('回调消息失败：', e)
        recvMsgNativeCallback = null
    }
}

// 发送消息推送
function sendMessagePush(msg: Message) {
    if (!pushConfig.enabled || !pushConfig.callbackUrl) {
        return;
    }

    try {
        // 解析回调 URL
        const url = pushConfig.callbackUrl;
        const urlMatch = url.match(/^(https?):\/\/([^\/]+)(\/.*)?$/);
        if (!urlMatch) {
            console.error(`[PUSH] [${new Date().toISOString()}] 无效的回调地址: ${url}`);
            return;
        }

        const protocol = urlMatch[1];
        const hostPort = urlMatch[2];
        const path = urlMatch[3] || '/';

        const [host, portStr] = hostPort.split(':');
        const port = portStr ? parseInt(portStr, 10) : (protocol === 'https' ? 443 : 80);

        // 创建 HTTP 请求数据
        const requestBody = JSON.stringify(msg);
        const bodyBytes = stringToUint8Array(requestBody);
        
        const requestText = 
            `POST ${path} HTTP/1.1\r\n` +
            `Host: ${hostPort}\r\n` +
            `Content-Type: application/json; charset=utf-8\r\n` +
            `Content-Length: ${bodyBytes.byteLength}\r\n` +
            `\r\n` +
            requestBody;

        // 创建 TCP 连接并发送请求
        const socket = net.connect({
            host: host,
            port: port
        }, () => {
            console.log(`[PUSH] [${new Date().toISOString()}] 连接到推送服务器: ${host}:${port}`);
            socket.write(requestText);
        });

        let responseReceived = false;
        socket.on('data', (data: any) => {
            // 接收响应（可选，用于调试）
            if (!responseReceived) {
                responseReceived = true;
                const responseText = typeof data === 'string' ? data : uint8ArrayToString(new Uint8Array(data));
                console.log(`[PUSH] [${new Date().toISOString()}] 推送响应:`, responseText.substring(0, 200));
                socket.end();
            }
        });

        socket.on('error', (err: any) => {
            console.error(`[PUSH] [${new Date().toISOString()}] 推送失败:`, err.message || String(err));
        });

        socket.on('close', () => {
            // 连接关闭
        });

        // 设置超时（5秒）
        setTimeout(() => {
            if (!responseReceived) {
                try {
                    socket.destroy();
                } catch (e) {
                    // 忽略销毁错误
                }
                console.error(`[PUSH] [${new Date().toISOString()}] 推送超时`);
            }
        }, 5000);

    } catch (e: any) {
        console.error(`[PUSH] [${new Date().toISOString()}] 推送异常:`, e.message || String(e));
    }
}

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
    
    // 发送消息推送
    if (pushConfig.enabled) {
        sendMessagePush(msg);
    }
    
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

// 延迟执行数据库操作，避免在脚本加载时访问数据库
// const dbNames = getDbNames()
// log('sqlite', '获取可查询数据库/getDbNames() done:\n', JSON.stringify(dbNames))

// log('sqlite', '获取数据库所有表/getDbTables() done:\n', JSON.stringify(getDbTables('MicroMsg.db')))

// const sql = 'select UserName,Alias,NickName,Remark,LabelIDList,DomainList,ChatRoomType,BigHeadImgUrl,SmallHeadImgUrl,ChatRoomNotify from Contact where NickName!="" limit 2;'

// log('sqlite', 'execDbQuery() done:\n', JSON.stringify(execDbQuery('MicroMsg.db', sql), null, 2))

export {
    checkLogin,
    contactSelfInfo,
    contactList,
    contactRawPayload,
    roomList,
    roomRawPayload,
    messageSendText,
    messageSendImage,
    messageSendFile,
    messageSendPat,
    messageForward,
    getDbHandles,
    getMsgDbHandle,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
}

// 添加 RPC 导出（可选，用于 Python 调用）
// 如果只需要 HTTP 控制，可以注释掉这部分
rpc.exports = {
    checkLogin: checkLogin,
    contactSelfInfo: contactSelfInfo,
    contactList: contactList,
    contactRawPayload: contactRawPayload,
    roomList: roomList,
    roomRawPayload: roomRawPayload,
    messageSendText: messageSendText,
    messageSendImage: messageSendImage,
    messageSendFile: messageSendFile,
    messageSendPat: messageSendPat,
    messageForward: messageForward,
    getDbHandles: getDbHandles,
    getMsgDbHandle: getMsgDbHandle,
    getDbNames: getDbNames,
    getDbTables: getDbTables,
    execDbQuery: execDbQuery,
    getLocalIdAndDbIdx: getLocalIdAndDbIdx
} as any

/*---------------------HTTP Server (Node.js Style)---------------------*/

interface HttpResponse {
    code: number;
    data: any;
    msg: string;
}

interface ParsedRequest {
    method: string;
    url: string;
    headers: { [key: string]: string };
    body: string;
    query: { [key: string]: string };
}

function parseHttpRequest(rawRequest: string): ParsedRequest {
    // 首先尝试从请求行手动解析（备用方案）
    const firstLine = rawRequest.split('\r\n')[0];
    let method = '';
    let url = '';
    
    const requestLineMatch = firstLine.match(/(GET|POST|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP/);
    if (requestLineMatch) {
        method = requestLineMatch[1];
        url = requestLineMatch[2];
    }
    
    // 尝试使用 HTTPParser
    try {
        const parser = new HTTPParser(HTTPParser.REQUEST);
        const headersArr: string[] = [];
        let parserMethod: string = '';
        let parserUrl: string = '';
        
        parser[HTTPParser.kOnHeadersComplete] = (info: any) => {
            parserMethod = info.method || '';
            parserUrl = info.url || '';
            if (info.headers) {
                headersArr.push(...info.headers);
            }
        };

        // 在 Frida 环境中，直接使用字符串
        parser.execute(rawRequest as any);
        
        // 如果 HTTPParser 成功解析，使用解析结果
        if (parserMethod && parserUrl) {
            method = parserMethod;
            url = parserUrl;
        }
    } catch (e) {
        console.log('[HTTP] HTTPParser 解析失败，使用手动解析:', e);
    }
    
    // 解析 headers
    const headers: { [key: string]: string } = {};
    const headerLines = rawRequest.split('\r\n').slice(1);
    for (const line of headerLines) {
        if (line === '') break; // 遇到空行，headers 结束
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            headers[key] = value;
        }
    }

    // 解析 query 参数（手动实现，因为 Frida 环境可能没有 URLSearchParams）
    const query: { [key: string]: string } = {};
    const urlParts = url.split('?');
    const path = urlParts[0] || '';
    if (urlParts.length > 1) {
        const queryString = urlParts[1];
        // 手动解析 query 参数
        const pairs = queryString.split('&');
        for (const pair of pairs) {
            const equalIndex = pair.indexOf('=');
            if (equalIndex > 0) {
                let key = pair.substring(0, equalIndex);
                let value = pair.substring(equalIndex + 1);
                // 简单的 URL 解码（处理 %20 等基本编码）
                try {
                    key = key.replace(/\+/g, ' ').replace(/%([0-9A-F]{2})/gi, (match, hex) => {
                        return String.fromCharCode(parseInt(hex, 16));
                    });
                    value = value.replace(/\+/g, ' ').replace(/%([0-9A-F]{2})/gi, (match, hex) => {
                        return String.fromCharCode(parseInt(hex, 16));
                    });
                } catch (e) {
                    // 如果解码失败，使用原始值
                }
                query[key] = value;
            } else if (pair.length > 0) {
                // 没有值的参数
                let key = pair;
                try {
                    key = key.replace(/\+/g, ' ').replace(/%([0-9A-F]{2})/gi, (match, hex) => {
                        return String.fromCharCode(parseInt(hex, 16));
                    });
                } catch (e) {
                    // 如果解码失败，使用原始值
                }
                query[key] = '';
            }
        }
    }

    // 解析 body
    // 首先尝试使用 Content-Length 头部来确定 body 的长度
    let body = '';
    const contentLength = headers['content-length'];
    const bodyStartIndex = rawRequest.indexOf('\r\n\r\n');
    
    if (bodyStartIndex >= 0) {
        const bodyStart = bodyStartIndex + 4; // 跳过 \r\n\r\n
        if (contentLength) {
            // 使用 Content-Length 精确提取 body
            const length = parseInt(contentLength, 10);
            if (!isNaN(length) && length > 0) {
                body = rawRequest.substring(bodyStart, bodyStart + length);
            } else {
                // 如果 Content-Length 无效，使用剩余部分
                body = rawRequest.substring(bodyStart);
            }
        } else {
            // 没有 Content-Length，使用剩余部分
            body = rawRequest.substring(bodyStart);
        }
    }

    return {
        method: method || 'GET',
        url: path,
        headers,
        body: body.trim(),
        query
    };
}

function sendResponse(socket: any, response: HttpResponse, statusCode: number = 200) {
    const responseBody = JSON.stringify(response, null, 2);
    const bodyBytes = stringToUint8Array(responseBody);
    const responseText = 
        `HTTP/1.1 ${statusCode} ${statusCode === 200 ? 'OK' : 'Error'}\r\n` +
        `Content-Type: application/json; charset=utf-8\r\n` +
        `Content-Length: ${bodyBytes.byteLength}\r\n` +
        `Access-Control-Allow-Origin: *\r\n` +
        `Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n` +
        `Access-Control-Allow-Headers: Content-Type\r\n` +
        `\r\n` +
        responseBody;
    
    socket.write(responseText);
}

function handleRequest(req: ParsedRequest): HttpResponse {
    const res: HttpResponse = {
        code: 1,
        data: null,
        msg: 'success'
    };

    try {
        const path = req.url;
        
        // API 路由处理
        if (path === '/api/checkLogin' || path === '/api/checklogin') {
            res.data = checkLogin();
        } 
        else if (path === '/api/contacts/self') {
            res.data = contactSelfInfo();
        } 
        else if (path === '/api/contacts') {
            res.data = contactList();
        } 
        else if (path === '/api/contact') {
            const contactId = req.query.contactId;
            if (contactId) {
                const contactData = contactRawPayload(contactId);
                // 检查是否返回错误对象
                if (contactData && (contactData as any).error) {
                    res.code = 0;
                    res.msg = (contactData as any).message || '获取联系人失败';
                    res.data = contactData;
                } else {
                    res.data = contactData;
                }
            } else {
                res.code = 0;
                res.msg = '参数错误: 需要 contactId';
            }
        } 
        else if (path === '/api/rooms') {
            res.data = roomList();
        } 
        else if (path === '/api/room') {
            const roomId = req.query.roomId;
            if (roomId) {
                const result = roomRawPayload(roomId);
                // 检查返回结果是否包含错误信息
                if (result && typeof result === 'object' && result.error === true) {
                    res.code = 0;
                    res.data = result;
                    res.msg = result.message || '获取群详情失败';
                } else {
                    res.data = result;
                }
            } else {
                res.code = 0;
                res.msg = '参数错误: 需要 roomId';
            }
        } 
        else if (path === '/api/message/text') {
            const startTime = Date.now();
            console.log(`[API] [${new Date().toISOString()}] 收到发送文本消息请求`);
            
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        // 记录 body 的前100个字符用于调试
                        const bodyPreview = req.body.length > 100 ? req.body.substring(0, 100) + '...' : req.body;
                        console.log(`[API] [${new Date().toISOString()}] 解析 body (前100字符):`, bodyPreview);
                        body = JSON.parse(req.body);
                        console.log(`[API] [${new Date().toISOString()}] JSON 解析成功:`, {
                            contactId: body.contactId,
                            textLength: body.text ? body.text.length : 0,
                            atWxids: body.atWxids
                        });
                    }
                } catch (e: any) {
                    console.error(`[API] [${new Date().toISOString()}] JSON 解析失败:`, e);
                    console.error(`[API] [${new Date().toISOString()}] Body 内容:`, req.body);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                
                if (body.contactId && body.text) {
                    console.log(`[API] [${new Date().toISOString()}] 准备调用 messageSendText:`, {
                        contactId: body.contactId,
                        textPreview: body.text.length > 50 ? body.text.substring(0, 50) + '...' : body.text,
                        atWxids: body.atWxids
                    });
                    
                    try {
                        const callStartTime = Date.now();
                        console.log(`[API] [${new Date().toISOString()}] 开始调用 messageSendText...`);
                        res.data = messageSendText(body.contactId, body.text, body.atWxids);
                        const callEndTime = Date.now();
                        const callDuration = callEndTime - callStartTime;
                        console.log(`[API] [${new Date().toISOString()}] messageSendText 调用完成，耗时: ${callDuration}ms，返回值:`, res.data);
                    } catch (e: any) {
                        console.error(`[API] [${new Date().toISOString()}] messageSendText 调用异常:`, e);
                        console.error(`[API] [${new Date().toISOString()}] 异常堆栈:`, e.stack);
                        res.code = 0;
                        res.msg = `发送消息失败: ${e.message || String(e)}`;
                        res.data = null;
                    }
                } else {
                    console.error(`[API] [${new Date().toISOString()}] 参数错误:`, {
                        hasContactId: !!body.contactId,
                        hasText: !!body.text
                    });
                    res.code = 0;
                    res.msg = '参数错误: 需要 contactId 和 text';
                }
            } else {
                console.error(`[API] [${new Date().toISOString()}] 方法错误: 需要使用 POST，当前方法:`, req.method);
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
            
            const endTime = Date.now();
            const totalDuration = endTime - startTime;
            console.log(`[API] [${new Date().toISOString()}] /api/message/text 处理完成，总耗时: ${totalDuration}ms`);
        } 
        else if (path === '/api/message/image') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.contactId && body.path) {
                    res.data = messageSendImage(body.contactId, body.path);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 contactId 和 path（图片文件路径）';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        } 
        else if (path === '/api/message/file') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.contactId && body.path) {
                    res.data = messageSendFile(body.contactId, body.path);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 contactId 和 path（文件路径）';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        } 
        else if (path === '/api/message/pat') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.roomId && body.contactId) {
                    res.data = messageSendPat(body.roomId, body.contactId);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 roomId 和 contactId';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        } 
        else if (path === '/api/message/forward') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.msgId && body.receiver) {
                    res.data = messageForward(body.msgId, body.receiver);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 msgId 和 receiver';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        } 
        else if (path === '/api/db/names') {
            res.data = getDbNames();
        } 
        else if (path === '/api/db/tables') {
            const dbName = req.query.dbName;
            if (dbName) {
                res.data = getDbTables(dbName);
            } else {
                res.code = 0;
                res.msg = '参数错误: 需要 dbName';
            }
        } 
        else if (path === '/api/db/query') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.dbName && body.sql) {
                    res.data = execDbQuery(body.dbName, body.sql);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 dbName 和 sql';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        } 
        else if (path === '/api/push/config') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) {
                        body = JSON.parse(req.body);
                    }
                } catch (e: any) {
                    console.error('[HTTP] JSON 解析失败:', e);
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                
                // 验证参数
                if (body.enabled === undefined) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 enabled 字段';
                    return res;
                }
                
                // 如果开启推送，必须提供回调地址
                if (body.enabled === true) {
                    if (!body.callbackUrl || typeof body.callbackUrl !== 'string' || body.callbackUrl.trim() === '') {
                        res.code = 0;
                        res.msg = '参数错误: 开启推送时必须提供 callbackUrl';
                        return res;
                    }
                    
                    // 验证 URL 格式
                    const urlPattern = /^https?:\/\/.+/;
                    if (!urlPattern.test(body.callbackUrl)) {
                        res.code = 0;
                        res.msg = '参数错误: callbackUrl 格式不正确，应为 http:// 或 https:// 开头的完整 URL';
                        return res;
                    }
                    
                    pushConfig.enabled = true;
                    pushConfig.callbackUrl = body.callbackUrl.trim();
                    console.log(`[PUSH] [${new Date().toISOString()}] 推送已开启，回调地址: ${pushConfig.callbackUrl}`);
                } else {
                    // 关闭推送时，可以只传递 enabled: false
                    pushConfig.enabled = false;
                    // 如果提供了 callbackUrl，也更新它（可选）
                    if (body.callbackUrl && typeof body.callbackUrl === 'string') {
                        pushConfig.callbackUrl = body.callbackUrl.trim();
                    }
                    console.log(`[PUSH] [${new Date().toISOString()}] 推送已关闭`);
                }
                
                res.data = {
                    enabled: pushConfig.enabled,
                    callbackUrl: pushConfig.callbackUrl
                };
            } else if (req.method === 'GET') {
                // 获取当前推送配置
                res.data = {
                    enabled: pushConfig.enabled,
                    callbackUrl: pushConfig.callbackUrl
                };
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST 或 GET';
            }
        } 
        else if (path === '/api/health' || path === '/') {
            res.data = {
                status: 'ok',
                timestamp: new Date().toISOString(),
                apis: [
                    'GET /api/checkLogin',
                    'GET /api/contacts/self',
                    'GET /api/contacts',
                    'GET /api/contact?contactId=xxx',
                    'GET /api/rooms',
                    'GET /api/room?roomId=xxx',
                    'POST /api/message/text',
                    'GET /api/db/names',
                    'GET /api/db/tables?dbName=xxx',
                    'POST /api/db/query',
                    'GET /api/push/config',
                    'POST /api/push/config'
                ]
            };
        } 
        else {
            res.code = 0;
            res.msg = `未知的 API 端点: ${path}`;
        }
    } catch (e: any) {
        res.code = 0;
        res.msg = `错误: ${e.message || String(e)}`;
        console.error('[HTTP] 处理错误:', e);
    }

    return res;
}

// 创建 HTTP 服务器
console.log(`[HTTP] [${new Date().toISOString()}] 开始创建 HTTP 服务器...`);

// 确保 Buffer 可用
let Buffer: any;
try {
    // 尝试使用全局 Buffer（在 Frida 环境中，Buffer 可能不可用）
    // 使用 eval 来避免 TypeScript 类型检查错误
    Buffer = (eval('typeof Buffer !== "undefined" ? Buffer : null') as any) || null;
    if (!Buffer) {
        // 如果 Buffer 不可用，创建一个简单的实现
        console.log(`[HTTP] [${new Date().toISOString()}] Buffer 不可用，使用 Uint8Array 替代`);
    }
} catch (e) {
    console.log(`[HTTP] [${new Date().toISOString()}] Buffer 初始化失败，使用 Uint8Array 替代`);
}

const server = net.createServer((socket: any) => {
    console.log(`[HTTP] [${new Date().toISOString()}] 收到新的客户端连接`);
    let requestBuffer: any = new Uint8Array(0);
    let expectedBodyLength = -1;
    let headerEndIndex = -1;

    socket.on('data', (data: any) => {
        try {
            // 将数据转换为 Uint8Array
            let dataArray: Uint8Array;
            if (data instanceof Uint8Array) {
                dataArray = data;
            } else if (Buffer && Buffer.isBuffer && Buffer.isBuffer(data)) {
                dataArray = new Uint8Array(data);
            } else if (data instanceof ArrayBuffer) {
                dataArray = new Uint8Array(data);
            } else {
                // 尝试转换为字符串再编码
                const str = String(data);
                dataArray = new Uint8Array(str.length);
                for (let i = 0; i < str.length; i++) {
                    dataArray[i] = str.charCodeAt(i);
                }
            }
            
            // 拼接缓冲区
            const newBuffer = new Uint8Array(requestBuffer.length + dataArray.length);
            newBuffer.set(requestBuffer, 0);
            newBuffer.set(dataArray, requestBuffer.length);
            requestBuffer = newBuffer;
        
        } catch (e: any) {
            console.error(`[HTTP] [${new Date().toISOString()}] 处理数据错误:`, e);
            return;
        }
        
        // 检查是否已经找到 header 结束位置
        if (headerEndIndex < 0) {
            // 查找 header 结束标记 \r\n\r\n (字节序列: 0x0D 0x0A 0x0D 0x0A)
            for (let i = 0; i <= requestBuffer.length - 4; i++) {
                if (requestBuffer[i] === 0x0D && 
                    requestBuffer[i + 1] === 0x0A && 
                    requestBuffer[i + 2] === 0x0D && 
                    requestBuffer[i + 3] === 0x0A) {
                    headerEndIndex = i;
                    
                    // 解析 header 获取 Content-Length
                    const headerBytes = requestBuffer.subarray(0, i);
                    const headerText = uint8ArrayToString(headerBytes);
                    const contentLengthMatch = headerText.match(/content-length:\s*(\d+)/i);
                    if (contentLengthMatch) {
                        expectedBodyLength = parseInt(contentLengthMatch[1], 10);
                    } else {
                        expectedBodyLength = 0; // 没有 body
                    }
                    break;
                }
            }
        }
        
        // 检查请求是否完整
        const isComplete = headerEndIndex >= 0 && (
            expectedBodyLength === 0 || // 没有 body
            (requestBuffer.length >= headerEndIndex + 4 + expectedBodyLength) // body 已完整接收
        );
        
        if (isComplete) {
            try {
                // 将 Uint8Array 转换为字符串（使用 utf-8 编码）
                const bodyStart = headerEndIndex + 4;
                const headerBytes = requestBuffer.subarray(0, headerEndIndex);
                const bodyBytes = expectedBodyLength > 0 
                    ? requestBuffer.subarray(bodyStart, bodyStart + expectedBodyLength)
                    : new Uint8Array(0);
                
                const headerText = uint8ArrayToString(headerBytes);
                const bodyText = expectedBodyLength > 0 ? uint8ArrayToString(bodyBytes) : '';
                const requestText = headerText + '\r\n\r\n' + bodyText;
                
                // 调试：打印原始请求（前500字符）
                const requestPreview = requestText.length > 500 ? requestText.substring(0, 500) + '...' : requestText;
                console.log('[HTTP] 收到请求:\n', requestPreview);
                
                const req = parseHttpRequest(requestText);
                
                // 调试：打印解析结果
                console.log('[HTTP] 解析结果:', {
                    method: req.method,
                    url: req.url,
                    hasQuery: Object.keys(req.query).length > 0,
                    bodyLength: req.body ? req.body.length : 0
                });
                
                // 如果 URL 为空，尝试从原始请求中提取
                if (!req.url || req.url === '') {
                    const firstLine = requestText.split('\r\n')[0];
                    const match = firstLine.match(/(GET|POST|PUT|DELETE|OPTIONS)\s+(\S+)/);
                    if (match) {
                        req.url = match[2].split('?')[0];
                        console.log('[HTTP] 从请求行提取 URL:', req.url);
                    }
                }
                
                log('HTTP', `${req.method} ${req.url}`);
                
                const res = handleRequest(req);
                sendResponse(socket, res);
            } catch (e: any) {
                console.error('[HTTP] 解析请求错误:', e);
                console.error('[HTTP] 错误堆栈:', e.stack);
                sendResponse(socket, {
                    code: 0,
                    data: null,
                    msg: `解析请求失败: ${e.message || String(e)}`
                }, 400);
            }
            
            // 重置缓冲区
            requestBuffer = new Uint8Array(0);
            expectedBodyLength = -1;
            headerEndIndex = -1;
            socket.end();
        }
    });

    socket.on('error', (err: any) => {
        console.error('[HTTP] Socket 错误:', err);
    });

    socket.on('close', () => {
        // 连接关闭
    });
});

// 启动服务器（延迟启动，确保脚本完全加载）
const HTTP_PORT = 19088;

function startHttpServer() {
    console.log(`[HTTP] [${new Date().toISOString()}] 准备启动 HTTP 服务器，端口: ${HTTP_PORT}`);
    
    try {
        server.on('error', (err: any) => {
            console.error(`[HTTP] [${new Date().toISOString()}] 服务器错误:`, err);
            if (err.code === 'EADDRINUSE') {
                console.error(`[HTTP] [${new Date().toISOString()}] 端口 ${HTTP_PORT} 已被占用，请检查是否有其他进程在使用该端口`);
            }
        });
        
        server.on('listening', () => {
            console.log(`[HTTP] [${new Date().toISOString()}] 服务器正在监听端口 ${HTTP_PORT}`);
        });
        
        server.listen(HTTP_PORT, '0.0.0.0', () => {
            console.log(`[HTTP] [${new Date().toISOString()}] ✓ 服务器已成功启动，监听端口 ${HTTP_PORT}`);
            console.log(`[HTTP] [${new Date().toISOString()}] ✓ 访问 http://localhost:${HTTP_PORT}/api/health 查看 API 列表`);
            console.log(`[HTTP] [${new Date().toISOString()}] ✓ 服务器地址: http://0.0.0.0:${HTTP_PORT}`);
        });
        
        // 添加超时检查
        setTimeout(() => {
            try {
                // 检查服务器是否在监听
                const isListening = server.listening;
                if (!isListening) {
                    console.error(`[HTTP] [${new Date().toISOString()}] ✗ 服务器启动超时，可能启动失败`);
                } else {
                    console.log(`[HTTP] [${new Date().toISOString()}] ✓ 服务器状态确认：正在运行 (listening: ${isListening})`);
                }
            } catch (e: any) {
                console.error(`[HTTP] [${new Date().toISOString()}] ✗ 检查服务器状态失败:`, e);
            }
        }, 1000);
    } catch (e: any) {
        console.error(`[HTTP] [${new Date().toISOString()}] ✗ 启动服务器失败:`, e);
        console.error(`[HTTP] [${new Date().toISOString()}] ✗ 错误堆栈:`, e.stack);
    }
}

// 延迟启动服务器，确保脚本完全加载
setImmediate(() => {
    console.log(`[HTTP] [${new Date().toISOString()}] 延迟启动 HTTP 服务器...`);
    startHttpServer();
});