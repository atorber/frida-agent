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
    parseAppMsg,
    getFileNameFromAppMsg,
} from './appMsgParser.js'

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
    roomDel,
    roomTopic,
} from './room.js'

import {
    messageSendText,
    messageSendImage,
    messageSendFile,
    messageSendPat,
    messageForward,
    messageSendRichText,
    messageSendEmotion,
    getFirstPage,
    getNextPage,
    decryptImage,
    downloadAttach,
    refreshPyq,
    getAudio,
    getMsgTypes,
} from './message.js'
import {
    downloadFinderFeedVideo,
    buildFinderVideoSavePath,
} from './httpDownload.js'

import {
    getDbHandles,
    getMsgDbHandle,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
} from './sqlite.js'

import {
    enableRecvMsg,
    disableRecvMsg,
    listenPyq,
    unListenPyq,
    isRecvMsgEnabled,
    isRecvPyqEnabled,
    setMsgHandler,
} from './recv.js'

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
        setTimeout(() => {
            initializeMessageHook()
        }, 1000)
    } catch (e) {
        console.error('初始化失败:', e)
    }
})

/*---------------------Hook---------------------*/
function onRecvChatMessage(msg: Message) {
    try {
        if (msg.type === 49) {
            const appMsg = parseAppMsg(msg.text) ?? undefined
            msg.appMsg = appMsg
            if (appMsg?.subType === 6) {
                const filename = getFileNameFromAppMsg(msg.text, selfInfo.id) ?? ''
                if (filename) {
                    msg.filename = filename
                    console.log('filename:', filename)
                }
            }
        }
        handleMsg(msg)
    } catch (e) {
        console.error('处理接收消息失败：', e)
    }
}

function onRecvPyqMessage(msg: Message) {
    console.log('朋友圈消息:', JSON.stringify(msg, null, 2))
    if (pushConfig.enabled) {
        sendMessagePush(msg)
    }
}

function initializeMessageHook() {
    setMsgHandler(onRecvChatMessage)
    const ok = enableRecvMsg(onRecvChatMessage)
    if (!ok) {
        console.error('消息 Hook 初始化失败')
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

    if (msg.type === 49 && msg.appMsg?.subType === 51 && msg.appMsg.finderFeed) {
        const feed = msg.appMsg.finderFeed
        const media = feed.mediaList[0]
        const savePath = buildFinderVideoSavePath(id)
        console.log('视频号消息:', JSON.stringify({
            nickname: feed.nickname,
            desc: feed.desc,
            avatar: feed.avatar,
            objectId: feed.objectId,
            username: feed.username,
            videoUrl: media?.url,
            coverUrl: media?.coverUrl,
            duration: media?.videoPlayDuration,
            width: media?.width,
            height: media?.height,
            savePath,
        }, null, 2))

        if (media?.url) {
            downloadFinderFeedVideo(id, media.url, savePath)
                .then(path => console.log('视频号视频下载完成:', path))
                .catch(err => console.error('视频号视频下载失败:', err.message || err))
        }
    }
 
}

/*---------------------SQLite / Export---------------------*/
export {
    checkLogin,
    contactSelfInfo,
    contactList,
    contactRawPayload,
    roomList,
    roomRawPayload,
    roomAdd,
    roomInvite,
    roomDel,
    roomTopic,
    messageSendText,
    messageSendImage,
    messageSendFile,
    messageSendPat,
    messageForward,
    messageSendRichText,
    messageSendEmotion,
    downloadAttach,
    decryptImage,
    getAudio,
    refreshPyq,
    getMsgTypes,
    enableRecvMsg,
    disableRecvMsg,
    listenPyq,
    unListenPyq,
    getDbHandles,
    getMsgDbHandle,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
}

rpc.exports = {
    checkLogin: checkLogin,
    contactSelfInfo: contactSelfInfo,
    contactList: contactList,
    contactRawPayload: contactRawPayload,
    roomList: roomList,
    roomRawPayload: roomRawPayload,
    roomAdd: roomAdd,
    roomInvite: roomInvite,
    roomDel: roomDel,
    roomTopic: roomTopic,
    messageSendText: messageSendText,
    messageSendImage: messageSendImage,
    messageSendFile: messageSendFile,
    messageSendPat: messageSendPat,
    messageForward: messageForward,
    messageSendRichText: messageSendRichText,
    messageSendEmotion: messageSendEmotion,
    downloadAttach: downloadAttach,
    decryptImage: decryptImage,
    getAudio: getAudio,
    refreshPyq: refreshPyq,
    getMsgTypes: getMsgTypes,
    enableRecvMsg: enableRecvMsg,
    disableRecvMsg: disableRecvMsg,
    listenPyq: listenPyq,
    unListenPyq: unListenPyq,
    isRecvMsgEnabled: isRecvMsgEnabled,
    isRecvPyqEnabled: isRecvPyqEnabled,
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
        else if (path === '/api/message/richText') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (!body.receiver) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 receiver';
                } else {
                    res.data = messageSendRichText(body);
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/emotion') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.contactId && body.path) {
                    res.data = messageSendEmotion(body.contactId, body.path);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 contactId 和 path';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/downloadAttach') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.msgId === undefined || body.msgId === null) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 msgId';
                } else {
                    res.data = downloadAttach(Number(body.msgId), body.thumb || '', body.extra || '');
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/decryptImage') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (!body.src) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 src';
                } else {
                    const out = decryptImage(body.src, body.dir || '');
                    if (!out) {
                        res.code = 0;
                        res.msg = '解密失败';
                    }
                    res.data = out;
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/audio') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.msgId === undefined || !body.dir) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 msgId 和 dir';
                } else {
                    const out = getAudio(Number(body.msgId), body.dir);
                    if (!out) {
                        res.code = 0;
                        res.msg = '获取语音失败';
                    }
                    res.data = out;
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/types') {
            res.data = getMsgTypes();
        }
        else if (path === '/api/message/listen') {
            if (req.method === 'POST') {
                let body: any = { enabled: true };
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.enabled === false) {
                    res.data = { enabled: disableRecvMsg() ? false : isRecvMsgEnabled() };
                } else {
                    res.data = { enabled: enableRecvMsg(onRecvChatMessage) };
                }
            } else {
                res.data = { enabled: isRecvMsgEnabled() };
            }
        }
        else if (path === '/api/sns/listen') {
            if (req.method === 'POST') {
                let body: any = { enabled: true };
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.enabled === false) {
                    res.data = { enabled: unListenPyq() ? false : isRecvPyqEnabled() };
                } else {
                    res.data = { enabled: listenPyq(onRecvPyqMessage) };
                }
            } else {
                res.data = { enabled: isRecvPyqEnabled() };
            }
        }
        else if (path === '/api/sns/refresh') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (!isRecvPyqEnabled()) {
                    res.code = 0;
                    res.msg = '请先开启朋友圈接收: POST /api/sns/listen {"enabled":true}';
                } else {
                    const id = body.id !== undefined ? Number(body.id) : 0;
                    res.data = refreshPyq(id);
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/room/add') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.roomId && body.wxids) {
                    res.data = roomAdd(body.roomId, body.wxids);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 roomId 和 wxids（逗号分隔）';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/room/del') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.roomId && body.wxids) {
                    res.data = roomDel(body.roomId, body.wxids);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 roomId 和 wxids（逗号分隔）';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/room/invite') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.roomId && body.wxids) {
                    res.data = roomInvite(body.roomId, body.wxids);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 roomId 和 wxids（逗号分隔）';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/room/topic') {
            if (req.method === 'POST') {
                let body: any = {};
                try {
                    if (req.body) body = JSON.parse(req.body);
                } catch (e: any) {
                    res.code = 0;
                    res.msg = `JSON 解析失败: ${e.message || String(e)}`;
                    return res;
                }
                if (body.roomId && body.topic !== undefined) {
                    res.data = roomTopic(body.roomId, body.topic);
                } else {
                    res.code = 0;
                    res.msg = '参数错误: 需要 roomId 和 topic';
                }
            } else {
                res.code = 0;
                res.msg = '方法错误: 需要使用 POST';
            }
        }
        else if (path === '/api/message/downloadFinderVideo') {
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
                if (!body.url) {
                    res.code = 0;
                    res.msg = '参数错误: 需要 url';
                    return res;
                }
                const savePath = body.savePath || buildFinderVideoSavePath(body.msgId || String(Date.now()));
                downloadFinderFeedVideo(body.msgId || 'manual', body.url, savePath)
                    .then(path => console.log('[API] 视频号视频下载完成:', path))
                    .catch(err => console.error('[API] 视频号视频下载失败:', err.message || err));
                res.data = { savePath, status: 'downloading' };
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
                    'POST /api/room/add',
                    'POST /api/room/del',
                    'POST /api/room/invite',
                    'POST /api/room/topic',
                    'POST /api/message/text',
                    'POST /api/message/image',
                    'POST /api/message/file',
                    'POST /api/message/emotion',
                    'POST /api/message/richText',
                    'POST /api/message/pat',
                    'POST /api/message/forward',
                    'POST /api/message/downloadAttach',
                    'POST /api/message/decryptImage',
                    'POST /api/message/audio',
                    'GET /api/message/types',
                    'GET|POST /api/message/listen',
                    'POST /api/message/downloadFinderVideo',
                    'GET|POST /api/sns/listen',
                    'POST /api/sns/refresh',
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