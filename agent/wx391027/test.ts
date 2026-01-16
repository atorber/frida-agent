/**
 * WeChat 3.9.10.27 测试脚本
 * 
 * 使用方法:
 * 1. 编译: npm run watch:wx391027:test
 * 2. 运行: npm run start:wx391027:test
 * 
 * 或者手动运行:
 * frida-compile agent/wx391027/test.ts -o agent/wx391027/test.js -w
 * frida -l agent/wx391027/test.js WeChat.exe
 */

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
    getNextPage
} from './message.js'

import {
    getDbHandles,
    getDbNames,
    getDbTables,
    execDbQuery,
    getLocalIdAndDbIdx
} from './sqlite.js'

import {
    readWideString,
    ReadWeChatStr,
    getStringByStrAddr,
    WeChatMessage
} from './utils.js'

import {
    Message
} from './types.js'

// ==================== 测试配置 ====================
const TEST_CONFIG = {
    // 测试消息接收者 (可以是 filehelper 或其他联系人)
    testContactId: 'filehelper',
    // 测试群聊ID (请替换为你的测试群)
    testRoomId: '',  // 例如: '12345678@chatroom'
    // 测试图片路径 (请替换为实际路径)
    testImagePath: 'C:\\GitHub\\frida-agent\\agent\\1.jpg',
    // 是否运行消息发送测试 (可能会发送实际消息)
    enableSendTests: true,
    // 是否运行群聊操作测试 (可能会修改群成员)
    enableRoomTests: false,
}

// ==================== 测试工具函数 ====================
const TestUtils = {
    passed: 0,
    failed: 0,
    skipped: 0,

    log(category: string, message: string, data?: any) {
        const timestamp = new Date().toLocaleTimeString()
        if (data !== undefined) {
            console.log(`[${timestamp}] [${category}] ${message}`, typeof data === 'object' ? JSON.stringify(data, null, 2) : data)
        } else {
            console.log(`[${timestamp}] [${category}] ${message}`)
        }
    },

    assert(condition: boolean, testName: string, details?: string) {
        if (condition) {
            this.passed++
            console.log(`✅ PASS: ${testName}`)
        } else {
            this.failed++
            console.log(`❌ FAIL: ${testName}${details ? ` - ${details}` : ''}`)
        }
    },

    skip(testName: string, reason: string) {
        this.skipped++
        console.log(`⏭️ SKIP: ${testName} - ${reason}`)
    },

    summary() {
        console.log('\n' + '='.repeat(50))
        console.log('📊 测试结果汇总')
        console.log('='.repeat(50))
        console.log(`✅ 通过: ${this.passed}`)
        console.log(`❌ 失败: ${this.failed}`)
        console.log(`⏭️ 跳过: ${this.skipped}`)
        console.log(`📝 总计: ${this.passed + this.failed + this.skipped}`)
        console.log('='.repeat(50))
    }
}

// ==================== 测试用例 ====================

/**
 * 测试登录模块
 */
function testLoginModule() {
    console.log('\n' + '='.repeat(50))
    console.log('🔐 测试登录模块')
    console.log('='.repeat(50))

    // 测试1: 检查登录状态
    try {
        const loginStatus = checkLogin()
        TestUtils.log('Login', '登录状态:', loginStatus)
        TestUtils.assert(loginStatus === 1, 'checkLogin() 返回已登录状态')
    } catch (e) {
        TestUtils.assert(false, 'checkLogin()', String(e))
    }

    // 测试2: 获取数据目录
    try {
        const homePath = getHomePath()
        TestUtils.log('Login', '数据目录:', homePath)
        TestUtils.assert(homePath.length > 0, 'getHomePath() 返回有效路径')
    } catch (e) {
        TestUtils.assert(false, 'getHomePath()', String(e))
    }

    // 测试3: 获取当前用户wxid
    try {
        const wxid = getSelfWxid()
        TestUtils.log('Login', '当前wxid:', wxid)
        TestUtils.assert(wxid.length > 0 && wxid !== 'empty_wxid', 'getSelfWxid() 返回有效wxid')
    } catch (e) {
        TestUtils.assert(false, 'getSelfWxid()', String(e))
    }

    // 测试4: 获取用户完整信息
    try {
        const userInfo = getUserInfo()
        TestUtils.log('Login', '用户信息:', userInfo)
        TestUtils.assert(userInfo.wxid.length > 0, 'getUserInfo() 返回有效用户信息')
    } catch (e) {
        TestUtils.assert(false, 'getUserInfo()', String(e))
    }
}

/**
 * 测试联系人模块
 */
function testContactModule() {
    console.log('\n' + '='.repeat(50))
    console.log('👥 测试联系人模块')
    console.log('='.repeat(50))

    // 测试1: 获取自己的信息
    try {
        const selfInfo = contactSelfInfo()
        TestUtils.log('Contact', '自己的信息:', selfInfo)
        const hasValidId = selfInfo !== null && selfInfo !== undefined && 
                          typeof selfInfo.id === 'string' && selfInfo.id.length > 0
        TestUtils.assert(hasValidId, 'contactSelfInfo() 返回有效信息')
    } catch (e) {
        TestUtils.assert(false, 'contactSelfInfo()', String(e))
    }

    // 测试2: 获取联系人列表
    try {
        const contacts = contactList()
        TestUtils.log('Contact', `联系人数量: ${contacts.length}`)
        TestUtils.assert(Array.isArray(contacts), 'contactList() 返回数组')
        TestUtils.assert(contacts.length >= 0, 'contactList() 返回联系人列表')
        
        // 打印前3个联系人
        if (contacts.length > 0) {
            TestUtils.log('Contact', '前3个联系人:', contacts.slice(0, 3).map(c => ({ id: c.id, name: c.name })))
        }
    } catch (e) {
        TestUtils.assert(false, 'contactList()', String(e))
    }

    // 测试3: 获取指定联系人详情 (使用一个真实存在的联系人，而不是filehelper)
    // filehelper 是系统特殊联系人，可能无法通过 GetContact 获取
    try {
        // 先尝试使用联系人列表中的第一个联系人
        const contacts = contactList()
        if (contacts.length > 0) {
            const testContactId = contacts[0].id
            const contact = contactRawPayload(testContactId)
            TestUtils.log('Contact', `${testContactId}详情:`, contact)
            TestUtils.assert(contact !== null, `contactRawPayload(${testContactId}) 返回联系人详情`)
        } else {
            TestUtils.skip('contactRawPayload()', '没有可用的联系人进行测试')
        }
    } catch (e) {
        TestUtils.assert(false, 'contactRawPayload()', String(e))
    }
}

/**
 * 测试群聊模块
 */
function testRoomModule() {
    console.log('\n' + '='.repeat(50))
    console.log('💬 测试群聊模块')
    console.log('='.repeat(50))

    // 测试1: 获取群聊列表
    let rooms: any[] = []
    try {
        rooms = roomList()
        TestUtils.log('Room', `群聊数量: ${rooms.length}`)
        TestUtils.assert(Array.isArray(rooms), 'roomList() 返回数组')
        
        // 打印前3个群聊
        if (rooms.length > 0) {
            TestUtils.log('Room', '前3个群聊:', rooms.slice(0, 3).map(r => ({ id: r.id, topic: r.topic })))
        }
    } catch (e) {
        TestUtils.assert(false, 'roomList()', String(e))
    }

    // 测试2: 获取指定群聊详情
    if (rooms.length > 0) {
        try {
            const roomId = rooms[0].id
            const room = roomRawPayload(roomId)
            TestUtils.log('Room', `群聊 ${roomId} 详情:`, room)
            TestUtils.assert(room !== null, 'roomRawPayload() 返回群聊详情')
        } catch (e) {
            TestUtils.assert(false, 'roomRawPayload()', String(e))
        }
    } else {
        TestUtils.skip('roomRawPayload()', '没有可用的群聊')
    }

    // 测试3: 群成员操作 (需要配置且启用)
    if (TEST_CONFIG.enableRoomTests && TEST_CONFIG.testRoomId) {
        TestUtils.log('Room', '群成员操作测试已启用但未实现具体测试')
    } else {
        TestUtils.skip('群成员操作测试', '未启用或未配置测试群')
    }
}

/**
 * 测试消息模块
 */
function testMessageModule() {
    console.log('\n' + '='.repeat(50))
    console.log('📨 测试消息模块')
    console.log('='.repeat(50))

    if (!TEST_CONFIG.enableSendTests) {
        TestUtils.skip('messageSendText()', '消息发送测试未启用')
        TestUtils.skip('messageSendImage()', '消息发送测试未启用')
        TestUtils.skip('messageSendFile()', '消息发送测试未启用')
        TestUtils.skip('messageSendPat()', '消息发送测试未启用')
        return
    }

    // 测试1: 发送文本消息
    try {
        const timestamp = new Date().toLocaleString()
        const result = messageSendText(TEST_CONFIG.testContactId, `[测试消息] ${timestamp}`)
        TestUtils.log('Message', `发送文本消息结果: ${result}`)
        TestUtils.assert(result >= 0, 'messageSendText() 发送成功')
    } catch (e) {
        TestUtils.assert(false, 'messageSendText()', String(e))
    }

    // 测试2: 发送图片消息
    try {
        const result = messageSendImage(TEST_CONFIG.testContactId, TEST_CONFIG.testImagePath)
        TestUtils.log('Message', `发送图片消息结果: ${result}`)
        TestUtils.assert(result >= 0, 'messageSendImage() 发送成功')
    } catch (e) {
        TestUtils.assert(false, 'messageSendImage()', String(e))
    }

    // 测试3: 发送文件消息
    try {
        const result = messageSendFile(TEST_CONFIG.testContactId, TEST_CONFIG.testImagePath)
        TestUtils.log('Message', `发送文件消息结果: ${result}`)
        TestUtils.assert(result >= 0, 'messageSendFile() 发送成功')
    } catch (e) {
        TestUtils.assert(false, 'messageSendFile()', String(e))
    }

    // 测试4: 发送拍一拍 (仅群聊)
    if (TEST_CONFIG.testRoomId) {
        try {
            const wxid = getSelfWxid()
            const result = messageSendPat(TEST_CONFIG.testRoomId, wxid)
            TestUtils.log('Message', `发送拍一拍结果: ${result}`)
            TestUtils.assert(result >= 0, 'messageSendPat() 发送成功')
        } catch (e) {
            TestUtils.assert(false, 'messageSendPat()', String(e))
        }
    } else {
        TestUtils.skip('messageSendPat()', '未配置测试群')
    }
}

/**
 * 测试SQLite模块
 */
function testSQLiteModule() {
    console.log('\n' + '='.repeat(50))
    console.log('🗄️ 测试SQLite模块')
    console.log('='.repeat(50))

    // 测试1: 获取数据库句柄
    try {
        const handles = getDbHandles()
        // getDbHandles() 返回 Map 对象，使用 size 属性获取数量
        const handleCount = handles.size
        TestUtils.log('SQLite', '数据库句柄数量:', handleCount)
        TestUtils.assert(handleCount > 0, 'getDbHandles() 返回数据库句柄')
    } catch (e) {
        TestUtils.assert(false, 'getDbHandles()', String(e))
    }

    // 测试2: 获取数据库名列表
    let dbNames: string[] = []
    try {
        dbNames = getDbNames()
        TestUtils.log('SQLite', '数据库列表:', dbNames)
        TestUtils.assert(dbNames.length > 0, 'getDbNames() 返回数据库列表')
    } catch (e) {
        TestUtils.assert(false, 'getDbNames()', String(e))
    }

    // 测试3: 获取表列表
    if (dbNames.includes('MicroMsg.db')) {
        try {
            const tables = getDbTables('MicroMsg.db')
            TestUtils.log('SQLite', 'MicroMsg.db 表数量:', tables.length)
            TestUtils.assert(tables.length > 0, 'getDbTables() 返回表列表')
        } catch (e) {
            TestUtils.assert(false, 'getDbTables()', String(e))
        }
    } else {
        TestUtils.skip('getDbTables()', 'MicroMsg.db 不存在')
    }

    // 测试4: 执行SQL查询
    if (dbNames.includes('MicroMsg.db')) {
        try {
            const sql = 'SELECT UserName, NickName FROM Contact LIMIT 3'
            const results = execDbQuery('MicroMsg.db', sql)
            TestUtils.log('SQLite', '查询结果:', results)
            TestUtils.assert(Array.isArray(results), 'execDbQuery() 返回查询结果')
        } catch (e) {
            TestUtils.assert(false, 'execDbQuery()', String(e))
        }
    } else {
        TestUtils.skip('execDbQuery()', 'MicroMsg.db 不存在')
    }
}

/**
 * 测试朋友圈模块
 */
function testSNSModule() {
    console.log('\n' + '='.repeat(50))
    console.log('📰 测试朋友圈模块')
    console.log('='.repeat(50))

    // 测试1: 获取朋友圈第一页
    try {
        const result = getFirstPage()
        TestUtils.log('SNS', '获取第一页结果:', result)
        TestUtils.assert(result !== -1, 'getFirstPage() 执行成功')
    } catch (e) {
        TestUtils.assert(false, 'getFirstPage()', String(e))
    }

    // 注意: getNextPage 需要有效的朋友圈ID，暂时跳过
    TestUtils.skip('getNextPage()', '需要有效的朋友圈ID')
}

// ==================== 消息监听配置 ====================
const MSG_HOOK_CONFIG = {
    // 是否启用消息监听
    enable: true,
    // 触发自动回复的关键词
    triggerKeyword: 'ding',
    // 自动回复的内容
    replyText: 'dong',
}

// ==================== 消息Hook相关 ====================
const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')
const kDoAddMsg = 0x2205510 // 3.9.10.27

/**
 * 处理同步消息
 */
function HandleSyncMsg(param1: NativePointer, param2: any, param3: any): WeChatMessage {
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

    try {
        if (!param2 || param2.isNull()) {
            return msg;
        }
        
        msg.msgId = param2.add(0x30).readS64().toString() // 消息ID
        msg.type = param2.add(0x38).readS32(); // 消息类型
        msg.isSelf = param2.add(0x3C).readS32() === 1; // 是否自己发送的消息
        msg.createTime = param2.add(0x44).readS32() // 创建时间
        
        try {
            msg.content = readWideString(param2.add(0x88)) || '' // 消息内容
        } catch (e) {
            msg.content = ''
        }
        
        try {
            msg.toUser = readWideString(param2.add(0x240)) || '' // 接收者
        } catch (e) {
            msg.toUser = ''
        }
        
        try {
            msg.fromUser = readWideString(param2.add(0x48)) || '' // 发送者
        } catch (e) {
            msg.fromUser = ''
        }
        
        try {
            msg.signature = ReadWeChatStr(param2.add(0x260)) || '' // 消息签名
        } catch (e) {
            msg.signature = ''
        }

        // 根据消息类型处理图片消息
        if (msg.type === 3) {
            try {
                const thumb = getStringByStrAddr(param2.add(0x280))
                const extra = getStringByStrAddr(param2.add(0x2A0))
                msg.content = JSON.stringify([
                    thumb, // PUPPET.types.Image.Unknown
                    thumb, // PUPPET.types.Image.Thumbnail
                    extra, // PUPPET.types.Image.HD
                    extra, // PUPPET.types.Image.Artwork
                ])
            } catch (e) {
                // 忽略图片处理错误
            }
        }
    } catch (e) {
        console.error('HandleSyncMsg error:', e)
    }

    return msg;
}

/**
 * 启动消息监听
 */
function setupMessageHook() {
    if (!MSG_HOOK_CONFIG.enable) {
        console.log('⏭️ 消息监听已禁用')
        return
    }

    try {
        console.log('\n' + '='.repeat(50))
        console.log('🎣 启动消息监听')
        console.log('='.repeat(50))
        console.log(`📝 触发关键词: "${MSG_HOOK_CONFIG.triggerKeyword}"`)
        console.log(`💬 自动回复: "${MSG_HOOK_CONFIG.replyText}"`)
        console.log('='.repeat(50) + '\n')

        const hookAddr = moduleBaseAddress.add(kDoAddMsg)
        console.log(`📌 Hook地址: ${hookAddr}`)
        console.log(`📌 模块基址: ${moduleBaseAddress}`)
        console.log(`📌 偏移量: 0x${kDoAddMsg.toString(16)}`)
        
        let hookCallCount = 0;
        
        Interceptor.attach(hookAddr, {
            onEnter(args) {
                hookCallCount++;
                // 每100次调用打印一次，避免日志过多
                if (hookCallCount % 100 === 0) {
                    console.log(`[Hook触发计数: ${hookCallCount}]`)
                }
                
                try {
                    // 先检查参数是否有效
                    if (!args[1] || args[1].isNull()) {
                        return
                    }

                    // 检查是否是自己发送的消息
                    const isSelf = args[1].add(0x3C).readS32() === 1;
                    
                    // 解析消息
                    const msg = HandleSyncMsg(args[0], args[1], args[2]);
                    
                    // 打印所有接收到的文本消息 (用于调试)
                    if (msg.type === 1 && !isSelf) {
                        console.log(`\n📩 收到消息:`)
                        console.log(`   类型: ${msg.type} (文本)`)
                        console.log(`   内容: "${msg.content}"`)
                        console.log(`   发送者: ${msg.fromUser}`)
                        console.log(`   接收者: ${msg.toUser || '(无)'}`)
                        console.log(`   是否自己: ${isSelf}`)
                        console.log(`   消息ID: ${msg.msgId}`)
                    }
                    
                    // 忽略自己发送的消息
                    if (isSelf) {
                        return;
                    }

                    const text = msg.content;
                    
                    // 判断是否为群聊消息 (参考index.ts的逻辑)
                    let room = '';
                    let talkerId = '';
                    
                    if (msg.fromUser && msg.fromUser.indexOf('@') !== -1) {
                        room = msg.fromUser;
                    } else if (msg.toUser && msg.toUser.indexOf('@') !== -1) {
                        room = msg.toUser;
                        talkerId = msg.fromUser;
                    }

                    if (room && msg.toUser) {
                        talkerId = msg.toUser;
                    } else if (room && !msg.toUser) {
                        talkerId = '';
                    } else {
                        // 私聊
                        talkerId = msg.fromUser;
                    }

                    // 只在文本消息类型时检查关键词
                    if (msg.type === 1 && text === MSG_HOOK_CONFIG.triggerKeyword) {
                        console.log(`\n🔔 收到触发消息 "${MSG_HOOK_CONFIG.triggerKeyword}":`)
                        console.log(`   发送者: ${talkerId || '(未知)'}`)
                        console.log(`   群聊: ${room || '(私聊)'}`)
                        console.log(`   消息ID: ${msg.msgId}`)

                        // 确定回复目标
                        const replyTarget = room || talkerId;
                        
                        if (replyTarget) {
                            // 如果是群聊，@发送者；如果是私聊，直接回复
                            const atWxids = room && talkerId ? [talkerId] : undefined;
                            
                            console.log(`\n💬 自动回复 "${MSG_HOOK_CONFIG.replyText}" 给: ${replyTarget}`)
                            if (atWxids) {
                                console.log(`   @用户: ${atWxids.join(', ')}`)
                            }
                            
                            try {
                                const result = messageSendText(replyTarget, MSG_HOOK_CONFIG.replyText, atWxids);
                                if (result >= 0) {
                                    console.log(`✅ 回复成功 (返回值: ${result})\n`)
                                } else {
                                    console.log(`❌ 回复失败 (返回值: ${result})\n`)
                                }
                            } catch (sendError) {
                                console.error(`❌ 发送消息异常:`, sendError)
                            }
                        } else {
                            console.log(`⚠️ 无法确定回复目标，跳过回复\n`)
                        }
                    }
                } catch (e: any) {
                    console.error('❌ 消息Hook处理失败：', e)
                    console.error('   错误堆栈:', e.stack || '无堆栈信息')
                }
            },
        })
        
        console.log('✅ Hook已附加，等待消息触发...\n')

        console.log('✅ 消息监听已启动，等待消息...\n')
    } catch (e) {
        console.error('❌ 启动消息监听失败：', e)
    }
}

// ==================== 运行测试 ====================
function runAllTests() {
    console.log('\n')
    console.log('╔══════════════════════════════════════════════════╗')
    console.log('║     WeChat 3.9.10.27 功能测试脚本                 ║')
    console.log('║     Frida-Agent Test Suite                        ║')
    console.log('╚══════════════════════════════════════════════════╝')
    console.log(`\n📅 测试时间: ${new Date().toLocaleString()}`)
    console.log(`📁 测试配置:`)
    console.log(`   - 消息发送测试: ${TEST_CONFIG.enableSendTests ? '✅ 启用' : '❌ 禁用'}`)
    console.log(`   - 群聊操作测试: ${TEST_CONFIG.enableRoomTests ? '✅ 启用' : '❌ 禁用'}`)
    console.log(`   - 测试联系人: ${TEST_CONFIG.testContactId}`)
    console.log(`   - 测试群聊: ${TEST_CONFIG.testRoomId || '未配置'}`)

    // 运行各模块测试
    testLoginModule()
    testContactModule()
    testRoomModule()
    testMessageModule()
    testSQLiteModule()
    testSNSModule()

    // 输出测试汇总
    TestUtils.summary()

    // 测试完成后启动消息监听
    console.log('\n')
    setupMessageHook()
}

// 执行测试
runAllTests()

// 导出测试函数供外部调用
export {
    runAllTests,
    testLoginModule,
    testContactModule,
    testRoomModule,
    testMessageModule,
    testSQLiteModule,
    testSNSModule,
    TEST_CONFIG
}

