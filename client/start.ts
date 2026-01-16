/**
 * WeChat Frida Agent SDK 使用示例
 * 
 * 演示如何使用 SDK 调用各种 API 接口
 * 
 * 运行方式:
 *   ts-node client/start.ts
 *   或
 *   node --loader ts-node/esm client/start.ts
 */

import { WeChatSDK } from '../sdk/sdk';

// SDK 配置
const API_BASE_URL = 'http://localhost:19088';
const CALLBACK_URL = 'http://localhost:8888'; // 回调测试服务器地址

/**
 * 主函数
 */
async function main() {
    console.log('='.repeat(80));
    console.log('WeChat Frida Agent SDK 使用示例');
    console.log('='.repeat(80));
    console.log(`API 地址: ${API_BASE_URL}`);
    console.log(`回调地址: ${CALLBACK_URL}\n`);

    // 创建 SDK 实例
    const sdk = new WeChatSDK(API_BASE_URL, {
        timeout: 30000
    });

    try {
        // ==================== 1. 检查服务器状态 ====================
        console.log('📡 步骤 1: 检查服务器状态...');
        try {
            const health = await sdk.health();
            console.log('✅ 服务器运行正常');
            console.log(`   状态: ${health.data.status}`);
            console.log(`   可用 API 数量: ${health.data.apis.length}\n`);
        } catch (error: any) {
            console.error('❌ 服务器连接失败:', error.message);
            console.error('   请确保 Frida Agent 已启动并运行在', API_BASE_URL);
            return;
        }

        // ==================== 2. 检查登录状态 ====================
        console.log('🔐 步骤 2: 检查登录状态...');
        const loginStatus = await sdk.checkLogin();
        if (loginStatus === 1) {
            console.log('✅ 微信已登录\n');
        } else {
            console.log('❌ 微信未登录，请先登录微信\n');
            return;
        }

        // ==================== 3. 设置消息推送 ====================
        console.log('📨 步骤 3: 设置消息推送...');
        try {
            // 设置推送配置（开启推送）
            const pushConfig = await sdk.setPushConfig(true, CALLBACK_URL);
            console.log('✅ 消息推送已开启');
            console.log(`   回调地址: ${pushConfig.callbackUrl}`);
            console.log(`   状态: ${pushConfig.enabled ? '已启用' : '已禁用'}\n`);
            console.log('💡 提示: 请确保回调测试服务器已启动 (python tests/test_callback_server.py)\n');
        } catch (error: any) {
            console.error('❌ 设置推送失败:', error.message);
            console.log('   继续执行其他示例...\n');
        }

        // ==================== 4. 获取自己的信息 ====================
        console.log('👤 步骤 4: 获取自己的信息...');
        try {
            const selfInfo = await sdk.getSelfInfo();
            console.log('✅ 获取成功');
            console.log(`   微信ID: ${selfInfo.id}`);
            console.log(`   昵称: ${selfInfo.name}`);
            console.log(`   头像: ${selfInfo.avatar || 'N/A'}\n`);
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 5. 获取联系人列表 ====================
        console.log('📇 步骤 5: 获取联系人列表...');
        try {
            const contacts = await sdk.getContacts();
            console.log(`✅ 获取成功，共 ${contacts.length} 个联系人`);
            if (contacts.length > 0) {
                console.log('   前 5 个联系人:');
                contacts.slice(0, 5).forEach((contact, index) => {
                    console.log(`   ${index + 1}. ${contact.name} (${contact.id})`);
                });
            }
            console.log();
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 6. 获取联系人详情 ====================
        console.log('🔍 步骤 6: 获取联系人详情...');
        try {
            const contacts = await sdk.getContacts();
            if (contacts.length > 0) {
                const firstContact = contacts[0];
                const contactDetail = await sdk.getContact(firstContact.id);
                console.log(`✅ 获取联系人详情成功: ${firstContact.name}`);
                console.log(`   用户名: ${contactDetail.UserName || 'N/A'}`);
                console.log(`   昵称: ${contactDetail.NickName || 'N/A'}`);
                console.log(`   备注: ${contactDetail.Remark || 'N/A'}`);
                console.log(`   类型: ${contactDetail.Type || 'N/A'}\n`);
            } else {
                console.log('⚠️  没有联系人，跳过此步骤\n');
            }
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 7. 获取群列表 ====================
        console.log('👥 步骤 7: 获取群列表...');
        try {
            const rooms = await sdk.getRooms();
            console.log(`✅ 获取成功，共 ${rooms.length} 个群`);
            if (rooms.length > 0) {
                console.log('   前 3 个群:');
                rooms.slice(0, 3).forEach((room, index) => {
                    console.log(`   ${index + 1}. ${room.name} (${room.id})`);
                });
            }
            console.log();
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 8. 获取群详情 ====================
        console.log('🔍 步骤 8: 获取群详情...');
        try {
            const rooms = await sdk.getRooms();
            if (rooms.length > 0) {
                const firstRoom = rooms[0];
                const roomDetail = await sdk.getRoom(firstRoom.id);
                console.log(`✅ 获取群详情成功: ${firstRoom.name}`);
                console.log(`   群ID: ${roomDetail.id}`);
                console.log(`   群名: ${roomDetail.name || roomDetail.topic || 'N/A'}`);
                console.log(`   公告: ${roomDetail.notice || 'N/A'}`);
                console.log(`   群主: ${roomDetail.admin || 'N/A'}\n`);
            } else {
                console.log('⚠️  没有群，跳过此步骤\n');
            }
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 9. 发送文本消息示例 ====================
        console.log('💬 步骤 9: 发送文本消息示例...');
        console.log('   (注释掉实际发送，避免误发消息)');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   // 发送普通消息');
        console.log('   await sdk.sendTextMessage("filehelper", "Hello World");');
        console.log('');
        console.log('   // 发送群消息');
        console.log('   await sdk.sendTextMessage("xxx@chatroom", "Hello Group");');
        console.log('');
        console.log('   // 发送群消息并@某人');
        console.log('   await sdk.sendTextMessage("xxx@chatroom", "Hello", ["wxid_xxx"]);');
        console.log('');
        console.log('   // @所有人');
        console.log('   await sdk.sendTextMessage("xxx@chatroom", "Hello All", ["notify@all"]);');
        console.log('   ```\n');

        // 取消注释以下代码以实际发送消息（请谨慎使用）
        // try {
        //     await sdk.sendTextMessage('filehelper', `测试消息 ${new Date().toLocaleString()}`);
        //     console.log('✅ 消息发送成功\n');
        // } catch (error: any) {
        //     console.error('❌ 发送失败:', error.message, '\n');
        // }

        // ==================== 10. 发送图片消息示例 ====================
        console.log('🖼️  步骤 10: 发送图片消息示例...');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   await sdk.sendImageMessage("filehelper", "C:\\\\path\\\\to\\\\image.jpg");');
        console.log('   ```\n');

        // ==================== 11. 发送文件消息示例 ====================
        console.log('📎 步骤 11: 发送文件消息示例...');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   await sdk.sendFileMessage("filehelper", "C:\\\\path\\\\to\\\\file.pdf");');
        console.log('   ```\n');

        // ==================== 12. 发送拍一拍示例 ====================
        console.log('👋 步骤 12: 发送拍一拍示例...');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   await sdk.sendPat("xxx@chatroom", "wxid_xxx");');
        console.log('   ```\n');

        // ==================== 13. 转发消息示例 ====================
        console.log('↪️  步骤 13: 转发消息示例...');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   await sdk.forwardMessage("msgId", "receiverId");');
        console.log('   ```\n');

        // ==================== 14. 数据库查询示例 ====================
        console.log('💾 步骤 14: 数据库查询示例...');
        try {
            // 获取数据库列表
            const dbNames = await sdk.getDbNames();
            console.log(`✅ 获取数据库列表成功，共 ${dbNames.length} 个数据库`);
            if (dbNames.length > 0) {
                console.log('   数据库列表:');
                dbNames.slice(0, 5).forEach((dbName, index) => {
                    console.log(`   ${index + 1}. ${dbName}`);
                });

                // 获取第一个数据库的表列表
                if (dbNames.length > 0) {
                    const firstDb = dbNames[0];
                    console.log(`\n   获取数据库 "${firstDb}" 的表列表...`);
                    try {
                        const tables = await sdk.getDbTables(firstDb);
                        console.log(`   ✅ 获取成功，共 ${tables.length} 个表`);
                        if (tables.length > 0) {
                            console.log('   前 5 个表:');
                            tables.slice(0, 5).forEach((table, index) => {
                                console.log(`   ${index + 1}. ${table}`);
                            });
                        }
                    } catch (error: any) {
                        console.error(`   ❌ 获取失败: ${error.message}`);
                    }
                }
            }
            console.log();
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 15. 执行 SQL 查询示例 ====================
        console.log('🔍 步骤 15: 执行 SQL 查询示例...');
        console.log('   示例代码:');
        console.log('   ```typescript');
        console.log('   // 查询联系人');
        console.log('   const results = await sdk.queryDb("MicroMsg.db",');
        console.log('     "SELECT UserName, NickName FROM Contact LIMIT 10"');
        console.log('   );');
        console.log('   ```\n');

        // 取消注释以下代码以实际执行查询（请谨慎使用）
        // try {
        //     const results = await sdk.queryDb('MicroMsg.db', 
        //         'SELECT UserName, NickName FROM Contact LIMIT 5'
        //     );
        //     console.log('✅ 查询成功，结果数量:', results.length);
        //     if (results.length > 0) {
        //         console.log('   前 3 条结果:');
        //         results.slice(0, 3).forEach((row, index) => {
        //             console.log(`   ${index + 1}.`, row);
        //         });
        //     }
        //     console.log();
        // } catch (error: any) {
        //     console.error('❌ 查询失败:', error.message, '\n');
        // }

        // ==================== 16. 获取推送配置 ====================
        console.log('📬 步骤 16: 获取推送配置...');
        try {
            const pushConfig = await sdk.getPushConfig();
            console.log('✅ 获取成功');
            console.log(`   推送状态: ${pushConfig.enabled ? '已启用' : '已禁用'}`);
            console.log(`   回调地址: ${pushConfig.callbackUrl || 'N/A'}\n`);
        } catch (error: any) {
            console.error('❌ 获取失败:', error.message, '\n');
        }

        // ==================== 完成 ====================
        console.log('='.repeat(80));
        console.log('✅ 所有示例执行完成！');
        console.log('='.repeat(80));
        console.log('\n💡 提示:');
        console.log('   - 消息推送已开启，请确保回调测试服务器正在运行');
        console.log('   - 在微信中发送消息，回调服务器会收到推送');
        console.log('   - 取消注释相关代码可以实际执行发送消息等操作');
        console.log('\n📚 更多信息请查看:');
        console.log('   - SDK 文档: sdk/README.md');
        console.log('   - API 文档: docs/api-reference.md');
        console.log();

    } catch (error: any) {
        console.error('\n❌ 发生错误:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

// 运行主函数
main().catch(error => {
    console.error('未捕获的错误:', error);
    process.exit(1);
});
