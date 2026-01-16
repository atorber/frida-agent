/**
 * WeChat SDK 基础使用示例
 */

import { WeChatSDK } from '../sdk';

async function main() {
    // 创建 SDK 实例
    const sdk = new WeChatSDK('http://localhost:19088');

    try {
        // 1. 检查服务器状态
        console.log('检查服务器状态...');
        const health = await sdk.health();
        console.log('服务器状态:', health.data.status);
        console.log('可用 API:', health.data.apis);

        // 2. 检查登录状态
        console.log('\n检查登录状态...');
        const loginStatus = await sdk.checkLogin();
        console.log('登录状态:', loginStatus === 1 ? '已登录' : '未登录');

        if (loginStatus !== 1) {
            console.log('请先登录微信');
            return;
        }

        // 3. 获取自己的信息
        console.log('\n获取自己的信息...');
        const selfInfo = await sdk.getSelfInfo();
        console.log('微信ID:', selfInfo.id);
        console.log('昵称:', selfInfo.name);

        // 4. 获取联系人列表
        console.log('\n获取联系人列表...');
        const contacts = await sdk.getContacts();
        console.log(`联系人数量: ${contacts.length}`);
        if (contacts.length > 0) {
            console.log('前5个联系人:');
            contacts.slice(0, 5).forEach(contact => {
                console.log(`  - ${contact.name} (${contact.id})`);
            });
        }

        // 5. 获取群列表
        console.log('\n获取群列表...');
        const rooms = await sdk.getRooms();
        console.log(`群数量: ${rooms.length}`);
        if (rooms.length > 0) {
            console.log('前3个群:');
            rooms.slice(0, 3).forEach(room => {
                console.log(`  - ${room.name} (${room.id})`);
            });
        }

        // 6. 发送测试消息（可选）
        // console.log('\n发送测试消息...');
        // await sdk.sendTextMessage('filehelper', `测试消息 ${new Date().toLocaleString()}`);

    } catch (error: any) {
        console.error('错误:', error.message);
    }
}

main();
