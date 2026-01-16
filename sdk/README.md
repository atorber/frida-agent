# WeChat Frida Agent TypeScript SDK

用于调用 Frida Agent HTTP API 的 TypeScript SDK。

## 安装

```bash
# 如果作为独立包使用
npm install @frida-agent/wechat-sdk

# 或者直接使用源码
import { WeChatSDK } from './sdk/sdk';
```

## 快速开始

```typescript
import { WeChatSDK } from './sdk/sdk';

// 创建 SDK 实例
const sdk = new WeChatSDK('http://localhost:19088');

// 检查登录状态
const loginStatus = await sdk.checkLogin();
console.log('登录状态:', loginStatus); // 1=已登录, -1=未登录

// 获取联系人列表
const contacts = await sdk.getContacts();
console.log('联系人数量:', contacts.length);

// 发送文本消息
await sdk.sendTextMessage('filehelper', 'Hello World');

// 发送群消息并@某人
await sdk.sendTextMessage('xxx@chatroom', 'Hello', ['wxid_xxx']);
```

## API 文档

### 基础接口

#### `health()`
检查服务器健康状态

```typescript
const health = await sdk.health();
console.log(health.data.apis); // API 列表
```

#### `checkLogin()`
检查登录状态

```typescript
const status = await sdk.checkLogin(); // 1=已登录, -1=未登录
```

### 联系人接口

#### `getSelfInfo()`
获取自己的信息

```typescript
const selfInfo = await sdk.getSelfInfo();
console.log(selfInfo.name, selfInfo.id);
```

#### `getContacts()`
获取联系人列表

```typescript
const contacts = await sdk.getContacts();
contacts.forEach(contact => {
    console.log(contact.name, contact.id);
});
```

#### `getContact(contactId: string)`
获取联系人详情

```typescript
const contact = await sdk.getContact('wxid_xxx');
console.log(contact.NickName, contact.Remark);
```

### 群聊接口

#### `getRooms()`
获取群列表

```typescript
const rooms = await sdk.getRooms();
rooms.forEach(room => {
    console.log(room.name, room.id);
});
```

#### `getRoom(roomId: string)`
获取群详情

```typescript
const room = await sdk.getRoom('xxx@chatroom');
console.log(room.name, room.notice);
```

### 消息接口

#### `sendTextMessage(contactId: string, text: string, atWxids?: string[])`
发送文本消息

```typescript
// 发送普通消息
await sdk.sendTextMessage('filehelper', 'Hello');

// 发送群消息并@某人
await sdk.sendTextMessage('xxx@chatroom', 'Hello', ['wxid_xxx']);

// @所有人
await sdk.sendTextMessage('xxx@chatroom', 'Hello', ['notify@all']);
```

#### `sendImageMessage(contactId: string, path: string)`
发送图片消息

```typescript
await sdk.sendImageMessage('filehelper', 'C:\\path\\to\\image.jpg');
```

#### `sendFileMessage(contactId: string, path: string)`
发送文件消息

```typescript
await sdk.sendFileMessage('filehelper', 'C:\\path\\to\\file.pdf');
```

#### `sendPat(roomId: string, contactId: string)`
发送拍一拍

```typescript
await sdk.sendPat('xxx@chatroom', 'wxid_xxx');
```

#### `forwardMessage(msgId: string, receiver: string)`
转发消息

```typescript
await sdk.forwardMessage('1234567890', 'filehelper');
```

### 数据库接口

#### `getDbNames()`
获取可查询的数据库列表

```typescript
const dbNames = await sdk.getDbNames();
console.log(dbNames); // ['MicroMsg.db', 'FTS5IndexMicroMsg.db', ...]
```

#### `getDbTables(dbName: string)`
获取数据库表列表

```typescript
const tables = await sdk.getDbTables('MicroMsg.db');
console.log(tables); // ['Contact', 'ChatRoom', ...]
```

#### `queryDb(dbName: string, sql: string)`
执行 SQL 查询

```typescript
const results = await sdk.queryDb('MicroMsg.db', 
    'SELECT UserName, NickName FROM Contact LIMIT 10'
);
console.log(results);
```

### 推送接口

#### `getPushConfig()`
获取推送配置

```typescript
const config = await sdk.getPushConfig();
console.log(config.enabled, config.callbackUrl);
```

#### `setPushConfig(enabled: boolean, callbackUrl?: string)`
设置推送配置

```typescript
// 开启推送
await sdk.setPushConfig(true, 'http://localhost:8888');

// 关闭推送
await sdk.setPushConfig(false);
```

## 错误处理

所有方法在失败时会抛出错误：

```typescript
try {
    await sdk.sendTextMessage('invalid_id', 'Hello');
} catch (error) {
    console.error('发送失败:', error.message);
}
```

## 配置选项

创建 SDK 实例时可以配置选项：

```typescript
const sdk = new WeChatSDK('http://localhost:19088', {
    timeout: 60000, // 超时时间（毫秒）
    headers: {
        'X-Custom-Header': 'value'
    }
});
```

## 类型定义

SDK 提供了完整的 TypeScript 类型定义：

```typescript
import { Contact, Room, Message, PushConfig } from './sdk/sdk';

const contact: Contact = {
    id: 'wxid_xxx',
    name: '张三',
    // ...
};
```

## 示例

完整示例请查看 `examples/` 目录。
