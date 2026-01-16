/**
 * WeChat Frida Agent TypeScript SDK
 * 
 * 用于调用 Frida Agent HTTP API 的 TypeScript SDK
 * 
 * @example
 * ```typescript
 * import { WeChatSDK } from './sdk';
 * 
 * const sdk = new WeChatSDK('http://localhost:19088');
 * 
 * // 检查登录状态
 * const loginStatus = await sdk.checkLogin();
 * 
 * // 获取联系人列表
 * const contacts = await sdk.getContacts();
 * 
 * // 发送文本消息
 * await sdk.sendTextMessage('filehelper', 'Hello World');
 * ```
 */

// ==================== 类型定义 ====================

/**
 * API 响应基础结构
 */
export interface ApiResponse<T = any> {
    code: number;  // 1=成功, 0=失败
    data: T;
    msg: string;
}

/**
 * 联系人信息
 */
export interface Contact {
    id: string;
    name: string;
    avatar: string;
    gender: number;
    type: number;
    alias?: string;
    city?: string;
    province?: string;
    weixin?: string;
    phone?: string[];
    friend?: boolean;
    star?: boolean;
    coworker?: boolean;
    address?: string;
    corporation?: string;
    title?: string;
    description?: string;
}

/**
 * 联系人详情
 */
export interface ContactInfo {
    UserName?: string;
    Alias?: string;
    NickName?: string;
    Remark?: string;
    DelFlag?: number;
    Type?: number;
    LabelIDList?: string;
    ChatRoomType?: string;
    PYInitial?: string;
    QuanPin?: string;
    BigHeadImgUrl?: string;
    SmallHeadImgUrl?: string;
    ChatRoomNotify?: string;
    ExtraBuf?: string;
    ImgFlag?: number;
    Sex?: number;
    ContactType?: number;
    WeiboNickname?: string;
    Country?: string;
    Province?: string;
    City?: string;
    Source?: number;
    VerifyContent?: string;
    IDCardNum?: string;
    RealName?: string;
    ExtInfo?: string;
    CardImgUrl?: string;
    error?: boolean;
    message?: string;
}

/**
 * 群聊信息
 */
export interface Room {
    id: string;
    name: string;
    type: number;
    [key: string]: any;
}

/**
 * 群聊详情
 */
export interface RoomInfo {
    id: string;
    name?: string;
    topic?: string;
    type?: number;
    notice?: string;
    admin?: string;
    xml?: string;
    alias?: string;
    remark?: string;
    error?: boolean;
    message?: string;
}

/**
 * 消息信息
 */
export interface Message {
    id: string;
    filename?: string;
    text: string;
    timestamp: number;
    type: number;
    talkerId: string;
    roomId: string;
    mentionIds: string[];
    listenerId?: string;
    isSelf: boolean;
}

/**
 * 用户信息
 */
export interface UserInfo {
    wxid: string;
    name: string;
    mobile: string;
    home: string;
}

/**
 * 推送配置
 */
export interface PushConfig {
    enabled: boolean;
    callbackUrl: string;
}

/**
 * SDK 配置选项
 */
export interface SDKOptions {
    baseUrl?: string;
    timeout?: number;
    headers?: Record<string, string>;
}

// ==================== SDK 类 ====================

/**
 * WeChat Frida Agent SDK
 */
export class WeChatSDK {
    private baseUrl: string;
    private timeout: number;
    private defaultHeaders: Record<string, string>;

    constructor(baseUrl: string = 'http://localhost:19088', options: SDKOptions = {}) {
        this.baseUrl = baseUrl.replace(/\/$/, ''); // 移除末尾的斜杠
        this.timeout = options.timeout || 30000; // 默认30秒超时
        this.defaultHeaders = {
            'Content-Type': 'application/json',
            ...options.headers
        };
    }

    /**
     * 发送 HTTP 请求
     */
    private async request<T>(
        method: string,
        path: string,
        body?: any,
        query?: Record<string, string>
    ): Promise<ApiResponse<T>> {
        const url = new URL(path, this.baseUrl);
        
        // 添加查询参数
        if (query) {
            Object.entries(query).forEach(([key, value]) => {
                url.searchParams.append(key, value);
            });
        }

        const options: any = {
            method,
            headers: this.defaultHeaders
        };

        // 添加超时支持（如果环境支持）
        if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
            options.signal = AbortSignal.timeout(this.timeout);
        }

        if (body && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(url.toString(), options);
            const data = await (response as any).json() as ApiResponse<T>;
            return data;
        } catch (error: any) {
            throw new Error(`请求失败: ${error.message || String(error)}`);
        }
    }

    // ==================== 基础接口 ====================

    /**
     * 检查服务器健康状态
     */
    async health(): Promise<ApiResponse<{
        status: string;
        timestamp: string;
        apis: string[];
    }>> {
        return this.request('GET', '/api/health');
    }

    /**
     * 检查登录状态
     * @returns 1=已登录, -1=未登录
     */
    async checkLogin(): Promise<number> {
        const response = await this.request<number>('GET', '/api/checkLogin');
        return response.data;
    }

    // ==================== 联系人接口 ====================

    /**
     * 获取自己的信息
     */
    async getSelfInfo(): Promise<Contact> {
        const response = await this.request<Contact>('GET', '/api/contacts/self');
        if (response.code !== 1) {
            throw new Error(response.msg || '获取自己信息失败');
        }
        return response.data;
    }

    /**
     * 获取联系人列表
     */
    async getContacts(): Promise<Contact[]> {
        const response = await this.request<Contact[]>('GET', '/api/contacts');
        if (response.code !== 1) {
            throw new Error(response.msg || '获取联系人列表失败');
        }
        return response.data || [];
    }

    /**
     * 获取联系人详情
     * @param contactId 联系人ID（wxid）
     */
    async getContact(contactId: string): Promise<ContactInfo> {
        const response = await this.request<ContactInfo>('GET', '/api/contact', undefined, {
            contactId
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '获取联系人详情失败');
        }
        if (response.data && (response.data as any).error) {
            throw new Error((response.data as any).message || '获取联系人详情失败');
        }
        return response.data;
    }

    // ==================== 群聊接口 ====================

    /**
     * 获取群列表
     */
    async getRooms(): Promise<Room[]> {
        const response = await this.request<Room[]>('GET', '/api/rooms');
        if (response.code !== 1) {
            throw new Error(response.msg || '获取群列表失败');
        }
        return response.data || [];
    }

    /**
     * 获取群详情
     * @param roomId 群ID（格式：xxx@chatroom）
     */
    async getRoom(roomId: string): Promise<RoomInfo> {
        const response = await this.request<RoomInfo>('GET', '/api/room', undefined, {
            roomId
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '获取群详情失败');
        }
        if (response.data && (response.data as any).error) {
            throw new Error((response.data as any).message || '获取群详情失败');
        }
        return response.data;
    }

    // ==================== 消息接口 ====================

    /**
     * 发送文本消息
     * @param contactId 联系人ID或群ID
     * @param text 消息内容
     * @param atWxids 可选，@的用户ID列表（仅群聊有效）
     */
    async sendTextMessage(
        contactId: string,
        text: string,
        atWxids?: string[]
    ): Promise<number> {
        const response = await this.request<number>('POST', '/api/message/text', {
            contactId,
            text,
            atWxids
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '发送消息失败');
        }
        return response.data;
    }

    /**
     * 发送图片消息
     * @param contactId 联系人ID或群ID
     * @param path 图片文件路径
     */
    async sendImageMessage(contactId: string, path: string): Promise<number> {
        const response = await this.request<number>('POST', '/api/message/image', {
            contactId,
            path
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '发送图片失败');
        }
        return response.data;
    }

    /**
     * 发送文件消息
     * @param contactId 联系人ID或群ID
     * @param path 文件路径
     */
    async sendFileMessage(contactId: string, path: string): Promise<number> {
        const response = await this.request<number>('POST', '/api/message/file', {
            contactId,
            path
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '发送文件失败');
        }
        return response.data;
    }

    /**
     * 发送拍一拍
     * @param roomId 群ID
     * @param contactId 被拍的用户ID
     */
    async sendPat(roomId: string, contactId: string): Promise<number> {
        const response = await this.request<number>('POST', '/api/message/pat', {
            roomId,
            contactId
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '发送拍一拍失败');
        }
        return response.data;
    }

    /**
     * 转发消息
     * @param msgId 消息ID
     * @param receiver 接收者ID（联系人ID或群ID）
     */
    async forwardMessage(msgId: string, receiver: string): Promise<number> {
        const response = await this.request<number>('POST', '/api/message/forward', {
            msgId,
            receiver
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '转发消息失败');
        }
        return response.data;
    }

    // ==================== 数据库接口 ====================

    /**
     * 获取可查询的数据库列表
     */
    async getDbNames(): Promise<string[]> {
        const response = await this.request<string[]>('GET', '/api/db/names');
        if (response.code !== 1) {
            throw new Error(response.msg || '获取数据库列表失败');
        }
        return response.data || [];
    }

    /**
     * 获取数据库表列表
     * @param dbName 数据库名称
     */
    async getDbTables(dbName: string): Promise<string[]> {
        const response = await this.request<string[]>('GET', '/api/db/tables', undefined, {
            dbName
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '获取表列表失败');
        }
        return response.data || [];
    }

    /**
     * 执行 SQL 查询
     * @param dbName 数据库名称
     * @param sql SQL 查询语句
     */
    async queryDb(dbName: string, sql: string): Promise<any[]> {
        const response = await this.request<any[]>('POST', '/api/db/query', {
            dbName,
            sql
        });
        if (response.code !== 1) {
            throw new Error(response.msg || '执行查询失败');
        }
        return response.data || [];
    }

    // ==================== 推送接口 ====================

    /**
     * 获取推送配置
     */
    async getPushConfig(): Promise<PushConfig> {
        const response = await this.request<PushConfig>('GET', '/api/push/config');
        if (response.code !== 1) {
            throw new Error(response.msg || '获取推送配置失败');
        }
        return response.data;
    }

    /**
     * 设置推送配置
     * @param enabled 是否开启推送
     * @param callbackUrl 回调地址（开启时必须提供）
     */
    async setPushConfig(enabled: boolean, callbackUrl?: string): Promise<PushConfig> {
        if (enabled && !callbackUrl) {
            throw new Error('开启推送时必须提供 callbackUrl');
        }
        
        const body: any = { enabled };
        if (callbackUrl) {
            body.callbackUrl = callbackUrl;
        }

        const response = await this.request<PushConfig>('POST', '/api/push/config', body);
        if (response.code !== 1) {
            throw new Error(response.msg || '设置推送配置失败');
        }
        return response.data;
    }
}

// ==================== 导出 ====================

export default WeChatSDK;
