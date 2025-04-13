// 联系人接口，包含所有提供的属性
export interface Contact {
    id: string;
    gender: number;
    type: number;
    name: string;
    avatar: string; // profile picture, optional
    address: string; // residential or mailing address, optional
    alias: string; // alias or nickname, optional
    city: string; // city of residence, optional
    friend?: boolean; // denotes if the contact is a friend
    province: string; // province of residence, optional
    signature?: string; // personal signature or motto, optional
    star?: boolean; // denotes if the contact is starred
    weixin: string; // WeChat handle, optional
    corporation: string; // associated company or organization, optional
    title: string; // job title or position, optional
    description: string; // a description for the contact, optional
    coworker: boolean; // denotes if the contact is a coworker
    phone: string[]; // list of phone numbers
}

// 消息接口定义
export interface Message {
    id: string;          // 消息的唯一标识符
    filename?: string;   // 与消息关联的文件名，如果是纯文本消息可以没有这个值
    text: string;         // 消息内容
    timestamp: number;    // 消息的时间戳
    type: number;    // 消息类型
    talkerId: string;     // 发消息用户的ID
    roomId: string;       // 消息所在房间的ID
    listenerId?: string;  // 如果是私聊，接收者用户的ID
    mentionIds: string[]; // @提到的人的ID列表，可以为空列表
    isSelf: boolean;      // 是否是自己发送的消息
}