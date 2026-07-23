/**
 * 微信 3.9.10.27 偏移地址定义
 */

export const offsets = {
    // 登录相关
    kGetAccountServiceMgr: 0x1C1FE90, // 3.9.10.27
    OS_USER_HOME: 0x5A7E190, // 来自C++代码
    OS_USER_WXID: 0x5AB7F30,
    OS_USER_NAME: 0x5AB8098,
    OS_USER_MOBILE: 0x5AB7FD8,
    
    // 联系人相关
    kGetAppDataSavePath: 0x26A7780,
    kGetCurrentDataPath: 0x2314E40,
    kGetContactMgr: 0x1C0BDE0,
    kGetContactList: 0x2265540,
    kNewContact: 0x25E3650,
    kGetContact: 0x225F950,
    
    // 群聊相关
    kChatRoomMgr: 0x1C4E200,
    kChatRoomInfoConstructor: 0x25CF470, // 3.9.10.27
    kGetChatRoomDetailInfo: 0x222BEA0, // 3.9.10.27
    kModChatRoomTopic: 0x2364610, // 3.9.10.27
    kOpLogMgr: 0x1C193C0,
    kAddChatroomMember: 0x221B8A0,
    kDelChatroomMember: 0x221BEE0,
    kInviteChatroomMember: 0x221B280,
    
    // 消息相关
    kDoAddMsg: 0x2205510, // 3.9.10.27
    kSendMessageMgr: 0x1C1E690, // 3.9.10.27
    kSendTextMsg: 0x238DDD0, // 3.9.10.27
    kFreeChatMsg: 0x1C1FF10, // 3.9.10.27
    kNewChatMsg: 0x1C28800,
    kSendImageMsg: 0x2383560, // 3.9.10.27
    kAppMsgMgr: 0x1C23630, // 3.9.10.27
    kSendFileMsg: 0x21969E0, // 3.9.10.27
    kSendPatMsg: 0x2D669B0, // 3.9.10.27
    kForwardMsg: 0x238D350, // 3.9.10.27
    
    // 消息相关 (OS_ 前缀别名)
    OS_NEW: 0x1C28800,
    OS_FREE: 0x1C1FF10,
    OS_SEND_MSG_MGR: 0x1C1E690,
    OS_SEND_TEXT: 0x238DDD0,
    OS_SEND_IMAGE: 0x2383560,
    OS_GET_APP_MSG_MGR: 0x1C23630,
    OS_SEND_FILE: 0x21969E0,
    OS_RTM_NEW: 0x1C27D50,
    OS_RTM_FREE: 0x1C27120,
    OS_SEND_RICH_TEXT: 0x21A09C0,
    OS_SEND_PAT_MSG: 0x2D669B0,
    OS_FORWARD_MSG: 0x238D350,
    OS_GET_EMOTION_MGR: 0x1C988D0,
    OS_SEND_EMOTION: 0x227B9E0,
    
    // 朋友圈相关
    OS_GET_SNS_DATA_MGR: 0x22A91C0,
    OS_GET_SNS_FIRST_PAGE: 0x2ED9080,
    OS_GET_SNS_TIMELINE_MGR: 0x2E6B110,
    OS_GET_SNS_NEXT_PAGE: 0x2EFEC00,
    OS_PYQ_MSG_CALL: 0x2EFAA10,
    OS_PYQ_MSG_START: 0x30,
    OS_PYQ_MSG_END: 0x38,
    OS_PYQ_MSG_TS: 0x38,
    OS_PYQ_MSG_XML: 0x9B8,
    OS_PYQ_MSG_SENDER: 0x18,
    OS_PYQ_MSG_CONTENT: 0x48,
    OS_PYQ_MSG_STEP: 0x1618,

    // 附件下载相关
    OS_GET_CHAT_MGR: 0x1C51CF0,
    OS_GET_PRE_DOWNLOAD_MGR: 0x1CD87E0,
    OS_PUSH_ATTACH_TASK: 0x1DA69C0,
    OS_GET_MGR_BY_PREFIX_LOCAL_ID: 0x2206280,
    
    // 标签相关
    kNetSceneModifyContactLabel: 0x250C480,
    kSceneCenter: 0x1CDD710,
    kSceneNetSceneBase: 0x2454EB0,
}

// 尝试不同的偏移量组合（用于内存搜索）
export const offsetVariants = {
    wxid: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10],
    name: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10],
    mobile: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10]
};
