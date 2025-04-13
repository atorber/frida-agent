export const Offsets = {
  Account: {
    SERVICE: 0x1B58B50, // 账户服务
    PATH: 0x25E9090,    // 数据路径
    WXID: 0x80,         // WXID
    NAME: 0x1E8,        // 昵称
    MOBILE: 0x128,      // 手机号
    LOGIN: 0x7F8,       // 登录状态
    ALIAS: 0x108,       // 修改后的WXID
  },

  Chatroom: {
    MGR: 0x1B86F60,
    DEL: 0x2158830,
    ADD: 0x21581F0,
    INV: 0x2157BD0,
  },

  Contact: {
    MGR: 0x1B44B20,
    LIST: 0x21A1E00,
    BIN: 0x200,
    BIN_LEN: 0x208,
    WXID: 0x10,
    CODE: 0x30,
    REMARK: 0x80,
    NAME: 0xA0,
    GENDER: 0x0E,
    STEP: 0x6A8,

    VERIFY_NEW: 0x2621B00,
    VERIFY_OK: 0x1F421E0,
    VERIFY_MGR: 0x4F022A8,
    VERIFY_A8: 0x2621B91,
    ADD_FRIEND_HELPER: 0x4EE4A20,
    FVDF: 0x4F02768, // FriendVeriyDialogFragment
  },

  Db: {
    INSTANCE: 0x59226C8, // 数据库实例地址
    MSG_I: 0x5980420,    // MSGi.db & MediaMsgi.db
    MICROMSG: 0xB8,
    CHAT_MSG: 0x2C8,
    MISC: 0x5F0,
    EMOTION: 0x15F0,
    MEDIA: 0xF48,
    BIZCHAT_MSG: 0x1AC0,
    FUNCTION_MSG: 0x1B98,
    NAME: 0x28,

    // SQLITE3
    EXEC: 0x3A76430,
    PREPARE: 0x3A76430 + 0x7CB0,
    STEP: 0x3A76430 - 0x3C000,
    COLUMN_COUNT: 0x3A76430 - 0x3B7E0,
    COLUMN_NAME: 0x3A76430 - 0x3ADE0,
    COLUMN_TYPE: 0x3A76430 - 0x3AF90,
    COLUMN_BLOB: 0x3A76430 - 0x3B7B0,
    COLUMN_BYTES: 0x3A76430 - 0x3B6C0,
    FINALIZE: 0x3A76430 - 0x3CF50,
  },

  Message: {
    Log: {
      LEVEL: 0x56E4244, // 日志级别
      CALL: 0x261B890,  // 日志函数
    },

    Receive: {
      CALL: 0x2141E80,      // 接收消息 Call
      ID: 0x30,             // 消息 ID
      TYPE: 0x38,           // 消息类型
      SELF: 0x3C,           // 消息是否来自自己
      TIMESTAMP: 0x44,      // 消息时间戳
      ROOMID: 0x48,         // 群聊 ID（或者发送者 wxid）
      CONTENT: 0x88,        // 消息内容
      WXID: 0x240,          // 发送者 wxid
      SIGN: 0x260,          // 消息签名
      THUMB: 0x280,         // 缩略图路径
      EXTRA: 0x2A0,         // 原图路径
      XML: 0x308,           // 消息 XML

      PYQ_CALL: 0x2E56080,  // 接收朋友圈 Call
      PYQ_START: 0x30,      // 开始地址
      PYQ_END: 0x38,        // 结束地址
      PYQ_SENDER: 0x18,     // 发布者
      PYQ_TS: 0x38,         // 时间戳
      PYQ_CONTENT: 0x48,    // 文本内容
      PYQ_XML: 0x9B8,       // 其他内容
    },

    Send: {
      MGR: 0x1B57350,
      INSTANCE: 0x1B614C0,
      FREE: 0x1B58BD0,
      TEXT: 0x22C9CA0,
      IMAGE: 0x22BF430,
      APP_MGR: 0x1B5C2F0,
      FILE: 0x20D30E0,
      XML: 0x20D2210,
      XML_BUF_SIGN: 0x24F95C0,
      EMOTION_MGR: 0x1BD2310,
      EMOTION: 0x21B8100,

      NEW_MM_READER: 0x1B60A10,
      FREE_MM_READER: 0x1B5FDE0,
      RICH_TEXT: 0x20DD0C0,

      PAT: 0x2CC1E90,

      FORWARD: 0x22C9220,
    }
  },

  Misc: {
    QR_CODE: 0x2025A80,

    INSATNCE: 0x1B614C0, // 与 Message.Send.INSTANCE 相同
    FREE: 0x1B58BD0,     // 与 Message.Send.FREE 相同
    CHAT_MGR: 0x1B8AA50,
    PRE_LOCAL_ID_MGR: 0x2142BF0,
    PRE_DOWNLOAD_MGR: 0x1C12260,
    PUSH_ATTACH_TASK: 0x1CE3050,

    Sns: {
      DATA_MGR: 0x21E52F0,
      TIMELINE: 0x2DC6180,
      FIRST: 0x2E346C0,
      NEXT: 0x2E5A270,
    }
  }
};
