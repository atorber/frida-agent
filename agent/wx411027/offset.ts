/**
 * 微信 4.1.10.27 (Weixin.dll) 偏移
 * 全部来自 aixed/WeChat-Hook v411027_（include/global.h）
 */

export const offsets = {
  // —— 发送（wx_send.cpp / global.h offset::）——
  create_param2: 0xdf40,
  send_message: 0x1677a30,
  param1_vtable: 0x84ec9c8,
  param2: 0xa0ce0b0,
  param2_1: 0x8595f58,
  param2_2: 0x8595e98,
  param2_3: 0x8595dd8,

  txt_message_ctr: 0x6b2c30,
  txt_message_vtbl: 0x8279358,
  img_msg_vtbl: 0x84f96b8,
  img_msg_vtb2: 0x84f9748,

  dec_pic_call: 0x493e70,

  // TextMessage 相对 ctr 对象（msgBuf+0x10）
  tm_receiver: 0xb0,
  tm_type: 0xd8,
  tm_msg_len: 0x188,
  tm_uuid: 0x6a8,
  tm_content: 0x708,
  tm_atlist: 0x728,

  txt_ctrl_const: 0x200000005,
  img_ctrl_const: 0x200000006,
  msg_buf_size_text: 0x768 * 8,
  msg_buf_size_image: 0x7c0,

  // —— XML 转发（aixed global.h `namespace Offsets`，源码注释为 4.1.5.30）——
  // 实测在 4.1.10.27 Weixin.dll 上这些地址不是合法 vtable；调用前见 forwardXml.xmlOffsetsLookValid()
  IMAGE_FIELD_VTABLE: 0x80d1098,
  IMAGE_FIELD_VTABLE2: 0x80d1128,
  IMAGE_DATA_VTABLE: 0x7415d28,
  IMAGE_DATA_VTABLE2: 0x7415db8,
  VIDEO_FIELD_VTABLE: 0x750c7f8,
  VIDEO_FIELD_VTABLE2: 0x750c888,
  ANIMATION_FIELD_VTABLE: 0x750cc18,
  ANIMATION_FIELD_VTABLE2: 0x750cca8,
  MESSAGE_STRUCT_VTABLE: 0x76bd388,
  MESSAGE_STRUCT_VTABLE2: 0x76bd338,
  MESSAGE_PARAM_VTABLE: 0x76bcf38,
  FORWARD_XML_CALL: 0x1cf3d20,

  // —— SQLite / SQLCipher（global.h XWECHAT_*）——
  SQLITE3_VFS: 0xa6c0490,
  SQLITE3_API_ROUTINES: 0x8bb0d38,
  SQLCIPHER_API_ROUTINES: 0x8bb1570,
  SQLITE3_CODEC_GET_KEY: 0x4ee64d0,

  // sqlite3_api_routines 字段下标 * 8（见 aixed xdb/sqlite3.h）
  api_prepare: 72 * 8,
  api_step: 94 * 8,
  api_finalize: 57 * 8,
  api_column_blob: 19 * 8,
  api_column_bytes: 20 * 8,
  api_column_count: 22 * 8,
  api_column_name: 30 * 8,
  api_column_type: 38 * 8,
  api_errcode: 52 * 8,
  api_close: 16 * 8,
  api_open: 70 * 8,

  // 其它
  PATCH_REVOKE: 0x22d09e7,
  MAIN_CLAZZ: 0xa83ab20,
}

export const WX_DLL = 'Weixin.dll'
export const WX_VERSION = '4.1.10.27'
