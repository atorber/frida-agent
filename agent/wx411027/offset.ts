/**
 * 微信 4.1.10.27 (Weixin.dll) 偏移
 * - 发送：aixed/WeChat-Hook v411027_（include/global.h offset::）——已在本机实机验证
 * - 收消息：由 4.1.9.23 DoAddMsg 特征 + send_message 邻域扫描重定位
 * - XML 转发虚表：aixed 标注 4.1.5.30，本 DLL 上非法；见 forwardXml 回退路径
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

  /**
   * BuildSendParam1_sub 文件类型字段（msgBuf+0xE8）
   * aixed wx_send.cpp: 3=png/jpg, 47=gif
   * 统一发送文件类接口实测还可发 mp4/xlsx/zip/txt 等（update.log 20260727）
   */
  media_type_image: 3,
  media_type_video: 43,
  media_type_emotion: 47,
  media_type_file: 49,

  // —— 收消息 DoAddMsg ——
  // 首选：相对 4.1.9.23(0x166A6BF) 按 send_message 增量估算，落在特征命中簇内
  do_add_msg: 0x16d2faf,
  do_add_msg_candidates: [0x16d2faf, 0x16d341e, 0x16afcf4, 0x16fc54d, 0x160ec77, 0x1641c7d],
  do_add_msg_scan_lo: 0x1600000,
  do_add_msg_scan_hi: 0x1750000,

  /**
   * MsgStruct（Frida dump 对齐 4.1.10.27 / DoAddMsg @ 0x16d2faf）
   * 实机群消息：from@0x18 群, to@0x38 自己, sender@0x58 发送者别名,
   * content@0x180 形如 "tyutluyc:\\nhi", msgsource@0x1c0,
   * type@0x0c, create_time@0x164, msg_id@0x148（u64）。
   */
  msg: {
    type: 0x0c,
    subtype: 0x10,
    from: 0x18,
    to: 0x38,
    sender: 0x58,
    local_id: 0x140,
    msg_id: 0x148,
    create_time: 0x164,
    create_time_alt: 0x110,
    content: 0x180,
    content_scan_lo: 0x170,
    content_scan_hi: 0x1c0,
    msgsource: 0x1c0,
    signature: 0x180,
  },

  // —— XML 转发（aixed global.h `namespace Offsets`，源码注释为 4.1.5.30）——
  // PE 校验：虚表位落在 SVG/字符串区，非法；FORWARD_XML_CALL 落在函数中部。
  // 原生路径仍保留；失败时 forwardXml 走「按 type 发 XML 内容」回退。
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
  // aixed rdx+0x20 硬编码（同属 4.1.5.30 线索，本 DLL 上亦非入口）
  FORWARD_XML_RDX_CONST: 0x367849,

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
