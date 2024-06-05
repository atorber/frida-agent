/**
 * WeChat 3.9.10.19
 * 
 */

// 偏移地址,来自于wxhelper项目
import { wxOffsets_3_9_10_19 as wxOffsets } from './offset.js';

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')
// console.info('moduleBaseAddress:', moduleBaseAddress)

/* -----------------base------------------------- */

const writeWStringPtr = (str:string) => {
  console.log(`输入字符串内容: ${str}`);
  const strLength = str.length;
  // console.log(`字符串长度: ${strLength}`);

  // 计算UTF-16编码的字节长度（每个字符2个字节）
  const utf16Length = strLength * 2;

  // 计算我们需要为字符串对象结构分配的总内存空间，结构包含：指针 (Process.pointerSize) + 长度 (4 bytes) + 容量 (4 bytes)
  const structureSize = Process.pointerSize + 4 + 4;
  
  // 为字符串数据和结构体分配连续的内存空间
  const totalSize = utf16Length + 2 + structureSize; // +2 用于 null 终止符
  const basePointer = Memory.alloc(totalSize);
  
  // 将结构体指针定位到分配的内存起始位置
  const structurePointer = basePointer;
  // console.log(`字符串分配空间内存指针: ${structurePointer}`);
  
  // 将字符串数据指针定位到结构体之后的位置
  const stringDataPointer = basePointer.add(structureSize);
  // console.log(`字符串保存地址指针: ${stringDataPointer}`);

  // 将 JavaScript 字符串转换成 UTF-16 编码格式，并写入分配的内存空间
  stringDataPointer.writeUtf16String(str);
  // console.log(`写入字符串到地址: ${stringDataPointer.readUtf16String()}`);

  // 检查分配的内存内容
  const allocatedMemoryContent = stringDataPointer.readUtf16String();
  // console.log(`检查分配的内存内容: ${allocatedMemoryContent}`);

  // 在分配的内存空间中写入字符串对象的信息
  // 写入字符串数据指针
  structurePointer.writePointer(stringDataPointer);
  // console.log(`写入字符串地址存放指针: ${structurePointer.readPointer()}`);
  // console.log(`写入字符串内容确认: ${structurePointer.readPointer().readUtf16String()}`);

  // 写入字符串长度（确保是长度，不包含 null 终止符）
  structurePointer.add(Process.pointerSize).writeU32(strLength);
  // console.log(`写入字符串长度指针: ${structurePointer.add(Process.pointerSize)}`);

  // 写入字符串容量，这里我们假设容量和长度是相同的
  structurePointer.add(Process.pointerSize + 4).writeU32(strLength);
  // console.log(`写入字符串容量指针: ${structurePointer.add(Process.pointerSize + 4)}`);

  // console.log(`写入字符串内容再次确认: ${structurePointer.readPointer().readUtf16String()}`);
  // console.log(`写入字符地址再次确认: ${structurePointer.readPointer()}`);
  // console.log(`读取32位测试: ${structurePointer.readPointer().readS32()}`);
  // console.log(`return写入字符串结构体: ${structurePointer}`);
  
  // 返回分配的结构体表面的起始地址
  return structurePointer;
};

const readWStringPtr = (addr: any) => {
  // console.log(`input读取字符串地址指针4: ${addr}`);
  // console.log(`读取字符串内容指针4: ${addr.readPointer().readUtf16String()}`);
  const stringPointer = addr.readPointer();
  // console.log(`读取数据指针地址1: ${stringPointer}`);
  // console.log(`读取数据指针内容1: ${stringPointer.readUtf16String()}`);

  const size = addr.add(Process.pointerSize).readU32();
  // console.log(`读取字符串长度: ${size}`);

  const capacity = addr.add(Process.pointerSize + 4).readU32();
  // console.log(`读取字符串容量: ${capacity}`);

  return {
    ptr: stringPointer,
    size: size,
    capacity: capacity,
    readUtf16String: () => {
      // UTF-16字符串长度需要乘以2，因为每个字符占2个字节
      const content = size ? stringPointer.readUtf16String()?.replace(/\0+$/, '') : '';
      console.log(`读取字符串内容: ${content}`);
      return content;
    }
  };
};

interface WeChatMessage {
  // 发送者的用户标识
  fromUser: string;

  // 接收者的用户标识
  toUser: string;

  // 消息内容，这里提供的是 XML 格式的数据
  content: string;

  // 消息签名，包含了一些描述和验证信息
  signature: string;

  // 消息的唯一识别码
  msgId: string;

  // 消息的序列号
  msgSequence: number;

  // 消息的创建时间戳
  createTime: number;

  // 全文展示的标记，这里为空字符串，具体情况需要根据实际的业务逻辑确定
  displayFullContent: string;

  // 消息的类型，这里为 3，具体指代意义在业务中确定
  type: number;

  base64Img?: string;
}

function ReadWeChatStr(addr: any) {
  // console.log("addr: " + addr);
  addr = ptr(addr);
  var len = addr.add(0x10).readS64(); // 使用 ptr的`.readS64`方法
  // console.log("len: " + len);

  if (len == 0) return "";

  var max_len = addr.add(0x18).readS64();
  // console.log("max_len: " + max_len);
  let res = ''
  if ((max_len.or(0xF)).equals(0xF)) {
    res = addr.readUtf8String(len);

  } else {
    var char_from_user = addr.readPointer();
    res = char_from_user.readUtf8String(len);
  }
  // console.log("res: " + res);
  return res;
}

function ReadSKBuiltinString(addr: { add: (arg0: number) => string | number; }) {
  var inner_string = ptr(addr.add(0x8)).readS64();
  // console.log("inner_string: " + inner_string);

  // if (inner_string.isNull()) return "";
  return ReadWeChatStr(inner_string);
}

function HandleSyncMsg(param1: NativePointer, param2: any, param3: NativePointer) {
  // console.log("HandleSyncMsg called with param2: " + param2);
  const msg: WeChatMessage = {
    fromUser: '',
    toUser: '',
    content: '',
    signature: '',
    msgId: '',
    msgSequence: 0,
    createTime: 0,
    displayFullContent: '',
    type: 0
  }
  // 填充消息内容到JSON对象
  msg.fromUser = ReadSKBuiltinString(param2.add(0x18).readS64()) // 发送者
  msg.toUser = ReadSKBuiltinString(param2.add(0x28).readS64()) // 发送者
  msg.content = ReadSKBuiltinString(param2.add(0x30).readS64()) // 消息内容
  msg.signature = ReadWeChatStr(param2.add(0x48).readS64()) // 消息签名
  msg.msgId = param2.add(0x60).readS64() // 消息ID
  msg.msgSequence = param2.add(0x5C).readS32() // 消息序列号
  msg.createTime = param2.add(0x58).readS32() // 创建时间
  msg.displayFullContent = ReadWeChatStr((param2.add(0x50).readS64())) // 是否展示完整内容
  msg.type = param2.add(0x24).readS32(); // 消息类型

  // 根据消息类型处理图片消息
  if (msg['type'] == 3) {
    // const img = ReadSKBuiltinBuffer(param2.add(0x40).readS64()); // 读取图片数据
    const img = ReadSKBuiltinString(param2.add(0x40).readS64()); // 读取图片数据
    console.log("img: " + img);
    msg.base64Img = img; // 将图片数据编码为Base64字符串
  }
  console.log("HandleSyncMsg msg: " + JSON.stringify(msg));
  return msg;
}

// 获取自己的信息
const getMyselfInfoFunction = () => {

  var success = -1;
  var out: any = {};

  // 确定相关函数的地址
  var accountServiceAddr = moduleBaseAddress.add(wxOffsets.kGetAccountServiceMgr);
  var getAppDataSavePathAddr = moduleBaseAddress.add(wxOffsets.kGetAppDataSavePath);
  var getCurrentDataPathAddr = moduleBaseAddress.add(wxOffsets.kGetCurrentDataPath);

  // Funcion hooks (使用Interceptor.attach可以替代这些函数，下面只是示例)
  var GetService = new NativeFunction(accountServiceAddr, 'pointer', []);
  var GetDataSavePath = new NativeFunction(getAppDataSavePathAddr, 'void', ['pointer']);
  var GetCurrentDataPath = new NativeFunction(getCurrentDataPathAddr, 'void', ['pointer']);

  var serviceAddr = GetService();

  // 必要的辅助函数
  function readWeChatString(addr: NativePointer, offset: number) {
    if (addr.add(offset).readU32() === 0 || addr.add(offset + 0x10).readU32() === 0) {
      return '';
    }
    var stringAddr = addr.add(offset);
    if (stringAddr.add(0x18).readU32() === 0xF) {
      return stringAddr.readUtf8String(addr.add(offset + 0x10).readU32());
    } else {
      return stringAddr.readPointer().readUtf8String(addr.add(offset + 0x10).readU32());
    }
  }

  // 使用辅助函数来模版处理字符串读取
  if (!serviceAddr.isNull()) {
    out.wxid = ReadWeChatStr(serviceAddr.add(0x80));
    out.account = readWeChatString(serviceAddr, 0x108);
    out.mobile = readWeChatString(serviceAddr, 0x128);
    out.signature = readWeChatString(serviceAddr, 0x148);
    // ... 其他属性按照相同的模式处理
    //     if (*(int64_t*)(service_addr + 0x148) == 0 ||
    //     *(int64_t*)(service_addr + 0x148 + 0x10) == 0) {
    if (serviceAddr.add(0x148).readU32() === 0 || serviceAddr.add(0x148 + 0x10).readU32() === 0) {
      //   out.signature = std::string();
      out.signature = '';
      // } else {
    } else {
      //   if (*(int64_t*)(service_addr + 0x148 + 0x18) == 0xF) {
      if (serviceAddr.add(0x148 + 0x18).readU32() === 0xF) {
        //     out.signature = std::string((char*)(service_addr + 0x148),
        //                                 *(int64_t*)(service_addr + 0x148 + 0x10));
        out.signature = serviceAddr.add(0x148).readUtf8String(serviceAddr.add(0x148 + 0x10).readU32());
        //   } else {
      } else {
        //     out.signature = std::string(*(char**)(service_addr + 0x148),
        //                                 *(int64_t*)(service_addr + 0x148 + 0x10));
        out.signature = serviceAddr.add(0x148).readPointer().readUtf8String(serviceAddr.add(0x148 + 0x10).readU32());
        //   }
      }
      // }
    }

    // if (*(int64_t*)(service_addr + 0x168) == 0 ||
    //     *(int64_t*)(service_addr + 0x168 + 0x10) == 0) {
    if (serviceAddr.add(0x168).readU32() === 0 || serviceAddr.add(0x168 + 0x10).readU32() === 0) {
      //   out.country = std::string();

      // } else {
    } else {
      //   if (*(int64_t*)(service_addr + 0x168 + 0x18) == 0xF) {
      if (serviceAddr.add(0x168 + 0x18).readU32() === 0xF) {
        //     out.country = std::string((char*)(service_addr + 0x168),
        //                               *(int64_t*)(service_addr + 0x168 + 0x10));
        out.country = serviceAddr.add(0x168).readUtf8String(serviceAddr.add(0x168 + 0x10).readU32());
        //   } else {
      } else {
        //     out.country = std::string(*(char**)(service_addr + 0x168),
        //                               *(int64_t*)(service_addr + 0x168 + 0x10));
        out.country = serviceAddr.add(0x168).readPointer().readUtf8String(serviceAddr.add(0x168 + 0x10).readU32());
        //   }
      }
      // }
    }

    // if (*(int64_t*)(service_addr + 0x188) == 0 ||
    //     *(int64_t*)(service_addr + 0x188 + 0x10) == 0) {
    if (serviceAddr.add(0x188).readU32() === 0 || serviceAddr.add(0x188 + 0x10).readU32() === 0) {
      //   out.province = std::string();
      out.province = '';
      // } else {
    } else {
      //   if (*(int64_t*)(service_addr + 0x188 + 0x18) == 0xF) {
      //     out.province = std::string((char*)(service_addr + 0x188),
      //                                *(int64_t*)(service_addr + 0x188 + 0x10));
      //   } else {
      //     out.province = std::string(*(char**)(service_addr + 0x188),
      //                                *(int64_t*)(service_addr + 0x188 + 0x10));
      //   }
      // }
      if (serviceAddr.add(0x188 + 0x18).readU32() === 0xF) {
        out.province = serviceAddr.add(0x188).readUtf8String(serviceAddr.add(0x188 + 0x10).readU32());
      } else {
        out.province = serviceAddr.add(0x188).readPointer().readUtf8String(serviceAddr.add(0x188 + 0x10).readU32());
      }
    }

    // if (*(int64_t*)(service_addr + 0x1A8) == 0 ||
    //     *(int64_t*)(service_addr + 0x1A8 + 0x10) == 0) {
    //   out.city = std::string();
    // } else {
    //   if (*(int64_t*)(service_addr + 0x1A8 + 0x18) == 0xF) {
    //     out.city = std::string((char*)(service_addr + 0x1A8),
    //                            *(int64_t*)(service_addr + 0x1A8 + 0x10));
    //   } else {
    //     out.city = std::string(*(char**)(service_addr + 0x1A8),
    //                            *(int64_t*)(service_addr + 0x1A8 + 0x10));
    //   }
    // }

    if (serviceAddr.add(0x1A8).readU32() === 0 || serviceAddr.add(0x1A8 + 0x10).readU32() === 0) {
      out.city = '';
    } else {
      if (serviceAddr.add(0x1A8 + 0x18).readU32() === 0xF) {
        out.city = serviceAddr.add(0x1A8).readUtf8String(serviceAddr.add(0x1A8 + 0x10).readU32());
      } else {
        out.city = serviceAddr.add(0x1A8).readPointer().readUtf8String(serviceAddr.add(0x1A8 + 0x10).readU32());
      }
    }

    // if (*(int64_t*)(service_addr + 0x1E8) == 0 ||
    //     *(int64_t*)(service_addr + 0x1E8 + 0x10) == 0) {
    //   out.name = std::string();
    // } else {
    //   if (*(int64_t*)(service_addr + 0x1E8 + 0x18) == 0xF) {
    //     out.name = std::string((char*)(service_addr + 0x1E8),
    //                            *(int64_t*)(service_addr + 0x1E8 + 0x10));
    //   } else {
    //     out.name = std::string(*(char**)(service_addr + 0x1E8),
    //                            *(int64_t*)(service_addr + 0x1E8 + 0x10));
    //   }
    // }

    if (serviceAddr.add(0x1E8).readU32() === 0 || serviceAddr.add(0x1E8 + 0x10).readU32() === 0) {
      out.name = '';
    } else {
      if (serviceAddr.add(0x1E8 + 0x18).readU32() === 0xF) {
        out.name = serviceAddr.add(0x1E8).readUtf8String(serviceAddr.add(0x1E8 + 0x10).readU32());
      } else {
        out.name = serviceAddr.add(0x1E8).readPointer().readUtf8String(serviceAddr.add(0x1E8 + 0x10).readU32());
      }
    }

    // if (*(int64_t*)(service_addr + 0x450) == 0 ||
    //     *(int64_t*)(service_addr + 0x450 + 0x10) == 0) {
    //   out.head_img = std::string();
    // } else {
    //   out.head_img = std::string(*(char**)(service_addr + 0x450),
    //                              *(int64_t*)(service_addr + 0x450 + 0x10));
    // }

    if (serviceAddr.add(0x450).readU32() === 0 || serviceAddr.add(0x450 + 0x10).readU32() === 0) {
      out.head_img = '';
    } else {
      out.head_img = serviceAddr.add(0x450).readPointer().readUtf8String(serviceAddr.add(0x450 + 0x10).readU32());
    }

    // if (*(int64_t*)(service_addr + 0x7B8) == 0 ||
    //     *(int64_t*)(service_addr + 0x7B8 + 0x10) == 0) {
    //   out.public_key = std::string();
    // } else {
    //   out.public_key = std::string(*(char**)(service_addr + 0x7B8),
    //                                *(int64_t*)(service_addr + 0x7B8 + 0x10));
    // }

    if (serviceAddr.add(0x7B8).readU32() === 0 || serviceAddr.add(0x7B8 + 0x10).readU32() === 0) {
      out.public_key = '';
    } else {
      out.public_key = serviceAddr.add(0x7B8).readPointer().readUtf8String(serviceAddr.add(0x7B8 + 0x10).readU32());
    }

    // if (*(int64_t*)(service_addr + 0x7D8) == 0 ||
    //     *(int64_t*)(service_addr + 0x7D8 + 0x10) == 0) {
    //   out.private_key = std::string();
    // } else {
    //   out.private_key = std::string(*(char**)(service_addr + 0x7D8),
    //                                 *(int64_t*)(service_addr + 0x7D8 + 0x10));
    // }

    if (serviceAddr.add(0x7D8).readU32() === 0 || serviceAddr.add(0x7D8 + 0x10).readU32() === 0) {
      out.private_key = '';
    } else {
      out.private_key = serviceAddr.add(0x7D8).readPointer().readUtf8String(serviceAddr.add(0x7D8 + 0x10).readU32());
    }

  }

  // console.info('out:', JSON.stringify(out, null, 2))

  const myself = {
    id: out.wxid,
    code: out.account,
    name: out.name,
    head_img_url: out.head_img,
  }
  const myselfJson = JSON.stringify(myself, null, 2)
  // console.info('myselfJson:', myselfJson)
  return myselfJson

}

// 发送文本消息
const sendMsg = (contactId: any, text: any) => {
  // console.log('\n\n');
  let to_user: any = null
  let text_msg: any = null
  // const to_user = Memory.alloc(wxid.length * 2 + 2)
  // to_user.writeUtf16String(wxid)
  // to_user = new WeChatString(wxid).getMemoryAddress();
  // console.info('wxid:', wxid)
  to_user = writeWStringPtr(contactId);
  console.info('to_user wxid :', readWStringPtr(to_user).readUtf16String());

  // const text_msg = Memory.alloc(msg.length * 2 + 2)
  // text_msg.writeUtf16String(msg)
  // text_msg = new WeChatString(msg).getMemoryAddress();

  text_msg = writeWStringPtr(text);
  console.info('text_msg msg:', readWStringPtr(text_msg).readUtf16String());
  // console.log('\n\n');

  var send_message_mgr_addr = moduleBaseAddress.add(wxOffsets.kGetSendMessageMgr);
  var send_text_msg_addr = moduleBaseAddress.add(wxOffsets.kSendTextMsg);
  var free_chat_msg_addr = moduleBaseAddress.add(wxOffsets.kFreeChatMsg);

  var chat_msg = Memory.alloc(0x460 * Process.pointerSize); // 在frida中分配0x460字节的内存
  chat_msg.writeByteArray(Array(0x460 * Process.pointerSize).fill(0)); // 清零分配的内存

  var temp = Memory.alloc(3 * Process.pointerSize); // 分配临时数组内存
  temp.writeByteArray(Array(3 * Process.pointerSize).fill(0)); // 初始化数组

  // 定义函数原型并实例化 NativeFunction 对象
  var mgr = new NativeFunction(send_message_mgr_addr, 'void', []);
  var send = new NativeFunction(send_text_msg_addr, 'uint64', ['pointer', 'pointer', 'pointer', 'pointer', 'int64', 'int64', 'int64', 'int64']);
  var free = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);

  // 调用发送消息管理器初始化
  mgr();

  // 发送文本消息
  // console.info('chat_msg:', chat_msg);
  // console.info('to_user:', to_user);
  // console.info('text_msg:', text_msg);
  // console.info('temp:', temp);
  var success = send(chat_msg, to_user, text_msg, temp, 1, 1, 0, 0);

  console.info('sendText success:', success);

  // 释放ChatMsg内存
  free(chat_msg);

  return 0; // 与C++代码保持一致，这里返回0（虽然在C++中这里应该是成功与否的指示符）
}

// // 接收消息回调
const recvMsgNativeCallback = (() => {

  const nativeCallback = new NativeCallback(() => { }, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])
  const nativeativeFunction = new NativeFunction(nativeCallback, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])

  try {
    Interceptor.attach(
      moduleBaseAddress.add(wxOffsets.hookMsg.WX_RECV_MSG_HOOK_OFFSET), {
      onEnter(args) {
        try {
          // 参数打印
          console.log("doAddMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2]);

          // 调用处理函数
          const msg = HandleSyncMsg(args[0], args[1], args[2]);
          // console.log("msg: " + JSON.stringify(msg, null, 2));

          let room = ''
          let talkerId = ''
          let content = ''
          const signature = msg.signature
          const msgType = msg.type

          if (msg.fromUser.indexOf('@') !== -1) {
            room = msg.fromUser
          } else if (msg.toUser.indexOf('@') !== -1) {
            room = msg.toUser
          }

          if (room) {
            const contentArr = msg.content.split(':\n')
            // console.log('contentArr:', contentArr)
            if (contentArr.length > 1) {
              talkerId =
                content = msg.content.replace(`${contentArr[0]}:\n`, '')
            } else {
              content = msg.content
            }
          } else {
            talkerId = msg.fromUser
            content = msg.content
          }


          const myContentPtr = Memory.alloc(content.length * 2 + 1)
          myContentPtr.writeUtf16String(content)

          const myTalkerIdPtr = Memory.alloc(talkerId.length * 2 + 1)
          myTalkerIdPtr.writeUtf16String(talkerId)

          const myGroupMsgSenderIdPtr = Memory.alloc(room.length * 2 + 1)
          myGroupMsgSenderIdPtr.writeUtf16String(room)

          const myXmlContentPtr = Memory.alloc(signature.length * 2 + 1)
          myXmlContentPtr.writeUtf16String(signature)

          const isMyMsg = 0
          const newMsg = {
            msgType, talkerId, content, room, signature, isMyMsg
          }
          console.log('回调消息:', JSON.stringify(newMsg))
          setImmediate(() => nativeativeFunction(msgType, myTalkerIdPtr, myContentPtr, myGroupMsgSenderIdPtr, myXmlContentPtr, isMyMsg))

        } catch (e: any) {
          console.error('接收消息回调失败：', e)
          throw new Error(e)
        }
      },
    })
    return nativeCallback
  } catch (e) {
    console.error('回调消息失败：')
    return null
  }

})()
