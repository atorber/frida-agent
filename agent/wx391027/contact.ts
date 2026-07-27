import {
    writeWStringPtr,
    readWStringPtr,
    ReadSKBuiltinString,
    ReadWeChatStr,
    WeChatMessage,
    hasPath,
    uint8ArrayToString,
    stringToUint8Array,
    readAll,
    findIamgePathAddr,
    readString,
    readWideString,
    readStringPtr,
    getStringByStrAddr,
    initStruct,
    initidStruct,
    initmsgStruct,
    parseContact,
} from './utils.js'

import {
    Contact,
    Message,
} from './types.js'

import { offsets } from './offset.js'
import { execDbQuery, lookupContactAvatars } from './sqlite.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

/*---------------------ContactSelf---------------------*/
/*
获取登录二维码
*/
export async function contactSelfQRCode() { }

/* 
获取自己的信息
*/
export function contactSelfInfo() {

    var success = -1;
    var out: any = {};

    // 确定相关函数的地址
    var accountServiceAddr = moduleBaseAddress.add(offsets.kGetAccountServiceMgr);
    var getAppDataSavePathAddr = moduleBaseAddress.add(offsets.kGetAppDataSavePath);
    var getCurrentDataPathAddr = moduleBaseAddress.add(offsets.kGetCurrentDataPath);

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

        if (serviceAddr.add(0x148).readU32() === 0 || serviceAddr.add(0x148 + 0x10).readU32() === 0) {
            out.signature = '';
        } else {
            if (serviceAddr.add(0x148 + 0x18).readU32() === 0xF) {
                out.signature = serviceAddr.add(0x148).readUtf8String(serviceAddr.add(0x148 + 0x10).readU32());
            } else {
                out.signature = serviceAddr.add(0x148).readPointer().readUtf8String(serviceAddr.add(0x148 + 0x10).readU32());
            }

        }

        if (serviceAddr.add(0x168).readU32() === 0 || serviceAddr.add(0x168 + 0x10).readU32() === 0) {

        } else {

            if (serviceAddr.add(0x168 + 0x18).readU32() === 0xF) {

                out.country = serviceAddr.add(0x168).readUtf8String(serviceAddr.add(0x168 + 0x10).readU32());

            } else {

                out.country = serviceAddr.add(0x168).readPointer().readUtf8String(serviceAddr.add(0x168 + 0x10).readU32());

            }

        }

        if (serviceAddr.add(0x188).readU32() === 0 || serviceAddr.add(0x188 + 0x10).readU32() === 0) {

            out.province = '';

        } else {
            if (serviceAddr.add(0x188 + 0x18).readU32() === 0xF) {
                out.province = serviceAddr.add(0x188).readUtf8String(serviceAddr.add(0x188 + 0x10).readU32());
            } else {
                out.province = serviceAddr.add(0x188).readPointer().readUtf8String(serviceAddr.add(0x188 + 0x10).readU32());
            }
        }

        if (serviceAddr.add(0x1A8).readU32() === 0 || serviceAddr.add(0x1A8 + 0x10).readU32() === 0) {
            out.city = '';
        } else {
            if (serviceAddr.add(0x1A8 + 0x18).readU32() === 0xF) {
                out.city = serviceAddr.add(0x1A8).readUtf8String(serviceAddr.add(0x1A8 + 0x10).readU32());
            } else {
                out.city = serviceAddr.add(0x1A8).readPointer().readUtf8String(serviceAddr.add(0x1A8 + 0x10).readU32());
            }
        }

        if (serviceAddr.add(0x1E8).readU32() === 0 || serviceAddr.add(0x1E8 + 0x10).readU32() === 0) {
            out.name = '';
        } else {
            if (serviceAddr.add(0x1E8 + 0x18).readU32() === 0xF) {
                out.name = serviceAddr.add(0x1E8).readUtf8String(serviceAddr.add(0x1E8 + 0x10).readU32());
            } else {
                out.name = serviceAddr.add(0x1E8).readPointer().readUtf8String(serviceAddr.add(0x1E8 + 0x10).readU32());
            }
        }

        if (serviceAddr.add(0x450).readU32() === 0 || serviceAddr.add(0x450 + 0x10).readU32() === 0) {
            out.head_img = '';
        } else {
            out.head_img = serviceAddr.add(0x450).readPointer().readUtf8String(serviceAddr.add(0x450 + 0x10).readU32());
        }

        if (serviceAddr.add(0x7B8).readU32() === 0 || serviceAddr.add(0x7B8 + 0x10).readU32() === 0) {
            out.public_key = '';
        } else {
            out.public_key = serviceAddr.add(0x7B8).readPointer().readUtf8String(serviceAddr.add(0x7B8 + 0x10).readU32());
        }

        if (serviceAddr.add(0x7D8).readU32() === 0 || serviceAddr.add(0x7D8 + 0x10).readU32() === 0) {
            out.private_key = '';
        } else {
            out.private_key = serviceAddr.add(0x7D8).readPointer().readUtf8String(serviceAddr.add(0x7D8 + 0x10).readU32());
        }

    }

    // console.log('out:', JSON.stringify(out, null, 2))

    const myself: Contact = {
        id: out.wxid,
        gender: 1,
        type: out.type,
        name: out.name,
        coworker: true,
        avatar: out.head_img,
        address: '',
        alias: '',
        city: out.city,
        province: out.province,
        weixin: out.account,
        corporation: '',
        title: '',
        description: '',
        phone: [out.mobile],
    };
    return myself

}

/*
获取联系人列表 3.9.10.27
*/
export const contactList = () => {
    // 使用NativeFunction调用相关函数
    const getContactMgrInstance = new NativeFunction(
        moduleBaseAddress.add(offsets.kGetContactMgr),
        'pointer', []
    );
    const getContactListFunction = new NativeFunction(
        moduleBaseAddress.add(offsets.kGetContactList),
        'int64', ['pointer', 'pointer']
    );

    // 获取联系人管理器的实例
    const contactMgrInstance = getContactMgrInstance();

    // 准备用于存储联系人信息的数组
    const contacts: Contact[] = [];
    const contactVecPlaceholder: any = Memory.alloc(Process.pointerSize * 3);
    contactVecPlaceholder.writePointer(ptr(0));  // 初始化指针数组

    const success = getContactListFunction(contactMgrInstance, contactVecPlaceholder);
    const contactVecPtr = contactVecPlaceholder.readU32();

    // 解析联系人信息
    if (success) {
        const contactPtr = contactVecPlaceholder;
        let start = contactPtr.readPointer();
        const end = contactPtr.add(Process.pointerSize * 2).readPointer();

        const CONTACT_SIZE = 0x6A8; // 假设每个联系人数据结构的大小

        while (start.compare(end) < 0) {
            try {
                // console.log('start:', start)
                const contact = parseContact(start);
                // console.log('contact:', JSON.stringify(contact, null, 2))
                // 仅返回个人好友：CONTACT 位 + VerifyFlag=0，排除公众号/陌生人等
                if (contact.id && contact.friend) {
                    contacts.push(contact);
                }
            } catch (error) {
                console.log('contactList() error:', error)
            }
            start = start.add(CONTACT_SIZE);
        }
    }
    // 从 DB 补齐头像（内存结构里 URL 常为空）
    try {
        const avatarMap = lookupContactAvatars(contacts.map((c) => c.id))
        for (const c of contacts) {
            const url = avatarMap.get(c.id)
            if (url) c.avatar = url
        }
    } catch (e) {
        console.log('contactList() avatar enrich error:', e)
    }
    // 按名称正序（空名靠后）
    contacts.sort((a, b) => {
        const na = (a.name || '').trim()
        const nb = (b.name || '').trim()
        if (!na && !nb) return (a.id || '').localeCompare(b.id || '', 'zh-CN')
        if (!na) return 1
        if (!nb) return -1
        const byName = na.localeCompare(nb, 'zh-CN')
        return byName !== 0 ? byName : (a.id || '').localeCompare(b.id || '', 'zh-CN')
    })
    return contacts;
};

/*
获取联系人详情-未完成
*/
export function contactRawPayload(wxid: string) {
    // 用于创建Contact对象的Constructor
    var constructorAddr = moduleBaseAddress.add(offsets.kNewContact);
    var Constructor = new NativeFunction(constructorAddr, 'pointer', ['pointer']);

    // 获取Contact管理器的Instance
    var instanceAddr = moduleBaseAddress.add(offsets.kGetContactMgr);
    var Instance = new NativeFunction(instanceAddr, 'pointer', []);

    // 获取联系人信息的GetContact函数
    var getContactAddr = moduleBaseAddress.add(offsets.kGetContact);
    var GetContact = new NativeFunction(getContactAddr, 'int64', ['pointer', 'pointer', 'pointer']);

    // 构造toUser WeChatWString对象（使用 writeWStringPtr 创建正确的字符串结构）
    var toUserStrPtr = writeWStringPtr(wxid);

    // 分配内存用于存放Contact对象
    var contactBuf = Memory.alloc(0x6B0); // Contact对象所需的内存大小

    // 调用Constructor和GetContact函数
    Constructor(contactBuf); // 构造Contact对象
    var success = GetContact(Instance(), toUserStrPtr, contactBuf);

    // 注意：GetContact 的返回值可能不是错误码，而是其他值（如指针）
    // 即使返回值非0，也可能成功，所以先尝试读取数据
    // 如果读取失败（如 UserName 为空），再判断为失败

    // 读取并转换获取的联系人信息到适当的格式——这需要根据common::ContactCast转换方法的具体实施来确定
    // 假设ContactCast就是简单地将内存信息拷贝到另外一个buffer（实际情况会更复杂）
    var info: any = {}; // 假设这是一个对JavaScript对象的映射
    const start = contactBuf;

    // mmString 字段起始偏移直接用 readWideString；勿再 +0x20（会错读到下一字段）
    const readMm = (off: number): string => {
        try {
            return readWideString(start.add(off)) || ''
        } catch (e) {
            return ''
        }
    }
    // mmString   UserName;			//0x10
    info.UserName = readMm(0x10)
    if (!info.UserName) {
        console.log(`GetContact可能失败: wxid=${wxid}, UserName为空, success=${success}`);
    }
    // mmString   Alias;				//0x30  微信号
    info.Alias = readMm(0x30)
    // mmString   EncryptUserName;		//0x50
    info.EncryptUserName = readMm(0x50)
    // int32_t	   DelFlag;				//0x70
    info.DelFlag = start.add(0x70).readU32();
    // int32_t    Type;				//0x74
    info.Type = start.add(0x74).readU32();
    // int32_t    VerifyFlag;			//0x78
    info.VerifyFlag = start.add(0x78).readU32();
    // mmString   Remark;				//0x80
    info.Remark = readMm(0x80)
    // mmString   NickName;			//0xA0
    info.NickName = readMm(0xA0)
    // mmString   LabelIDList;			//0xC0
    info.LabelIDList = readMm(0xC0)
    // int64_t    ChatRoomType;		//0x100
    info.ChatRoomType = start.add(0x100).readU64().toString()
    // mmString   PYInitial;			//0x108
    info.PYInitial = readMm(0x108)
    // mmString   QuanPin;				//0x128
    info.QuanPin = readMm(0x128)
    // mmString   BigHeadImgUrl;		//0x188
    info.BigHeadImgUrl = readMm(0x188)
    // mmString   SmallHeadImgUrl;		//0x1A8
    info.SmallHeadImgUrl = readMm(0x1A8)

    // //int64_t  ChatRoomNotify;      //0x1E8
    info.ChatRoomNotify = start.add(0x1E8).readU64().toString()
    // mmString   ExtraBuf;			//0x200
    info.ExtraBuf = readMm(0x200)

    // int32_t    ImgFlag;			   //0x220
    info.ImgFlag = start.add(0x220).readU32();
    // int32_t    Sex;				   //0x224
    info.Sex = start.add(0x224).readU32();
    // int32_t    ContactType;		   //0x228
    info.ContactType = start.add(0x228).readU32();

    // mmString  WeiboNickname;		//0x258
    info.WeiboNickname = readMm(0x258)

    // mmString  Country;			  //0x2A0
    info.Country = readMm(0x2A0)

    // mmString  Province;				//0x2D8
    info.Province = readMm(0x2D8)
    // mmString  City;					//0x2F8
    info.City = readMm(0x2F8)
    // int32_t   Source;				//0x318
    info.Source = start.add(0x318).readU32();

    // mmString  VerifyContent;      //0x398
    info.VerifyContent = readMm(0x398)

    // mmString IDCardNum;			//0x420
    info.IDCardNum = readMm(0x420)
    // mmString RealName;			//0x440
    info.RealName = readMm(0x440)

    // mmString ExtInfo;			//0x4A0
    info.ExtInfo = readMm(0x4A0)

    // mmString CardImgUrl;	    //0x4E0
    info.CardImgUrl = readMm(0x4E0)

    // DB 兜底：微信号 / 备注 / 昵称 / 头像
    try {
        const esc = String(wxid).replace(/'/g, "''")
        const rows = execDbQuery(
            'MicroMsg.db',
            `SELECT Alias, Remark, NickName, BigHeadImgUrl, SmallHeadImgUrl ` +
                `FROM Contact WHERE UserName='${esc}' LIMIT 1;`,
        )
        if (rows && rows[0]) {
            const row = rows[0]
            const cell = (v: any): string => {
                if (v === undefined || v === null) return ''
                if (typeof v === 'string') return v
                if (v instanceof Uint8Array) {
                    try {
                        return Array.from(v).map((b) => String.fromCharCode(b)).join('')
                    } catch {
                        return ''
                    }
                }
                return String(v)
            }
            if (!info.Alias) info.Alias = cell(row.Alias)
            if (!info.Remark) info.Remark = cell(row.Remark)
            if (!info.NickName) info.NickName = cell(row.NickName)
            if (!info.BigHeadImgUrl) info.BigHeadImgUrl = cell(row.BigHeadImgUrl)
            if (!info.SmallHeadImgUrl) info.SmallHeadImgUrl = cell(row.SmallHeadImgUrl)
        }
    } catch (e) {
        /* ignore */
    }

    // console.log('contact info:', JSON.stringify(info))

    // 验证是否成功获取联系人信息
    // 如果 UserName 为空，可能表示获取失败
    if (!info.UserName || info.UserName === '') {
        console.log(`GetContact失败: wxid=${wxid}, 无法读取联系人信息`);
        return {
            error: true,
            message: `获取联系人失败: wxid=${wxid}, 无法读取联系人信息`,
            wxid: wxid
        } as any;
    }

    // 请根据实际情况自行实现清理内存的逻辑
    // 如果contact有destructor，可能需要调用destructor来确保内存被正确释放

    return info;
}