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
    parseContact
} from './utils.js'

import {
    Contact,
    Message,
} from './types.js'

const offsets = {
    kGetAccountServiceMgr: 0x1C1FE90, // 3.9.10.27
    kGetAppDataSavePath: 0x26A7780, // done
    kGetCurrentDataPath: 0x2314E40, // done
    kGetContactMgr: 0x1C0BDE0, // done
    kGetContactList: 0x2265540, // done
    kNewContact: 0x25E3650,
    kGetContact: 0x225F950,
}

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
                if (contact.id && (!contact.id.endsWith('chatroom'))) {
                    contacts.push(contact);
                }
            } catch (error) {
                console.log('contactList() error:', error)
            }
            start = start.add(CONTACT_SIZE);
        }
    }
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

    // 构造toUser WeChatWString对象
    var toUserStr = Memory.allocUtf16String(wxid);
    var toUserStrPtr = Memory.alloc(Process.pointerSize);
    toUserStrPtr.writePointer(toUserStr);

    // 分配内存用于存放Contact对象
    var contactBuf = Memory.alloc(0x6B0); // Contact对象所需的内存大小

    // 调用Constructor和GetContact函数
    Constructor(contactBuf); // 构造Contact对象
    var success = GetContact(Instance(), toUserStrPtr, contactBuf);

    // 读取并转换获取的联系人信息到适当的格式——这需要根据common::ContactCast转换方法的具体实施来确定
    // 假设ContactCast就是简单地将内存信息拷贝到另外一个buffer（实际情况会更复杂）
    var info: any = {}; // 假设这是一个对JavaScript对象的映射
    const start = contactBuf;
    // mmString   UserName;			//0x10  + 0x20
    info.UserName = readWideString(start.add(0x10));
    // mmString   Alias;				//0x30  + 0x20
    info.Alias = start.add(0x30 + 0x20).readPointer().readUtf16String();
    // mmString   EncryptUserName;		//0x50  + 0x20
    // const EncryptUserName = start.add(0x50 + 0x20).readPointer().readUtf16String();
    // console.log('EncryptUserName:', EncryptUserName)
    // int32_t	   DelFlag;				//0x70  + 0x4
    info.DelFlag = start.add(0x70).readU32();
    // int32_t    Type;				//0x74  + 0x4
    info.Type = start.add(0x74 + 0x4).readU32();
    // int32_t    VerifyFlag;			//0x78  + 0x4
    // int32_t	   _0x7C;				//0x7C  + 0x4
    // mmString   Remark;				//0x80  + 0x20
    info.Remark = start.add(0x80 + 0x20).readPointer().readUtf16String();
    // mmString   NickName;			//0xA0  + 0x20
    info.NickName = readWideString(start.add(0xA0));
    // mmString   LabelIDList;			//0xC0  + 0x20
    info.LabelIDList = start.add(0xC0 + 0x20).readPointer().readUtf16String();
    // mmString   DomainList;			//0xE0  + 0x20
    // int64_t    ChatRoomType;		//0x100 + 0x8
    info.ChatRoomType = start.add(0x100).readPointer().readUtf16String();
    // mmString   PYInitial;			//0x108 + 0x20
    info.PYInitial = start.add(0x108 + 0x20).readPointer().readUtf16String();
    // mmString   QuanPin;				//0x128 + 0x20
    info.QuanPin = start.add(0x128 + 0x20).readPointer().readUtf16String();
    // mmString   RemarkPYInitial;		//0x148 + 0x20
    // mmString   RemarkQuanPin;		//0x168 + 0x20
    // mmString   BigHeadImgUrl;		//0x188 + 0x20
    info.BigHeadImgUrl = readWideString(start.add(0x188 + 0x20));
    // mmString   SmallHeadImgUrl;		//0x1A8 + 0x20
    info.SmallHeadImgUrl = readWideString(start.add(0x1A8));
    // mmString   _HeadImgMd5;			//0x1C8 + 0x20 

    // //int64_t  ChatRoomNotify;      //0x1E8
    info.ChatRoomNotify = start.add(0x1E8).readPointer().readUtf16String();
    // char       _0x1E8[24];			//0x1E8 + 0x18
    // mmString   ExtraBuf;			//0x200 + 0x20
    info.ExtraBuf = start.add(0x200 + 0x20).readPointer().readUtf16String();

    // int32_t    ImgFlag;			   //0x220 + 0x4
    info.ImgFlag = start.add(0x220).readU32();
    // int32_t    Sex;				   //0x224 + 0x4
    info.Sex = start.add(0x224).readU32();
    // int32_t    ContactType;		   //0x228 + 0x4
    info.ContactType = start.add(0x228).readU32();
    // int32_t   _0x22C;			   //0x22c + 0x4

    // mmString  Weibo;				//0x230 + 0x20
    // int32_t   WeiboFlag;			//0x250 + 0x4
    // int32_t   _0x254;				//0x254 + 0x4

    // mmString  WeiboNickname;		//0x258 + 0x20
    info.WeiboNickname = readWideString(start.add(0x258 + 0x20));

    // int32_t  PersonalCard;		   //0x278 + 0x4
    // int32_t  _0x27C;			   //0x27c + 0x4

    // mmString  Signature;		  //0x280 + 0x20
    // mmString  Country;			  //0x2A0 + 0x20
    info.Country = readWideString(start.add(0x2A0 + 0x20));

    // std::vector<mmString>  PhoneNumberList; //0x2C0 + 0x18

    // mmString  Province;				//0x2D8 + 0x20
    info.Province = start.add(0x2D8 + 0x20).readUtf16String();
    // mmString  City;					//0x2F8 + 0x20
    info.City = start.add(0x2F8 + 0x20).readUtf16String();
    // int32_t   Source;				//0x318 + 0x4
    info.Source = start.add(0x318).readU32();
    // int32_t   _0x31C;				//0x31C + 0x4

    // mmString  VerifyInfo;			//0x320 + 0x20
    // mmString  RemarkDesc;		   //0x340 + 0x20
    // mmString  RemarkImgUrl;		   //0x360 + 0x20

    // int32_t   BitMask;			  //0x380 + 0x4
    // int32_t   BitVal;			  //0x384 + 0x4
    // int32_t   AddContactScene;	  //0x388 + 0x4
    // int32_t   HasWeiXinHdHeadImg; //0x38c + 0x4
    // int32_t   Level;			  //0x390 + 0x4
    // int32_t   _0x394;			  //0x394 + 0x4

    // mmString  VerifyContent;      //0x398 + 0x20
    info.VerifyContent = start.add(0x398 + 0x20).readPointer().readUtf16String();
    // int32_t  AlbumStyle;	      //0x3B8 + 0x4
    // int32_t  AlbumFlag;			  //0x3BC + 0x4
    // mmString AlbumBGImgID;		  //0x3C0 + 0x20

    // int64_t  _0x3E0;			 //0x3E0 + 0x8

    // int32_t  SnsFlag;			//0x3E8	+ 0x4
    // int32_t  _0x3EC;			//0x3EC + 0x4

    // mmString  SnsBGImgID;		//0x3F0 + 0x20

    // int64_t  SnsBGObjectID;		//0x410 + 0x8

    // int32_t  SnsFlagEx;			//0x418 + 0x4
    // int32_t  _0x41C;			//0x41C + 0x4

    // mmString IDCardNum;			//0x420 + 0x20
    info.IDCardNum = start.add(0x420 + 0x20).readPointer().readUtf16String();
    // mmString RealName;			//0x440 + 0x20
    info.RealName = start.add(0x440 + 0x20).readPointer().readUtf16String();

    // mmString MobileHash;		//0x460 + 0x20
    // mmString MobileFullHash;    //0x480 + 0x20

    // mmString ExtInfo;			//0x4A0 + 0x20
    info.ExtInfo = start.add(0x4A0 + 0x20).readPointer().readUtf16String();
    // mmString _0x4C0;		    //0x4C0 + 0x20

    // mmString CardImgUrl;	    //0x4EO + 0x20
    info.CardImgUrl = start.add(0x4E0 + 0x20).readPointer().readUtf16String();
    // char _res[0x1A8];           //0x500 + 

    // console.log('contact info:', JSON.stringify(info))



    // 请根据实际情况自行实现清理内存的逻辑
    // 如果contact有destructor，可能需要调用destructor来确保内存被正确释放

    return info;
}