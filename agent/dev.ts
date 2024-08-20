/**
 * WeChat 3.9.10.27
 * 
 */
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
} from './utils.js'
import {
    Contact,
    Message,
} from './types.js'
import { listeners, prependListener } from 'process'
import test from 'node:test'
import { text } from 'stream/consumers'
import { timeEnd } from 'console'

/*
偏移地址
*/
const offsets = {
    // kDoAddMsg: 0x23D2B10, // done
    kDoAddMsg: 0x2205510, // 3.9.10.27
    kGetAccountServiceMgr: 0x1C1FE90, // 3.9.10.27
    kSyncMsg: 0xc39680,
    kSyncMsgNext: 0xc39680,
    kSendTextMsg: 0x238DDD0, // 3.9.10.27
    kFreeChatMsg: 0x1C1FF10, // 3.9.10.27
    kGetContactMgr: 0x1C0BDE0, // 3.9.10.27
    // const uint64_t kSearchContactMgr = 0x2065F80;
    kSearchContactMgr: 0x2065F80,
    // const uint64_t kChatRoomMgr = 0x1C4E200;
    kChatRoomMgr: 0x1C4E200,
    // const uint64_t kOpLogMgr = 0x1C193C0;
    kOpLogMgr: 0x1C193C0,
    // const uint64_t kSnsTimeLineMgr = 0x2E6B110;
    kSnsTimeLineMgr: 0x2E6B110,
    // const uint64_t kCDNServicecs = 0x1CAE4E0;
    kCDNServicecs: 0x1CAE4E0,
    // const uint64_t kAccountServiceMgr = 0x1C1FE90;
    kAccountServiceMgr: 0x1C1FE90,

    // const uint64_t kGetAppDataSavePath = 0x26A7780;
    kGetAppDataSavePath: 0x26A7780, // done
    // const uint64_t kGetCurrentDataPath = 0x2314E40;
    kGetCurrentDataPath: 0x2314E40, // done

    // const uint64_t kNewContact = 0x25E3650;
    kNewContact: 0x25E3650,
    // const uint64_t kFreeContact = 0x25E3D00;
    kFreeContact: 0x25E3D00,
    // const uint64_t kGetContact = 0x225F950;
    kGetContact: 0x225F950,
    // const uint64_t kDelContact = 0x2263490;
    kDelContact: 0x2263490,
    kGetContactList: 0x2265540, // 3.9.10.27
    // const uint64_t kRemarkContact = 0x22550D0;
    kRemarkContact: 0x22550D0,
    // const uint64_t kBlackContact = 0x2255310;
    kBlackContact: 0x2255310,
    // const uint64_t kGetContactCardContent = 0x2200BB0;
    kGetContactCardContent: 0x2200BB0,

    // const uint64_t kVerifyUser = 0x225C340;								// ContactMgr::doVerifyUser 
    kVerifyUser: 0x225C340,
    // const uint64_t kStartSearchFromScene = 0x2370010;					//SearchContactMgr::StartSearchFromScene
    kStartSearchFromScene: 0x2370010,
    // const uint64_t kNetSceneGetContact = 0x225D060;						//new NetSceneBatchGetContact (id:%d)
    kNetSceneGetContact: 0x225D060,
    // const uint64_t kNetSceneGetContactLabelList = 0x2245F00;            //NetSceneGetContactLabelList::NetSceneGetContactLabelList

    // const uint64_t kSceneCenter = 0x1CDD710;
    kSceneCenter: 0x1CDD710,
    // const uint64_t kSceneNetSceneBase = 0x2454EB0;
    kSceneNetSceneBase: 0x2454EB0,
    // const uint64_t kNewContactLabelIdStruct = 0x2189150;
    // const uint64_t kNetSceneAddContactLabel = 0x245BE40;                //NetSceneAddContactLabel::NetSceneAddContactLabel
    // const uint64_t kNetSceneDelContactLabel = 0x248F410;      

    // const uint64_t kNetSceneModifyContactLabel = 0x250C480;
    kNetSceneModifyContactLabel: 0x250C480,
    kSendMessageMgr: 0x1C1E690, // 3.9.10.27
    // const uint64_t kAppMsgMgr = 0x1C23630;
    kAppMsgMgr: 0x1C23630, // 3.9.10.27
    // const uint64_t kSendTextMsg = 0x238DDD0;
    // const uint64_t kSendImageMsg = 0x2383560;
    kSendImageMsg: 0x2383560, // 3.9.10.27
    // const uint64_t kSendFileMsg = 0x21969E0;
    kSendFileMsg: 0x21969E0, // 3.9.10.27
    kSendPatMsg: 0x2D669B0, // 3.9.10.27
    // const uint64_t kFreeChatMsg = 0x1C1FF10;
    // const uint64_t kNewChatMsg = 0x1C28800;
    kNewChatMsg: 0x1C28800,
    // const uint64_t kCreateChatRoom = 0x221AF50;
    kChatRoomInfoConstructor: 0x25CF470, // 3.9.10.27
    kGetChatRoomDetailInfo: 0x222BEA0, // 3.9.10.27
    kGetChatroomMemberDetail: 0x2226C80, // 3.9.10.27
    // const uint64_t kDoAddMemberToChatRoom = 0x221B8A0;
    // const uint64_t kDoDelMemberFromChatRoom = 0x221BEE0;
    // const uint64_t kInviteMemberToChatRoom = 0x221B280;
    // const uint64_t kQuitAndDelChatRoom = 0x2225EF0;
    kModChatRoomTopic: 0x2364610, // 3.9.10.27
    // const uint64_t kGetA8Key = 0x24ABD40;

    // const uint64_t kTimelineGetFirstPage = 0x2EFE660;
    // const uint64_t kTimelineGetNextPage = 0x2EFEC00;
    // const uint64_t kSnsObjectDetail = 0x2EFDEC0;
    // const uint64_t kSnsObjectLike = 0x2F113D0;
    // const uint64_t kSnsObjectOp = 0x2F13670;
    // const uint64_t kSnsObjectDoComment = 0x2EFD0F0;

    // const uint64_t kStartupDownloadMedia = 0x2596780;

    // const uint64_t kDoAddMsg = 0x23D2B10;
    // const uint64_t kJSLogin =  0x27826A0;
    // const uint64_t kTenPayTransferConfirm = 0x304C700;

    // const uint64_t kSceneCenterStartTask = 0x2454F70;					//must do scene after auth
    // const uint64_t kMessageLoop = 0x397B400;							//Chrome.MessageLoopProblem (__int64 a1, __int64 a2)
    // const uint64_t kWMDestroy = 0x2119240;	
}

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

let selfInfo: any = {}

/*---------------------Base---------------------*/

const checkLogin = () => {
    let success = -1;
    const accout_service_addr = moduleBaseAddress.add(offsets.kGetAccountServiceMgr);
    let getAccountService = new NativeFunction(accout_service_addr, 'pointer', []);
    let service_addr = getAccountService();
    if (!service_addr.isNull()) {
        success = service_addr.add(0x7F8).readU32();
    }
    return success;
}

// console.log('checkLogin:', checkLogin())

/*---------------------ContactSelf---------------------*/
/*
获取登录二维码
*/
async function contactSelfQRCode() { }

/* 
获取自己的信息 3.9.10.27
*/
const contactSelfInfo = () => {

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

selfInfo = contactSelfInfo()
// console.log('call contactSelfInfo res:\n', JSON.stringify(contactSelfInfo(), null, 2))

/*---------------------Contact---------------------*/
/*
获取联系人列表 3.9.10.27
*/
const contactList = () => {
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

// console.log('call contactList() res:\n', JSON.stringify(contactList().length))

// 解析联系人信息，信息不准确
function parseContact(start: any) {
    // console.log('contactPtr:', contactPtr)

    /* Get Contacts:
    call1, call2, wxId, Code, Remark,Name, Gender, Country, Province, City*/
    // { 0x75A4A0, 0xC089F0, 0x10, 0x24, 0x58, 0x6C, 0x0E, 0x00, 0x00, 0x00 },

    const temp: any = {
        wxid: readWideString(start.add(0x10)),
        custom_account: readWideString(start.add(0x30)),
        encrypt_name: readWideString(start.add(0x50)),
        remark: readWideString(start.add(0x80)),
        remark_pinyin: readWideString(start.add(0x148)),
        remark_pinyin_all: readWideString(start.add(0x168)),
        label_ids: readWideString(start.add(0xc0)),
        nickname: readWideString(start.add(0xA0)),
        pinyin: readWideString(start.add(0x108)),
        pinyin_all: readWideString(start.add(0x128)),
        verify_flag: start.add(0x70).readS32(),
        type: start.add(0x74).readS32(),
        reserved1: start.add(0x1F0).readS32(),
        reserved2: start.add(0x1F4).readS32(),
    };
    // console.log('temp:', JSON.stringify(temp, null, 2))

    const info: any = {}

    const contact: Contact = {
        id: temp.wxid,
        gender: 1,
        type: temp.type,
        name: temp.nickname,
        friend: true,
        star: false,
        coworker: temp.wxid.indexOf('@openim') > -1,
        avatar: info.SmallHeadImgUrl,
        address: info.Province + info.City,
        alias: info.Alias,
        city: info.City,
        province: info.Province,
        weixin: temp.custom_account,
        corporation: '',
        title: '',
        description: '',
        phone: [],
    };
    return contact;

}

/*
获取联系人详情-未完成
*/
async function contactRawPayload(wxid: string) {
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

    console.log('contact info:', JSON.stringify(info))



    // 请根据实际情况自行实现清理内存的逻辑
    // 如果contact有destructor，可能需要调用destructor来确保内存被正确释放

    return success;
}

// contactRawPayload('tyutluyc')

/*---------------------Room---------------------*/
/*
获取群列表
*/
function roomList() {
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
                if (contact.id && (contact.id.endsWith('chatroom'))) {
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

// console.log('call roomList() res:\n', JSON.stringify(roomList().length))

/*
获取群详情
*/
async function roomRawPayload(roomId: string) {
    let success = -1;
    let instanceAddr = moduleBaseAddress.add(offsets.kChatRoomMgr);
    let constructorAddr = moduleBaseAddress.add(offsets.kChatRoomInfoConstructor);
    let getChatRoomDetailInfoAddr = moduleBaseAddress.add(offsets.kGetChatRoomDetailInfo);

    let instance = new NativeFunction(instanceAddr, 'pointer', []);
    let constructor = new NativeFunction(constructorAddr, 'pointer', ['pointer']);
    let getChatRoomDetailInfo = new NativeFunction(getChatRoomDetailInfoAddr, 'uint8', ['pointer', 'pointer', 'pointer', 'int']);

    let roomIdStr = writeWStringPtr(roomId);
    let buff = Memory.alloc(0x148);

    // 调用constructor创建ChatRoomInfoBuf
    let chatRoomInfoBuf = constructor(buff);
    const instancePtr = instance();

    console.log('instancePtr:', instancePtr)

    // 调用GetChatRoomDetailInfo
    success = getChatRoomDetailInfo(instancePtr, roomIdStr, chatRoomInfoBuf, 1);

    let info = {};
    if (success === 1) {
        info = {
            id: readWideString(chatRoomInfoBuf.add(0x8)),
            notice: readWideString(chatRoomInfoBuf.add(0x28)),
            admin: readWideString(chatRoomInfoBuf.add(0x48)),
            xml: readWideString(chatRoomInfoBuf.add(0x78)),
        };
        console.log('获取到的聊天室详情信息:', JSON.stringify(info, null, 2));
    } else {
        console.error('获取聊天室详情信息失败');
    }
    return info;
};

// roomRawPayload('21341182572@chatroom')

/*
解散群
*/
async function roomDel(
    roomId: string,
    contactId: string,
) {
    return roomId
}

/*
获取群头像
*/
async function roomAvatar(roomId: string) {
    return ''
}

/*
加入群
*/
async function roomAdd(
    roomId: string,
    contactId: string,
) {

}

/*
设置群名称 3.9.10.27 未完成
*/
async function roomTopic(roomId: string, topic: string) {
    let result: any = -1;
    // 计算instance函数和ModChatRoomTopic函数的地址
    var instanceAddr = moduleBaseAddress.add(offsets.kOpLogMgr);
    var modChatRoomTopicAddr = moduleBaseAddress.add(offsets.kModChatRoomTopic);

    // 定义这两个函数
    var Instance = new NativeFunction(instanceAddr, 'pointer', []);
    var ModChatRoomTopic = new NativeFunction(modChatRoomTopicAddr, 'uint64', ['pointer', 'pointer', 'pointer']);

    const instancePtr = Instance();
    console.log('instancePtr:', instancePtr)

    // 创建roomIdStr和topicStr的内存表示
    var roomIdStrPtr = writeWStringPtr(roomId);
    var topicStrPtr = writeWStringPtr(topic);

    console.log('roomId:', readWStringPtr(roomIdStrPtr).readUtf16String());
    console.log('topic:', readWStringPtr(topicStrPtr).readUtf16String());

    // 调用ModChatRoomTopic
    // result = ModChatRoomTopic(instancePtr, roomIdStrPtr, topicStrPtr);
    console.log("ModChatRoomTopic result:", result);

    return result;
}

// roomTopic('21341182572@chatroom', '大师是群主111')

// 调试：监听函数调用
Interceptor.attach(
    moduleBaseAddress.add(offsets.kModChatRoomTopic), {
    onEnter(args) {
        try {
            // 参数打印
            console.log("called with args: " + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + ", " + args[4] + ", " + args[5] + ", " + args[6] + ", " + args[7]);
            console.log('args[0]:', args[0]);
            console.log('roomId:', readWStringPtr(args[1]).readUtf16String());
            console.log('topic:', readWStringPtr(args[2]).readUtf16String());

        } catch (e: any) {
            console.error('修改群名称失败：', e)
            throw new Error(e)
        }
    },
})

/*
创建群
*/
async function roomCreate(
    contactIdList: string[],
    topic: string,
) {

    return 'mock_room_id'
}

/*
退出群
*/
async function roomQuit(roomId: string): Promise<void> {

}

/*
获取群二维码
*/
async function roomQRCode(roomId: string): Promise<string> {
    return roomId + ' mock qrcode'
}

/*
获取群成员列表
*/
async function roomMemberList(roomId: string) {
    console.log('roomMemberList roomId:', roomId)
}

// roomMemberList('21341182572@chatroom')

/*---------------------Room Invitation---------------------*/
/*
接受群邀请
*/
async function roomInvitationAccept(roomInvitationId: string) { }

/*
获取群邀请
*/
async function roomInvitationRawPayload(roomInvitationId: string): Promise<any> { }

/*---------------------Friendship---------------------*/
/*
获取好友请求
*/
async function friendshipRawPayload(id: string): Promise<any> {
    return { id } as any
}

/*
手机号搜索好友
*/
async function friendshipSearchPhone(
    phone: string,
): Promise<null | string> {
    return null
}

/*
微信号搜索好友
*/
async function friendshipSearchWeixin(
    weixin: string,
): Promise<null | string> {
    return null
}

/*
发送好友请求
*/
async function friendshipAdd(
    contactId: string,
    hello: string,
): Promise<void> { }

/*
接受好友请求
*/
async function friendshipAccept(
    friendshipId: string,
): Promise<void> { }

/*---------------------Tag---------------------*/
/*
联系人标签添加
*/
async function tagContactAdd(
    tagId: string,
    contactId: string,
): Promise<void> { }

/*未完成*/
const modifyContactLabel = (wxidList: string[], labelList: string) => {
    // 定义ContactLabelIdStruct的构造函数
    function createContactLabelIdStruct(wxid: string, label: string) {
        // 分配内存
        let struct = Memory.alloc(0x48); // 结构体大小
        struct.writeU64(0x0); // _0x0
        let wxidStr = Memory.allocUtf16String(wxid);
        struct.add(0x8).writePointer(wxidStr); // buf
        struct.add(0x10).writeU32(wxid.length); // len
        struct.add(0x14).writeU32(wxid.length); // cap
        // 跳过_0x18 和 _0x20
        let labelStr = Memory.allocUtf16String(label);
        struct.add(0x28).writePointer(labelStr); // c_buf
        struct.add(0x30).writeU32(label.length); // c_len
        struct.add(0x34).writeU32(label.length); // c_cap
        // 跳过_0x38 和 _0x40

        return struct;
    }

    // 根据wxidList初始化ContactLabelIdStruct数组
    let structsArray = new Array(wxidList.length);
    for (let i = 0; i < wxidList.length; i++) {
        structsArray[i] = createContactLabelIdStruct(wxidList[i], labelList);
    }

    let vecStruct = Memory.alloc(structsArray.length * Process.pointerSize);
    for (let i = 0; i < structsArray.length; i++) {
        vecStruct.add(i * Process.pointerSize).writePointer(structsArray[i]);
    }

    let netSceneBaseEx = Memory.alloc(0x308); // 伪造NetSceneBaseEx

    var modContactLabelAddr = moduleBaseAddress.add(offsets.kNetSceneModifyContactLabel);
    var modContactLabel = new NativeFunction(modContactLabelAddr, 'uint64', ['pointer', 'pointer']);

    var instanceAddr = moduleBaseAddress.add(offsets.kSceneCenter);
    var instance = new NativeFunction(instanceAddr, 'pointer', []);

    var sceneNetSceneBaseAddr = moduleBaseAddress.add(offsets.kSceneNetSceneBase);
    var sceneNetSceneBase = new NativeFunction(sceneNetSceneBaseAddr, 'int64', ['pointer', 'uint64']);

    return sceneNetSceneBase(instance(), modContactLabel(netSceneBaseEx, vecStruct));
}

// modifyContactLabel(['tyutluyc'], 'test')

/*
联系人标签移除
*/
async function tagContactRemove(
    tagId: string,
    contactId: string,
): Promise<void> { }

/*
联系人标签删除
*/
async function tagContactDelete(
    tagId: string,
): Promise<void> { }

/*
联系人标签列表
*/
async function tagContactList(
    contactId?: string,
): Promise<string[]> {
    return []
}

/*
获取群成员详情
*/
async function roomMemberRawPayload(roomId: string, contactId: string) { }

/*
设置群公告
*/
async function roomAnnounce(roomId: string, text?: string): Promise<void | string> {
    if (text) {
        return
    }
    return 'mock announcement for ' + roomId
}

/*---------------------Message---------------------*/
/*
发送文本消息 3.9.10.27
*/
const messageSendText = (contactId: string, text: string) => {
    let to_user: any = null
    let text_msg: any = null
    to_user = writeWStringPtr(contactId);
    text_msg = writeWStringPtr(text);

    var send_message_mgr_addr = moduleBaseAddress.add(offsets.kSendMessageMgr);
    var send_text_msg_addr = moduleBaseAddress.add(offsets.kSendTextMsg);
    var free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);

    var chat_msg = Memory.alloc(0x460 * Process.pointerSize); // 在frida中分配0x460字节的内存
    chat_msg.writeByteArray(Array(0x460 * Process.pointerSize).fill(0)); // 清零分配的内存

    let temp = Memory.alloc(3 * Process.pointerSize); // 分配临时数组内存
    temp.writeByteArray(Array(3 * Process.pointerSize).fill(0)); // 初始化数组

    // 定义函数原型并实例化 NativeFunction 对象
    var mgr = new NativeFunction(send_message_mgr_addr, 'void', []);
    var send = new NativeFunction(send_text_msg_addr, 'uint64', ['pointer', 'pointer', 'pointer', 'pointer', 'int64', 'int64', 'int64', 'int64']);
    var free = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);

    // 调用发送消息管理器初始化
    mgr();

    // 发送文本消息 
    var success = send(chat_msg, to_user, text_msg, temp, 1, 1, 0, 0);

    console.log('sendText success:', success);

    // 释放ChatMsg内存
    free(chat_msg);

    return Number(success) > 0 ? 1 : 0; // 与C++代码保持一致，这里返回0（虽然在C++中这里应该是成功与否的指示符）
}
// messageSendText('filehelper', 'hello world')

const findAdd = (add: any) => {
    console.log('findAdd is called:', add);
    const max = 10;

    for (let i = 0; i < max; i++) {
        try {
            const offset = i * 0x20;
            console.log('findAdd offset:', i, offset);

            const str = readWideString(add.readPointer().add(offset));
            console.log('findAdd str:', str);

            if (str) {
                console.log('findAdd str is:', i, offset, str);
            } else {
                console.log('findAdd str is not:', i);
                // 终止循环
                break;
            }
            // return i
        } catch (e) {
            console.error('kSendTextMsg arg3-2:', i, e);
            break
        }
    }

    return 'unknown';
}

/*
发送@消息 3.9.10.27-未完成
*/
const messageSendAtText = (contactId:string, text:string, atWxids:string[]) => {
    let nickname = '';
    if (atWxids && atWxids.length && atWxids[0] && atWxids[0] === 'notify@all') {
        nickname = '@所有人';
        text = nickname + ' ' + text;
    }

    const offSize = 0x20

    const tempSize = offSize * atWxids.length;

    // 使用临时缓冲区
    const tempBuffer = Memory.alloc(tempSize);
    console.log('atWxids temp 初始化:', tempBuffer);

    for (let i = 0; i < atWxids.length; i++) {
        const wxoff = offSize * i;
        console.log('写入atWxids:', i, wxoff);
        console.log('写入atWxids字符串:', i, atWxids[i]);
        let wxidWStringPtr = writeWStringPtr(atWxids[i]);
        console.log('写入atWxids写入内存的读取:', i, readWideString(wxidWStringPtr));
        console.log('写入atWxids指针:', i, wxidWStringPtr);
        tempBuffer.add(offSize * i).writePointer(wxidWStringPtr);
        console.log('写入atWxids指针读取:', i, tempBuffer.add(wxoff).readPointer());
        console.log('写入atWxids读取结果:', wxoff, readWideString(tempBuffer.add(wxoff).readPointer()));
    }

    // 复制临时缓冲区到temp，并保护内存为只读
    // Memory.copy(temp, tempBuffer, tempSize);
    // Memory.protect(temp, tempSize, 'r--');

    console.log('atWxids temp 初始化:', tempBuffer);
    console.log('atWxids temp 存储的指针:', tempBuffer.readPointer());

    console.log('messageSendAtText temp 第一个wxid:', 0, readWideString(tempBuffer.add(0).readPointer()));
    // console.log('messageSendAtText temp 第二个wxid:', readWideString(tempBuffer.add(offSize).readPointer()));
    console.log('messageSendAtText temp findAdd:', findAdd(tempBuffer));

    let to_user = writeWStringPtr(contactId);
    let text_msg = writeWStringPtr(text);

    const send_message_mgr_addr = moduleBaseAddress.add(offsets.kSendMessageMgr);
    const send_text_msg_addr = moduleBaseAddress.add(offsets.kSendTextMsg);
    const free_chat_msg_addr = moduleBaseAddress.add(offsets.kFreeChatMsg);

    const chat_msg = Memory.alloc(0x460 * Process.pointerSize); // 在frida中分配0x460字节的内存
    chat_msg.writeByteArray(Array(0x460 * Process.pointerSize).fill(0)); // 清零分配的内存

    // 定义函数原型并实例化 NativeFunction 对象
    const mgr = new NativeFunction(send_message_mgr_addr, 'void', []);
    const send = new NativeFunction(send_text_msg_addr, 'uint64', ['pointer', 'pointer', 'pointer', 'pointer', 'int32', 'int32', 'int32', 'int32']);
    const free = new NativeFunction(free_chat_msg_addr, 'void', ['pointer']);

    // 调用发送消息管理器初始化
    mgr();

    // 发送文本消息
    console.log('messageSendAtText chat_msg:', chat_msg);
    console.log('messageSendAtText to_user:', readWideString(to_user));
    console.log('messageSendAtText text_msg:', readWideString(text_msg));

    const success = send(chat_msg, to_user, text_msg, tempBuffer, 0x1, 0x1, 0x0, 0x0);

    console.log('sendText success:', success);

    // 释放ChatMsg内存
    free(chat_msg);
    // free(temp)

    return Number(success) > 0 ? 1 : 0; // 与C++代码保持一致，这里返回0（虽然在C++中这里应该是成功与否的指示符）
};

// messageSendAtText('21341182572@chatroom', 'hello world all', ['notify@all'])
// messageSendAtText('21341182572@chatroom', '@超哥 hello world', ['tyutluyc', 'wxid_pnza7m7kf9tq12'])
// messageSendAtText('21341182572@chatroom', '@超哥 hello world', ['tyutluyc'])

// 调试：监听函数调用
Interceptor.attach(
    moduleBaseAddress.add(offsets.kSendTextMsg), {
    onEnter(args) {
        try {
            // 参数打印
            console.log("kSendTextMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + ", " + args[4] + ", " + args[5] + ", " + args[6] + ", " + args[7]);
            console.log('kSendTextMsg arg0:', args[0]);
            console.log('kSendTextMsg arg1:', readWideString(args[1]));
            console.log('kSendTextMsg arg2:', readWideString(args[2]));
            console.log('kSendTextMsg arg3-1:', readWideString(args[3].readPointer()));
            console.log('kSendTextMsg arg3-2:', findAdd(args[3]));
            console.log('kSendTextMsg arg4:', args[4].toInt32());
            // console.log('kSendTextMsg arg4:', findType(args[4].add(0x4)));

            console.log('kSendTextMsg arg5:', args[5].toInt32());
            console.log('kSendTextMsg arg6:', args[6].toInt32());
            console.log('kSendTextMsg arg7:', args[7].toInt32());

        } catch (e: any) {
            console.error('kSendTextMsg解析失败：', e)
            throw new Error(e)
        }
    },
})

const findType = (add: any) => {

    try {
        let value = add.readPointer();
        console.log('add is readPointer:', value);
        return 'readPointer';
    } catch (e) {
        console.log('add is not readPointer:', e);
    }

    try {
        let value = add.readUtf16String();
        console.log('add is readUtf16String:', value);
        return 'readUtf16String';
    } catch (e) {
        console.log('add is not readUtf16String:', e);
    }

    try {
        let value = add.readCString();
        console.log('add is readCString:', value);
        return 'readCString';
    } catch (e) {
        console.log('add is not readCString:', e);
    }

    try {
        let value = add.readUtf8String();
        console.log('add is readUtf8String:', value);
        return 'readUtf8String';
    } catch (e) {
        console.log('add is not readUtf8String:', e);
    }

    try {
        let value = add.readS8();
        console.log('add is readS8:', value);
        return 'readS8';
    } catch (e) {
        console.log('add is not readS8:', e);
    }

    try {
        let value = add.readS16();
        console.log('add is readS16:', value);
        return 'readS16';
    } catch (e) {
        console.log('add is not readS16:', e);
    }

    try {
        let value = add.readS32();
        console.log('add is readS32:', value);
        return 'readS32';
    } catch (e) {
        console.log('add is not readS32:', e);
    }

    try {
        let value = add.readS64();
        console.log('add is readS64:', value);
        return 'readS64';
    } catch (e) {
        console.log('add is not readS64:', e);
    }

    try {
        let value = add.readU8();
        console.log('add is readU8:', value);
        return 'readU8';
    } catch (e) {
        console.log('add is not readU8:', e);
    }

    try {
        let value = add.readU16();
        console.log('add is readU16:', value);
        return 'readU16';
    } catch (e) {
        console.log('add is not readU16:', e);
    }

    try {
        let value = add.readU32();
        console.log('add is readU32:', value);
        return 'readU32';
    } catch (e) {
        console.log('add is not readU32:', e);
    }

    try {
        let value = add.readU64();
        console.log('add is readU64:', value);
        return 'readU64';
    } catch (e) {
        console.log('add is not readU64:', e);
    }

    try {
        let value = add.readFloat();
        console.log('add is readFloat:', value);
        return 'readFloat';
    } catch (e) {
        console.log('add is not readFloat:', e);
    }

    try {
        let value = add.readDouble();
        console.log('add is readDouble:', value);
        return 'readDouble';
    } catch (e) {
        console.log('add is not readDouble:', e);
    }

    try {
        let value = add.readByteArray(10);
        console.log('add is readByteArray:', value);
        return 'readByteArray';
    } catch (e) {
        console.log('add is not readByteArray:', e);
    }

    try {
        let value = add.readCString();
        console.log('add is readCString:', value);
        return 'readCString';
    } catch (e) {
        console.log('add is not readCString:', e);
    }

    try {
        let value = add.readUtf8String();
        console.log('add is readUtf8String:', value);
        return 'readUtf8String';
    } catch (e) {
        console.log('add is not readUtf8String:', e);
    }

    try {
        let value = add.readUtf16String();
        console.log('add is readUtf16String:', value);
        return 'readUtf16String';
    } catch (e) {
        console.log('add is not readUtf16String:', e);
    }

    return 'unknown';
}

/*
发送图片消息
*/
async function messageSendFile(
    conversationId: string,
    file: any,
): Promise<void> { }

// 未完成
const sendImageMsg = (wxid: string, fullPath: string) => {
    let success: any = -1;
    // 构造器、实例和函数定义
    var constructorAddr = moduleBaseAddress.add(offsets.kNewChatMsg);
    var destructorAddr = moduleBaseAddress.add(offsets.kFreeChatMsg);
    var instanceAddr = moduleBaseAddress.add(offsets.kSendMessageMgr);
    var sendImageMsgAddr = moduleBaseAddress.add(offsets.kSendImageMsg);

    var Constructor = new NativeFunction(constructorAddr, 'pointer', ['pointer']);
    var Destructor = new NativeFunction(destructorAddr, 'void', ['pointer']);
    var Instance = new NativeFunction(instanceAddr, 'pointer', []);
    var SendImageMsg = new NativeFunction(sendImageMsgAddr, 'int64', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

    // 分配内存并构造ChatMsg对象
    var msg = Memory.alloc(0x490);
    msg.writeByteArray(Array(0x490).fill(0)); // 初始化数组
    var pMsg = Constructor(msg);

    // 分配第二个ChatMsg对象
    var msgTmp = Memory.alloc(0x490);
    msgTmp.writeByteArray(Array(0x490).fill(0)); // 清零分配的内存
    var pMsgTmp = Constructor(msgTmp);


    // 构造toUser和msgStr参数
    var toUserStr = writeWStringPtr(wxid);
    var msgStr = writeWStringPtr(fullPath);

    // 分配和初始化变量
    var flag = Memory.alloc(Process.pointerSize * 10); // 分配一个包含10个指针大小空间的内存块
    var tmp1 = ptr(0);  // 分配一个8字节的内存块，用于存储QWORD
    var tmp2 = ptr(0);  // 分配一个8字节的内存块，用于存储QWORD
    const tmp3 = ptr(1);

    // 设置flag数组中的指针
    flag.writePointer(tmp3);
    flag.add(Process.pointerSize * 8).writePointer(tmp1);  // flag[8] = &tmp1;
    flag.add(Process.pointerSize * 9).writePointer(tmp2);  // flag[9] = &tmp2;
    flag.add(Process.pointerSize).writePointer(pMsgTmp);   // flag[1] = (QWORD *)(pMsgTmp);

    const instance = Instance()
    console.log('instance:', instance)
    console.log('pMsg:', pMsg)
    console.log('toUserStr:', readWideString(toUserStr))
    console.log('msgStr:', readWideString(msgStr))
    console.log('flag:', flag.readS32())

    // sendImageMsg called with args: 0x26eb82a0d50, 0xa4918fb1f0, 0xa4918faac0, 0x26ecd432818, 0xa4918fa9a0, 0x0, 0xa4918fab30, 0x7ff90b20b2fc
    // sendImageMsg arg0: 0x26eb82a0d50
    // sendImageMsg arg1: 0xa4918fb1f0
    // sendImageMsg arg2: filehelper
    // sendImageMsg arg3: C:\Users\tyutl\Downloads\wx_20240618000441.png
    // sendImageMsg arg4: 1

    // instance: 0x26eb82a0d50
    // pMsg: 0x26ecc800600
    // toUserStr: filehelper
    // msgStr: C:\Users\tyutl\Downloads\wx_20240618000441.png
    // flag: 1

    success = SendImageMsg(instance, pMsg, toUserStr, msgStr, flag);

    Destructor(pMsgTmp);
    Destructor(pMsg);

    console.log("SendImageMsg Success:", success);

    return success;
}
// sendImageMsg('tyutluyc', 'C:\\Users\\tyutl\\Documents\\WeChat Files\\wxid_0o1t51l3f57221\\FileStorage\\MsgAttach\\01c2dbb9bb49519d3708de94a13d0d42\\Thumb\\2024-06\\message-7536055685103019865-url-thumb.jpg')
// sendImageMsg('filehelper', 'C:\\Users\\tyutl\\Downloads\\wx_20240618000441.png')

// 调试：监听函数调用
Interceptor.attach(
    moduleBaseAddress.add(offsets.kSendImageMsg), {
    onEnter(args) {
        try {
            // 参数打印
            console.log("sendImageMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + ", " + args[4] + ", " + args[5] + ", " + args[6] + ", " + args[7]);
            console.log('sendImageMsg arg0:', args[0]);
            console.log('sendImageMsg arg1:', args[1]);
            console.log('sendImageMsg arg2:', readWideString(args[2]));
            console.log('sendImageMsg arg3:', readWideString(args[3]));
            console.log('sendImageMsg arg4:', args[4].readS32());

        } catch (e: any) {
            console.error('接收消息回调失败：', e)
            throw new Error(e)
        }
    },
})

/*
发送联系人名片
*/
async function messageSendContact(
    conversationId: string,
    contactId: string,
): Promise<void> {

}

/*
发送链接消息
*/
async function messageSendUrl(
    conversationId: string,
    urlLinkPayload: any,
): Promise<void> {
}

/*
发送小程序消息
*/
async function messageSendMiniProgram(
    conversationId: string,
    miniProgramPayload: any,
): Promise<void> {

}

/*
发送位置消息
*/
async function messageSendLocation(
    conversationId: string,
    locationPayload: any,
): Promise<void | string> {
}

/*
转发消息
*/
async function messageForward(
    conversationId: string,
    messageId: string,
): Promise<void> {

}

/*
拍一拍消息
*/
const sendPatMsg = (roomId: any, contactId: any) => {
    // 定义一个NativeFunction来代表 SendPatMsg 函数
    const SendPatMsg = new NativeFunction(
        moduleBaseAddress.add(offsets.kSendPatMsg),
        'int64', // 假设返回类型为int64
        ['pointer', 'pointer', 'int64']
    );

    // 现在，我们需要一种方式来创建WeChatWString类的实例并将其传递给SendPatMsg。
    // 这里的createWeChatWString函数是一个假设函数，需要你根据WeChatWString的实际内存结构来实现。
    const roomIdStrPointer = writeWStringPtr(roomId);
    const wxidStrPointer = writeWStringPtr(contactId);

    const arg3 = Memory.alloc(0x8);
    arg3.writeU64(0x0);

    try {
        // 调用 SendPatMsg 函数
        const result: any = SendPatMsg(roomIdStrPointer, wxidStrPointer, 0);
        console.log("SendPatMsg 调用结果: ", result);
    } catch (e) {
        console.error("SendPatMsg 调用失败: ", e);
    }
}

// sendPatMsg('21341182572@chatroom', 'tyutluyc')

// 调试：监听函数调用
Interceptor.attach(
    moduleBaseAddress.add(offsets.kSendPatMsg), {
    onEnter(args) {
        try {
            // 参数打印
            console.log("sendImageMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2] + ", " + args[3] + ", " + args[4] + ", " + args[5] + ", " + args[6] + ", " + args[7]);
            console.log('sendImageMsg roomId:', readWStringPtr(args[0]).readUtf16String());
            console.log('sendImageMsg contactId:', readWStringPtr(args[1]).readUtf16String());
            console.log('sendImageMsg arg2:', args[2].readS32());
            console.log('sendImageMsg arg3:', args[3].readUtf16String());
            console.log('sendImageMsg arg4:', args[4].readS32());
            console.log('sendImageMsg arg5:', args[5]);
            console.log('sendImageMsg arg6:', args[6]);
            console.log('sendImageMsg arg7:', args[7]);

        } catch (e: any) {
            console.error('接收消息回调失败：', e)
            throw new Error(e)
        }
    },
})

/*---------------------Hook---------------------*/
/*
接收消息回调 3.9.10.27
*/
const recvMsgNativeCallback = (() => {

    const nativeCallback = new NativeCallback(() => { }, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])
    const nativeativeFunction = new NativeFunction(nativeCallback, 'void', ['int32', 'pointer', 'pointer', 'pointer', 'pointer', 'int32'])

    try {
        Interceptor.attach(
            moduleBaseAddress.add(offsets.kDoAddMsg), {
            onEnter(args) {
                try {
                    // 参数打印
                    // console.log("doAddMsg called with args: " + args[0] + ", " + args[1] + ", " + args[2]);

                    // 调用处理函数
                    const msg = HandleSyncMsg(args[0], args[1], args[2]);
                    // console.log("msg: " + JSON.stringify(msg, null, 2));
                    let room = ''
                    let talkerId = ''
                    let listenerId = ''
                    const text = msg.content
                    const signature = msg.signature
                    const msgType = msg.type
                    const isSelf = msg.isSelf
                    let filename = ''

                    if (msg.fromUser.indexOf('@') !== -1) {
                        room = msg.fromUser
                    } else if (msg.toUser && msg.toUser.indexOf('@') !== -1) {
                        room = msg.toUser
                        talkerId = msg.fromUser
                    }

                    if (room && msg.toUser) {
                        talkerId = msg.toUser
                    } else if (room && !msg.toUser) {
                        talkerId = ''
                    } else {
                        if (msg.isSelf) {
                            talkerId = ''
                            listenerId = msg.fromUser

                        } else {
                            talkerId = msg.fromUser
                        }
                    }

                    if (msgType === 3) {
                        filename = JSON.parse(msg.content)[0]
                    }

                    if (msgType === 49) {
                        const content = msg.content as string
                        // <title>example_upsert.json</title>\n        <des></des>\n        <action>view</action>\n        <type>6</type>\n   
                        // 使用正则提取出文件名和type
                        const subType = content.match(/<type>(\d+)<\/type>/)
                        if (subType && subType[1] === '6') {
                            const filenames = content.match(/<title>(.*)<\/title>/)
                            if (filenames) {
                                const curTime = new Date()
                                filename = `${selfInfo.id}\\FileStorage\\File\\${curTime.getFullYear()}-${curTime.getMonth() < 9 ? '0' : ''}${curTime.getMonth() + 1}\\${filenames[1]}`
                                console.log('filename:', filename)
                            }
                        }
                    }

                    const message: Message = {
                        id: msg.msgId,
                        filename, // 只有在发送文件时需要
                        text,
                        timestamp: msg.createTime,
                        type: msgType,
                        talkerId,
                        roomId: room,
                        mentionIds: [],
                        listenerId, // 在一对一聊天中使用
                        isSelf,
                    }

                    // console.log('message:', JSON.stringify(message, null, 2))

                    send(message)
                    const myContentPtr = Memory.alloc(text.length * 2 + 1)
                    myContentPtr.writeUtf16String(text)

                    const myTalkerIdPtr = Memory.alloc(talkerId.length * 2 + 1)
                    myTalkerIdPtr.writeUtf16String(talkerId)

                    const myGroupMsgSenderIdPtr = Memory.alloc(room.length * 2 + 1)
                    myGroupMsgSenderIdPtr.writeUtf16String(room)

                    const myXmlContentPtr = Memory.alloc(signature.length * 2 + 1)
                    myXmlContentPtr.writeUtf16String(signature)

                    const isMyMsg = 0
                    const newMsg = {
                        msgType, talkerId, text, room, signature, isMyMsg
                    }
                    // console.log('agent 回调消息:', JSON.stringify(newMsg))
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

function HandleSyncMsg(param1: NativePointer, param2: any, param3: any) {
    // console.log("HandleSyncMsg called with param2: " + param2);
    // findIamgePathAddr(param2)

    /* Receive Message:
        Hook,  call, msgId, type, isSelf, ts, roomId, content, wxid, sign, thumb, extra, msgXml */
    // { 0x00, 0x2205510, 0x30, 0x38, 0x3C, 0x44, 0x48, 0x88, 0x240, 0x260, 0x280, 0x2A0, 0x308 },

    const msg: WeChatMessage = {
        fromUser: '',
        toUser: '',
        content: '',
        signature: '',
        msgId: '',
        msgSequence: 0,
        createTime: 0,
        displayFullContent: '',
        type: 0,
        isSelf: false,
    }

    msg.msgId = param2.add(0x30).readS64() // 消息ID
    // console.log("msg.msgId: " + msg.msgId);
    msg.type = param2.add(0x38).readS32(); // 消息类型
    // console.log("msg.type: " + msg.type);
    msg.isSelf = param2.add(0x3C).readS32() === 1; // 是否自己发送的消息
    // console.log("msg.isSelf: " + msg.isSelf);
    msg.createTime = param2.add(0x44).readS32() // 创建时间
    // console.log("msg.createTime: " + msg.createTime);
    msg.content = readWideString(param2.add(0x88)) // 消息内容
    // console.log("msg.content: " + msg.content);
    msg.toUser = readWideString(param2.add(0x240)) // 消息签名
    // console.log("msg.toUser: " + msg.toUser);
    msg.fromUser = readWideString(param2.add(0x48)) // 发送者
    // console.log("msg.fromUser: " + msg.fromUser);
    msg.signature = ReadWeChatStr(param2.add(0x260)) // 消息签名
    // console.log("msg.signature: " + msg.signature);

    const msgXml = getStringByStrAddr(param2.add(0x308)) // 消息签名
    // console.log("msg.msgXml: " + msgXml);

    // 根据消息类型处理图片消息
    if (msg['type'] == 3) {
        const thumb = getStringByStrAddr(param2.add(0x280)) // 消息签名
        // console.log("msg.thumb: " + thumb);

        const extra = getStringByStrAddr(param2.add(0x2A0)) // 消息签名
        // console.log("msg.extra: " + extra);
        // const img = ReadSKBuiltinBuffer(param2.add(0x40).readS64()); // 读取图片数据
        // console.log("img: " + img);
        // msg.base64Img = img; // 将图片数据编码为Base64字符串
        // findIamgePathAddr(param2)
        msg.base64Img = ''
        msg.content = JSON.stringify([
            thumb, //  PUPPET.types.Image.Unknown
            thumb, //  PUPPET.types.Image.Thumbnail
            extra, //  PUPPET.types.Image.HD
            extra, //  PUPPET.types.Image.Artwork
        ])

    }
    // console.log("HandleSyncMsg msg: " + JSON.stringify(msg, null, 2));
    return msg;
}

/*---------------------send&recv---------------------*/
// function onMessage(message: any) {
//     console.log("agent onMessage:", JSON.stringify(message, null, 2));

// }
// recv(onMessage);

// rpc.exports = {
//     callFunction: function (contactId: any, text: any) {
//         return messageSendText(contactId, text);
//     }
// };
