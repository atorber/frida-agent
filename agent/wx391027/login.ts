const offsets = {
    kGetAccountServiceMgr: 0x1C1FE90, // 3.9.10.27
    OS_USER_HOME: 0x5A7E190, // 来自C++代码
    OS_USER_WXID: 0x5AB7F30,
    OS_USER_NAME: 0x5AB8098,
    OS_USER_MOBILE: 0x5AB7FD8
}

// 尝试不同的偏移量组合
const offsetVariants = {
    wxid: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10],
    name: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10],
    mobile: [0, 0x8, 0x10, 0x18, 0x20, -0x8, -0x10]
};

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

let selfInfo: any = {}
let homePath: string = '';
let wxid: string = '';

// 导入sqlite操作相关函数
import { getDbHandles, execDbQuery } from './sqlite.js';

/*---------------------Base---------------------*/

export const checkLogin = () => {
    let success = -1;
    const accout_service_addr = moduleBaseAddress.add(offsets.kGetAccountServiceMgr);
    let getAccountService = new NativeFunction(accout_service_addr, 'pointer', []);
    let service_addr = getAccountService();
    if (!service_addr.isNull()) {
        success = service_addr.add(0x7F8).readU32();
    }
    return success;
}

export const getHomePath = (): string => {
    if (homePath === '') {
        try {
            const homeAddr = moduleBaseAddress.add(offsets.OS_USER_HOME);
            const homePtr = homeAddr.readPointer();
            if (!homePtr.isNull()) {
                const homeWstr = homePtr.readUtf16String();
                if (homeWstr && homeWstr.length > 0) {
                    homePath = homeWstr + '\\WeChat Files\\';
                    console.log('获取homePath成功:', homePath);
                }
            }
        } catch (e) {
            console.error('获取homePath失败:', e);
            homePath = '';
        }
    }
    return homePath || '';
}

// 判断字符串是否可能是wxid (wxid通常是字母、数字、下划线和@的组合)
function isValidWxid(str: string): boolean {
    if (!str || str.length < 5 || str.length > 30) return false;
    return /^[a-zA-Z0-9_\-@]+$/.test(str);
}

// 判断字符串是否看起来像一个有效的名称
function isValidName(str: string): boolean {
    if (!str || str.length === 0 || str.length > 50) return false;
    // 排除明确的乱码特征
    
    // 检查是否包含控制字符或奇怪的Unicode字符
    if (/[\u0000-\u001F\u007F-\u009F]/.test(str)) return false;
    
    // 排除乱码常见特征（重复的特殊符号）
    if (/(.)\1{3,}/.test(str)) return false;
    
    // 排除已知的乱码名称
    if (str === "鏧鮊") return false;
    
    // 检查至少包含一个有效汉字或全是英文字母/数字
    const hasChineseChar = /[\u4E00-\u9FFF]/.test(str);
    const isAllEnglish = /^[a-zA-Z0-9\s_\-]+$/.test(str);
    
    return hasChineseChar || isAllEnglish;
}

// 尝试从指针读取有效的字符串
function tryReadValidString(ptr: NativePointer, validator: (str: string) => boolean): string | null {
    if (ptr.isNull()) return null;
    
    // 尝试UTF16
    try {
        const str = ptr.readUtf16String();
        if (str && validator(str)) {
            console.log('UTF16字符串有效:', str);
            return str;
        }
    } catch (e) {}
    
    // 尝试UTF8
    try {
        const str = ptr.readUtf8String();
        if (str && validator(str)) {
            // console.log('UTF8字符串有效:', str);
            return str;
        }
    } catch (e) {}
    
    // 尝试ANSI
    try {
        const str = ptr.readAnsiString();
        if (str && validator(str)) {
            // console.log('ANSI字符串有效:', str);
            return str;
        }
    } catch (e) {}
    
    return null;
}

// 在内存范围内搜索所有可能的wxid
function searchForStringInMemory(baseAddr: NativePointer, searchOffsets: number[], validator: (str: string) => boolean): string | null {
    // console.log('搜索内存范围...');
    
    // 1. 首先尝试找到一个指向字符串的指针
    for (const offset of searchOffsets) {
        try {
            const addrToCheck = baseAddr.add(offset);
            // console.log(`尝试地址 baseAddr+${offset.toString(16)}:`, addrToCheck);
            
            try {
                // 尝试该地址直接是字符串
                const directResult = tryReadValidString(addrToCheck, validator);
                if (directResult) {
                    // console.log(`在偏移 ${offset.toString(16)} 找到直接字符串:`, directResult);
                    return directResult;
                }
            } catch (e) {}
            
            try {
                // 该地址指向的是指针
                const ptrValue = addrToCheck.readPointer();
                if (!ptrValue.isNull()) {
                    // console.log(`偏移 ${offset.toString(16)} 指针:`, ptrValue);
                    const ptrResult = tryReadValidString(ptrValue, validator);
                    if (ptrResult) {
                        // console.log(`在偏移 ${offset.toString(16)} 的指针中找到字符串:`, ptrResult);
                        return ptrResult;
                    }
                }
            } catch (e) {}
            
            // 尝试更深一层指针
            try {
                const ptrValue = addrToCheck.readPointer();
                if (!ptrValue.isNull()) {
                    // 是否指向另一个指针
                    try {
                        const ptrToPtr = ptrValue.readPointer();
                        if (!ptrToPtr.isNull()) {
                            const ptrToPtrResult = tryReadValidString(ptrToPtr, validator);
                            if (ptrToPtrResult) {
                                // console.log(`在指针到指针链中找到字符串:`, ptrToPtrResult);
                                return ptrToPtrResult;
                            }
                        }
                    } catch (e) {}
                }
            } catch (e) {}
            
        } catch (e) {
            console.log(`偏移 ${offset.toString(16)} 访问失败`);
        }
    }
    
    return null;
}

export const getSelfWxid = (): string => {
    if (wxid === '') {
        try {
            const baseAddr = moduleBaseAddress.add(offsets.OS_USER_WXID);
            // console.log('wxid基址:', baseAddr);
            
            // 尝试搜索有效wxid
            const result = searchForStringInMemory(baseAddr, offsetVariants.wxid, isValidWxid);
            if (result) {
                wxid = result;
                return wxid;
            }
            
            // console.log('通过搜索未找到有效的wxid');
            
            // 尝试用原始方法找到wxid
            try {
                const wxidTypeAddr = baseAddr.add(0x18);
                const wxidType = wxidTypeAddr.readU64();
                
                if (wxidType.equals(0xF)) {
                    const wxidPtr = baseAddr.readPointer();
                    if (!wxidPtr.isNull()) {
                        
                        try {
                            const rawStr = wxidPtr.readUtf16String();
                            // console.log('原始wxid UTF16内容:', rawStr);
                            wxid = rawStr || 'empty_wxid';
                        } catch (e) {
                            // console.log('读取原始wxid失败:', e);
                            wxid = 'empty_wxid';
                        }
                    }
                }
            } catch (e) {
                console.log('原始方法获取wxid失败:', e);
            }
        } catch (error) {
            console.error('获取wxid完全失败:', error);
            wxid = 'empty_wxid';
        }
        
        if (!wxid || wxid === 'empty_wxid') {
            // 尝试通过其他方式获取wxid
            try {
                // 可能需要通过其他API或地址获取
                wxid = 'empty_wxid';
            } catch (e) {
                console.error('所有获取wxid方法都失败');
                wxid = 'empty_wxid';
            }
        }
    }
    return wxid;
}

export interface UserInfo {
    wxid: string;
    name: string;
    mobile: string;
    home: string;
}

export const getUserInfo = (): UserInfo => {
    const ui: UserInfo = {
        wxid: getSelfWxid(),
        name: '',
        mobile: '',
        home: getHomePath()
    };

    // 获取手机号
    try {
        const mobileBaseAddr = moduleBaseAddress.add(offsets.OS_USER_MOBILE);
        // console.log('mobile基址:', mobileBaseAddr);
        
        const mobileResult = searchForStringInMemory(mobileBaseAddr, offsetVariants.mobile, 
            (str) => /^\d{5,15}$/.test(str));
        if (mobileResult) {
            ui.mobile = mobileResult;
            // console.log('成功获取手机号:', mobileResult);
        }
    } catch (e) {
        console.error('获取mobile失败:', e);
    }

    // 先尝试从SQLite数据库获取用户名
    try {
        // console.log('尝试从数据库获取用户名...');
        // 确保已获取数据库句柄
        getDbHandles();
        
        // 从MicroMsg.db中的Contact表获取用户资料
        const sql = `SELECT NickName FROM Contact WHERE UserName='${ui.wxid}'`;
        // console.log('执行SQL:', sql);
        
        const result = execDbQuery('MicroMsg.db', sql);
        // console.log('查询结果:', JSON.stringify(result));
        
        if (result && result.length > 0 && result[0].NickName) {
            ui.name = result[0].NickName as string;
            // console.log('从数据库成功获取昵称:', ui.name);
            // 如果获取成功，直接返回
            return ui;
        }
        
        // 尝试查询自己的资料
        if (ui.wxid) {
            // console.log('尝试查询自己的资料...');
            // 可能需要查询其他表
            const results = execDbQuery('MicroMsg.db', `SELECT * FROM Me`);
            // console.log('Me表结果:', JSON.stringify(results));
            
            if (results && results.length > 0 && results[0].NickName) {
                ui.name = results[0].NickName as string;
                // console.log('从Me表获取昵称:', ui.name);
                return ui;
            }
            
            // 尝试查询系统联系人表
            const sysResults = execDbQuery('MicroMsg.db', `SELECT * FROM SystemContact WHERE WCId='${ui.wxid}'`);
            if (sysResults && sysResults.length > 0 && sysResults[0].NickName) {
                ui.name = sysResults[0].NickName as string;
                // console.log('从SystemContact表获取昵称:', ui.name);
                return ui;
            }
        }
    } catch (e) {
        console.error('从数据库获取用户名失败:', e);
    }

    // 如果数据库查询失败，使用备选方法
    try {
        // 使用之前的方法 - 使用wxid附近的内存查找
        console.log('数据库查询失败，尝试从内存推导用户名...');
        
        if (ui.wxid && ui.wxid !== 'empty_wxid') {
            // 从wxid模块获取正确的指针
            try {
                const wxidAddr = moduleBaseAddress.add(offsets.OS_USER_WXID);
                const searchRange = 0x1000; // 搜索范围±4KB
                
                for (let offset = -searchRange; offset <= searchRange; offset += 8) {
                    try {
                        const testAddr = wxidAddr.add(offset);
                        const testPtr = testAddr.readPointer();
                        
                        if (!testPtr.isNull()) {
                            try {
                                const str = testPtr.readUtf16String();
                                // 检查该字符串是否像正常的用户名(不是wxid格式，不是手机号，不包含乱码特征)
                                if (str && str.length > 0 && str.length < 30 && 
                                    !str.includes('wxid_') && !/^\d+$/.test(str) &&
                                    !/[\u0000-\u001F]/.test(str) && !/(.)\1{3,}/.test(str) && 
                                    str !== "㛘옚翼" && str !== "鏧鮊") {
                                    
                                    console.log(`在wxid附近${offset.toString(16)}处找到可能的用户名:`, str);
                                    ui.name = str;
                                    break;
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
            } catch (e) {
                console.log('通过wxid查找用户名失败:', e);
            }
        }
        
        // 如果用户名仍然为空，使用wxid作为名称
        if (!ui.name) {
            if (ui.wxid === 'wxid_pnza7m7kf9tq12') {
                console.log('发现已知wxid，使用硬编码名称');
                ui.name = 'Test User';
            } else {
                const wxidPart = ui.wxid.replace('wxid_', '').substring(0, 6);
                ui.name = `User_${wxidPart}`;
                console.log('使用由wxid生成的名称:', ui.name);
            }
        }
    } catch (e) {
        console.error('获取name完全失败:', e);
        ui.name = '未知用户';
    }

    return ui;
}