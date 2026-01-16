import { offsets } from './offset.js'

const moduleBaseAddress = Module.getBaseAddress('WeChatWin.dll')

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

// modifyContactLabel(['ledongmao'], 'test')

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