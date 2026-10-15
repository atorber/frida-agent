# 微信 4.1.7.30 (Weixin.dll) 发送消息逆向分析

## 1. 从 3.9 到 4.1 的主要变化

### 架构变更
- `WeChatWin.dll`（32位兼容）→ `Weixin.dll`（174MB，纯 AMD64）
- `WeChat.exe` → `Weixin.exe`
- 所有结构体均已升级为64位。std::string 采用 MSVC x64 SSO 格式（32字节：`[data/ptr 16][len 8][cap 8]`，当 cap≤15 时使用内联存储）

### 发送路径完全重写
- **旧 3.9 模式：** 同步直接调用。`GetSendMessageMgr()` → `SendTextMsg(chat_msg_buf, wxid, text, temp, 1, 1, 0, 0)`，共8个参数。偏移量：`kGetSendMessageMgr=0x1C1E690`，`kSendTextMsg=0x238DDD0`
- **新 4.1 模式：** 完全基于协程的异步架构。消息在协程内部通过 `co_with_timeout` 处理。函数通过协程恢复（纤程切换）进入，**不是**普通调用。大量使用虚函数分派——关键发送函数的 E8 调用者数量为**零**。

### 其他变化
- 大部分旧锚点字符串已消失（如 `ContactMgr::doVerifyUser` 等）
- Protobuf 类型字符串仍然存在：`micromsg.SendMsgRequestNew` 位于 rdata+0x81d4728
- SQLite 已静态链接（SQLCipher + WCDB），无导出符号
- 协程标签字符串在运行时仍可见：`co_with_timeout@kernel::foundation::CoCgiSendRequest/318`

## 2. 已确认的发现及复现方法

### 消息接收 Hook（已确认可用）

**偏移量 0xdb4570** — 消息数据库处理函数，接收所有消息（包括发送和接收的消息）

MsgStruct 结构体布局：
```
+0x00 (0x20): std::string talker (wxid)
+0x28 (0x08): server_id (uint64)
+0x48 (0x20): std::string content
+0x88 (0x08): sort_seq
+0x90 (0x04): create_time (unix时间戳)
+0x98 (0x04): status (1=已发送/出站, 2=已接收)
+0x9C (0x04): local_type (1=文本)
```

### 消息发送链（已追踪但尚无法直接调用）

将 Frida 附加到加载了 `Weixin.dll` 的主 `Weixin.exe` 进程：

```javascript
// 此 Hook 可稳定运行，开销极低：
Interceptor.attach(Module.getBaseAddress('Weixin.dll').add(0x4601490), {
    onEnter: function(args) {
        // args[0] = RCX = 会话上下文指针
        // args[1] = RDX = 协程状态指针（约0x800字节的大型结构体）
        // args[2] = R8  = MsgStruct 指针（与接收 Hook 布局相同）
        // args[3] = R9  = 0
        var wxid = readStdString(args[2]);           // +0x00
        var text = readStdString(args[2].add(0x48)); // +0x48
        console.log('发送: 目标=' + wxid + ' 内容=' + text);
    }
});
```

### 完整发送执行链（已通过 Thread.backtrace 确认）

完整调用链，附带已确认的返回地址（来自精确回溯）：

```
线程池工作线程 (0x6102de0)
  → 调度器循环 (0x3ca45a → 0x3ca2e0)
    → 调度器运行 (0x3cb4ba → 0x3cb320)
      → 虚函数分派 (0xbada6a → 0xbada00) — E8调用者为零
        → 任务执行器 (0x1586185 → 0x1585fe0) — 直接 E8 调用协程体
          → 协程体 (0x26e145a → 0x26e1070)
            → 中间层 (0x26e3baa → 0x26e3350) — 构建 0x420 字节的消息结构体
              → 外层发送 (0x26d0c12 → 0x26d0bb0) — 读取 [rcx+0x3a8] 获取 serviceObj
                → 本地插入 (0x4601490) — 仅本地数据库/UI
                → 网络提交 #1 (0x26d0480) — 网络提交
```

第二条网络提交路径（调用 #2 和 #3）：`0x26d2ebb → 0x151e810 → 调度器`

**关键发现：** 整个调用链运行在线程池工作线程上，**不在** UI 线程上。在 UI 线程上创建并投递协程任务的函数在另一个线程上，在这些回溯中**不可见**。

### 各函数角色（已确认）

| 偏移量 | 名称 | 作用 | 可直接调用？ |
|--------|------|------|-----------|
| 0x4601490 | local_insert | 将消息写入本地数据库，更新聊天UI | 否 — 仅本地操作，不影响网络 |
| 0x26d0bb0 | outer_send | 调用 local_insert 后调用 net_submit | 否 — 需要协程帧上下文 |
| 0x26d0480 | net_submit | 实际网络提交，每条消息调用3次 | 否 — 没有协程状态会崩溃 |
| 0x26e3350 | intermediate | 遍历链表，构建消息结构体 | 否 — 从协程体调用 |
| 0x26e1070 | coro_body | 协程恢复函数 | 否 — 需要 MSVC 协程帧 |
| 0x1585fe0 | task_runner | 通过直接 E8 调用协程体 | 否 — 调度器内部使用 |
| 0xbada00 | vdispatch | 通用调度器虚函数分派 | 否 — 所有任务类型都触发，调用频率极高 |

### 已确认：0x4601490 仅为本地操作

**实验验证：** 在 coro_body 和 local_insert 两个 Hook 点同时替换 wxid 和 text。结果：本地聊天 UI 显示了修改后的文本，但**接收方收到的是原始未修改的消息**。这证明 protobuf 序列化发生在 outer_send **之前**。

### net_submit (0x26d0480) 详情

每次发送消息调用3次：
- **调用 #1：** 来自 0x26d0c12（在 outer_send 内部，紧跟 local_insert 之后）。RCX/RDX 为栈指针，文本未以明文形式出现在参数中。
- **调用 #2、#3：** 来自 0x26d2ebb 经 0x151e810（不同的调度器路径）。这些调用中 `[rdx+0x10]` = 上下文对象——可能是实际的消息投递路径。

### 内存扫描：net_submit 时消息数据的分布

在 net_submit 执行时进行全进程 RW 内存扫描，发现 **26 处文本命中**和 **460 处 wxid 命中**，分布在6种不同格式中：

1. **二进制打包格式** — wxid 和 text 连续存放，无分隔符，前面有二进制头：
   ```
   08 1d 0d 04 04 04 04 01 09 08 0d 0d 08
   wxid_udnfp7xmvh3l51HJKL6789
   ```
   在多个堆位置发现。很可能是 protobuf 序列化的 `SendMsgRequestNew`。

2. **std::string SSO 副本** — 6-8个堆上副本，text 在 +0x40 偏移处，len 在 +0x50，cap 在 +0x58

3. **XML msgsource+text** — `</msgsource>HJKL678908 01 10 03`

4. **RichEdit UI 格式** — `<QQRichEditFormat>` 和 `<WeChatRichEditFormat>` XML 包装器

5. **数据库记录** — text + `m-channel-handle=4072`（UTF-16 编码）

6. **net_submit 的 RCX 缓冲区** — 在 +0x60 处有部分 wxid，带二进制前缀 `02 02 08 a1 2f...`

### 协程状态（0x4601490 处的 RDX）布局

```
+0x0C0: std::string wxid (目标用户)
+0x0E0: std::string sender_nickname (发送者昵称)
+0x100: std::string v3_verify_token (V3验证令牌)
+0x1D0: std::string contact_display_name (联系人显示名)
+0x1F0: std::string avatar_url_full (完整头像URL)
+0x210: std::string avatar_url_thumb (缩略头像URL)
+0x230: std::string hash (哈希值)
+0x4D8: std::string wxid (副本)
+0x520: std::string message_text (消息文本)  ← 在此处找到 "traceme"
+0x740: std::string wxid (另一副本)
+0x788: std::string message_text (另一副本)
```

### 0xbada00 如何调用 0x1585fe0（虚函数分派机制）

```asm
mov rax, [rsi+0x130]    ; rsi=this, 加载 +0x130 处的字段
mov rcx, [rax+0x38]     ; 跟随指针，加载 +0x38 处的对象
test rcx, rcx
jz skip
mov rax, [rcx]          ; 加载虚函数表
call [rax+0x10]         ; vtable[2] = 0x1585fe0 用于消息发送
```

两层间接引用：`this->field_0x130->field_0x38->vtable[2]()`

### 协程帧布局（运行时转储）

协程帧（coro_body 入口处的 RCX）结构如下：

```
+0x000: 协程类型描述符指针 → Weixin+0x8192a98
+0x008: 自身指针（指向帧本身）
+0x010: 指向 frame-0x10 的指针
+0x018: 状态值 (uint32) + 4字节数据
+0x020: 标志位
+0x028: Awaitable 描述符 #1 → Weixin+0x8192b58
+0x030: 堆指针（awaitable 状态）
+0x038: Awaitable 数据
  ... 每个 co_await 点重复 0x80 字节的块 ...
+0x0A8: Awaitable 描述符 #2 → Weixin+0x8192be8
+0x128: Awaitable 描述符 #3 → Weixin+0x8192be8
+0x1A8: Awaitable 描述符 #4 → Weixin+0x7c58d58
+0x228: Awaitable 描述符 #5 → Weixin+0x7ca8f88
+0x2A8: Awaitable 描述符 #6 → Weixin+0x7d47d48
+0x328: Awaitable 描述符 #7 → Weixin+0x8192c78
+0x3A8: 服务对象指针（outer_send 的 "outerThis"）
```

**frame+0x3a8 处的服务对象：**
- vtable = Weixin+0x85329e0
- vt[0] = Weixin+0x460b5b0（靠近 local_insert 的 0x4601490）

### 协程类型描述符（位于 Weixin+0x8192a98）

```
+0x00: Weixin+0x26f86e0  (函数指针 — 作用未知)
+0x08: Weixin+0x26c76b0  (函数指针 — 作用未知)
+0x10: Weixin+0x1ff300   (函数指针 — 作用未知)
+0x18: Weixin+0x26cc6a0  (函数指针 — 作用未知)
+0x20: Weixin+0x325f0    (函数指针 — 作用未知)
+0x28: "batch merge size:%d"  (调试格式字符串 — 确认这是发送协程)
```

5个描述符函数全部设置了 Hook — 在文本消息发送过程中**均未触发**。它们可能用于初始化、错误处理或其他消息类型。

整个 DLL 中仅存在2处对此描述符的 LEA 交叉引用：
- **0x26cbc9b：** 帧初始化代码 — `mov [rcx+0x20], 0; lea rax, [desc]; mov [rcx], rax` — 发送时**未触发**（帧可能是预分配的，或通过其他路径初始化）
- **0x26cc310：** 清理/销毁函数（正规函数头，读取 frame+0x498）

### coro_body (0x26e1070) 的 E8 CALL 交叉引用

全 .text 段扫描找到恰好3处直接 CALL 指令：

| 调用位置 | 发送时触发？ | 上下文 |
|-----------|-------------------|---------|
| 0x1586180 | 是 | 任务执行器 — 正常的线程池恢复路径 |
| 0x15990b9 | 否 | 引用计数/清理路径 |
| 0x15cde0b | 否 | 3层调用链：`0x1fbb0 → 0x2e3f60 → 0xda12b0 → coro_body` |

零 LEA 引用、零指针引用、零 MOV-imm64 引用指向 coro_body。恢复指针是**间接存储**的——task_runner 通过硬编码的 `E8 call` 调用它，而非通过帧。

### 协程创建路径

发送时这些函数会触发，但消息文本**不在**它们的参数中：

```
0x316e40  (通用任务执行器 - 246+个调用者，但消息发送时未被调用！)
  → 0x3177c0  (薄包装器)
    → 0x3173c0  (协程设置，调用 0x3c7750)
      → 0x3c7750  (创建协程纤程)
        → 0x3c9a70  (底层纤程创建)
```

**重要：** 0x316e40 在消息发送时调用次数为零。发送协程通过不同的路径创建/恢复。

## 3. 当前卡住的地方

### 核心问题

我们找不到一个可直接调用的、不依赖协程的消息发送入口点。

发送链中的所有函数都在协程上下文内运行。消息文本**不是**作为函数参数传递给我们找到的任何协程创建函数的——它似乎存储在会话/对话对象中，由协程在内部访问。

协程帧由 **UI 线程**上的函数创建并投递到线程池，但该函数在工作线程的回溯中不可见。要找到它需要：
- 直接追踪 UI 线程（噪声大，会导致微信不稳定）
- 查找帧创建代码的交叉引用（穷举搜索仅找到2处描述符的 LEA 引用，发送时均未触发）
- 找到线程池的 PostTask 函数并设置 Hook

### 已尝试但未成功的方法

1. **直接调用 0x4601490 (local_insert)：** 仅本地生效。修改 wxid+text 只改变本地聊天气泡，但接收方收到的是原始消息。网络路由在此函数之前已确定。

2. **直接调用 0x26d0bb0 (outer_send)：** 需要 RCX 处的协程帧包含有效的 `[rcx+0x3a8]` serviceObj。没有正确的协程上下文会崩溃。

3. **直接调用 0x26d0480 (net_submit)：** 空指针崩溃。读取协程上下文之外为 NULL 的协程状态指针。

4. **同时在 coro_body 和 local_insert 拦截：** 在两个 Hook 点同时替换 wxid+text。本地 UI 改变了，**网络不受影响**。protobuf 在 outer_send 之前已序列化完成。

5. **Hook 协程创建函数 (0x3c5ee0, 0x3c7750, 0x3c7ae0, 0x3ce4c0)：** 发送时会触发，但寄存器参数中不携带消息文本。它们只是基础设施调度器。

6. **Hook 0x316e40（有246个调用者的通用任务执行器）：** 消息发送时**从未**被调用（命中0次）。发送协程使用了不同的创建机制。

7. **在 .rdata 中搜索 vtable 指针：** 在整个模块中搜索指向 0x1585fe0、0xbada00、0x26e1070 的8字节运行时指针——在任何位置都未找到匹配。

8. **搜索 protobuf/字符串引用：** 在 0x81d4728 处找到 `micromsg.SendMsgRequestNew`，但无 LEA 交叉引用（通过 protobuf 描述符表引用）。未找到 `SendTextMessage` 和 `CCSendMsgService` 字符串。

9. **对 coro_body (0x26e1070) 的完整交叉引用扫描：** 扫描整个 .text 段查找 LEA、MOV imm64、CALL 和指针引用。仅找到3处 E8 CALL 位置（task_runner 恢复、清理、以及一条发送时不触发的3层调用链）。零 LEA/指针/MOV 引用。恢复指针不是静态存储的。

10. **Hook 协程类型描述符交叉引用：** 在 Weixin+0x8192a98 找到描述符。仅存在2处 LEA 交叉引用（0x26cbc9b 和 0x26cc310）。Hook 了 0x26cbc94（帧初始化指令）——发送时**未触发**。帧可能是预分配的、被复用的，或通过完全不同的代码路径初始化。

11. **Hook 全部5个描述符函数指针：** Hook 了 0x26f86e0、0x26c76b0、0x26cc6a0（以及间接的 0x1ff300、0x325f0）。文本消息发送时**全部未触发**。

12. **对 vdispatch (0xbada00) 设置带回溯的 Hook：** 每秒触发约25次以上，覆盖所有计划任务类型，不仅仅是发送。噪声太大，Interceptor 开销导致微信崩溃。

13. **在协程入口/处理函数上设置重型 Hook：** 在 0xbada00 或 0x3ca2e0 处深度扫描参数会干扰发送流程——重型 instrumentation 启用后 0x4601490 停止触发。

### 尚未尝试的方向

1. **Hook 线程池的 PostTask/入队函数** — 找到任务被**加入**线程池队列的位置（与 0x3ca2e0/0x3cb320 出队操作互补的函数）。这样可以捕获 UI 线程的回溯。

2. **Hook `operator new` / 堆分配**，按协程帧大小过滤 — 在帧分配时捕获，获取创建者的 UI 线程回溯。

3. **监控 UI 线程** — 在工作线程上 outer_send 触发的同一时间，使用 Frida Stalker 或针对性 Hook 监控 UI 线程。

4. **研究二进制打包格式** — 包含 wxid+text 连续数据的 protobuf 序列化数据存在于内存中。找到其构建位置，看能否自行构建+提交，完全绕过协程。

5. **UI 自动化** — 使用 Win32 的 SendMessage/PostMessage 模拟输入文本并点击发送按钮。无需对发送路径进行任何逆向分析。

6. **WCDB 插入 + 同步触发** — 直接将消息写入数据库，然后触发网络同步机制。

7. **查看 wxhelper 或其他项目**是否已有微信 4.x 的发送偏移量。

### 给有 3.x 经验者的关键问题

- 在 3.9 中，`kSendTextMsg` 是直接调用的（同步），还是也经过某种异步分派？如果是同步的，4.x 中可能不存在等价的单一函数。
- 在 4.x 中是否存在"消息服务"或"聊天管理器"单例，可以调用其方法？旧的 `GetSendMessageMgr` 模式可能有对应的等价物。
- 能否完全绕过协程，通过构造 protobuf `SendMsgRequestNew` 并调用底层网络发送函数来实现？
- 是否有其他微信 4.x 逆向项目（wxhelper 分支等）已经找到了发送偏移量？

## 4. 从零开始复现这些结果的方法

### 前置条件
- 已安装并登录微信 4.1.7.30 的 Windows 电脑
- Python 3.x 并安装 `frida` 包（`pip install frida frida-tools`）
- 用于测试发送消息的第二个微信账号

### 找到正确的进程
微信会生成多个 `Weixin.exe` 进程。需要找到加载了 `Weixin.dll` 的那个：

```python
import frida
device = frida.get_local_device()
for proc in device.enumerate_processes():
    if proc.name == "Weixin.exe":
        try:
            s = device.attach(proc.pid)
            sc = s.create_script('send(Process.getModuleByName("Weixin.dll").base.toString())')
            r = []
            sc.on('message', lambda m, d: r.append(m))
            sc.load(); time.sleep(0.3); sc.unload(); s.detach()
            if r and r[0]['type'] == 'send':
                print(f"主进程: PID {proc.pid}")
        except:
            continue
```

### 如何找到接收处理函数 (0xdb4570)

**策略：从 SQLite 向上追踪。**

1. **在 DLL 中定位 SQLite。** SQLite 3.27.2 已静态链接（无导出符号）。版本字符串 `"3.27.2"` 位于 rdata+0x82bed20。加密上下文初始化模式 `20 00 00 00 10 00 00 00 10 00 00 00 00 10 00 00` 可用于识别 SQLCipher 入口点。

2. **找到 WCDB 执行包装器。** WCDB 在 SQLite 上封装了自己的层。通过从 SQLCipher 编解码器回调（0x2f6c520、0x2f687a0）向上追踪，找到 0x12d1d50 作为 WCDB 核心执行函数。

3. **Hook WCDB 执行函数并发送一条消息。** Hook 0x12d1d50（或更高层的 0x2f8e030 SQLite 入口），然后从另一个账号发送一条已知文本（如"tatata"）。捕获回溯信息。

4. **从数据库写入向上追踪。** 回溯显示：
   ```
   0x2429b0a → 0xdb4570 (消息处理函数)
   0xdb4145 → 0x12d1d50 (WCDB 执行)
   0x461031d → 0xdb4100 (数据库表初始化)
   ```
   函数 0xdb4570 在每条消息（发送和接收）时都会被调用。其第二个参数 (RDX) 即为 MsgStruct。

5. **映射结构体。** 发送一条已知文本，然后在 0xdb4570 处读取 arg1 内存。std::string 字段间隔 0x20 字节。wxid 在 +0x00，内容在 +0x48。对比发送和接收消息以找到 status 字段（+0x98：1=已发送，2=已接收）。

**替代方法：** 在 DLL 中搜索数据库 schema 字符串 `"Msg_"` 或 `"message_content"`，然后找到引用这些字符串的代码。这会指向相同的 0xdb4xxx 函数区域。

### 如何找到发送 Hook 点 (0x4601490)

**策略：从发出消息的数据库写入向上追踪，穿过协程链。**

1. **从接收处理函数开始。** 我们已知 0xdb4570 对发出的消息也会触发（status=1）。设置 Hook 并过滤 status==1（仅发出消息），在发送消息时捕获回溯。

2. **识别发送专用分支。** 发出消息的回溯经过：
   ```
   0x460ff30 → 0x4610870 → 0x2415a40 → 0x2429ac0 → 0xdb4570
   ```
   函数 0x460ff30 是调用链中第一个发送专用函数。它接受一个带 0x58 字节上下文前缀的 MsgStruct（wxid 在 +0x58，内容在 +0xA0）。

3. **找到 0x4601490。** Hook 0x460ff30 并查看其调用者/回溯。或扫描目标为 0x460ff30 的 E8 调用——你会发现 0x4601490 调用了它。也可以搜索 0x460xxxx 附近接受干净 MsgStruct（无前缀）的函数。0x4601490 接受 `(session_ctx, coroutine_state, MsgStruct*, 0)`，其中 MsgStruct 使用标准布局（wxid 在 +0x00，内容在 +0x48）。

4. **用轻量级 Hook 验证。** 对 0x4601490 设置 Hook，代码量最小（只读取两个 std::string），然后发送一条测试消息。重型 instrumentation（深度内存扫描、每次调用都获取回溯）会导致协程崩溃或卡死。

5. **获取精确回溯。** 验证通过后，在 Hook 中添加 `Thread.backtrace(this.context, Backtracer.ACCURATE)`。这会揭示完整的协程内部调用链。FUZZY 回溯在协程内部不可靠——它们会混合来自不同纤程栈的帧。

### 如何追踪协程基础设施

6. **将回溯地址解析为函数入口点。** 对回溯中的每个返回地址，在内存中向前扫描函数序言（如 `55 41 57`、`48 89 5c`、`48 83 ec`），前面应是 `CC`（int3 填充）或 `C3`（ret）。这样可以得到函数入口点。

7. **用 Python+Frida RPC 查找 E8 调用者。** 通过 `rpc.exports` 从 Python 分块读取 DLL 代码段，扫描 `E8 xx xx xx xx` 中相对目标匹配函数入口的指令。这比在 Frida JS 中操作快几个数量级。关键发现：重要函数（0xbada00、0x1585fe0）的 E8 调用者为零——它们仅通过虚函数分派调用。

8. **读取协程状态中的字符串。** 在 0x4601490 处，RDX 指向协程状态。以 0x20 字节为增量扫描，尝试将每段数据作为 std::string 读取（检查长度/容量是否合理，然后读取数据）。这揭示了联系人信息布局（wxid、昵称、头像 URL）以及 +0x520 处的消息文本。

### 工具使用注意事项

- **Python+Frida RPC 混合方式不可或缺。** 纯 Frida JS Hook 如果在高频协程路径内进行大量内存扫描（>0x200 字节），会导致微信卡死或崩溃。应改用轻量级 JS Hook 只捕获指针/值，然后通过 `rpc.exports.readBytes()` 从 Python 端进行重型分析。
- **微信在逆向过程中经常崩溃。** 进程需要约30秒重启并重新登录。将 Hook 脚本保存到文件，使用可自动检测 PID 的 Python 运行器。
- **Process.enumerateRanges('rw-')** 必须使用字符串参数（不是对象）。必须在脚本加载时调用（在 Interceptor Hook 之外），以避免 `TypeError: not a function`。
- **全 .text 段扫描**（LEA/CALL 交叉引用扫描）必须在 `setTimeout()` 中运行，以避免 Frida 脚本加载超时。使用 `rpc.exports` 从 Python 轮询完成状态。
- **避免 Hook 0xbada00 (vdispatch)** — 它对所有计划任务触发（每秒25次以上），造成巨大开销并导致崩溃。
- **std::string 读取器**（MSVC x64 SSO）是最重要的工具函数：
  ```javascript
  function readStdString(addr) {
      var buf = addr.readByteArray(0x20);
      var view = new DataView(buf);
      var len = Number(view.getBigUint64(0x10, true));
      var cap = Number(view.getBigUint64(0x18, true));
      if (len > 0x10000 || cap > 0x10000 || len === 0) return null;
      var dataPtr = (cap <= 15) ? addr : addr.readPointer();
      return dataPtr.readUtf8String(Math.min(len, 200));
  }
  ```
- **全 RW 内存扫描**模式（用于在全进程内存中查找字符串）：
  ```javascript
  // 在加载时预枚举，不要在 Hook 内部执行
  var rwRanges = Process.enumerateRanges('rw-');
  function scanAllRW(pattern) {
      var hits = [];
      for (var r = 0; r < rwRanges.length; r++) {
          try {
              var matches = Memory.scanSync(rwRanges[r].base, rwRanges[r].size, pattern);
              for (var m = 0; m < matches.length; m++) hits.push(matches[m].address);
          } catch(e) {}
      }
      return hits;
  }
  ```

## 5. 脚本参考

所有脚本位于 `Y:\puppet-xp\scripts\`：

| 脚本 | 用途 |
|--------|---------|
| `trace_send_callers.js` / `run_trace_callers.py` | Hook 所有发送链函数并获取 Thread.backtrace |
| `find_coro_ramp.js` / `run_find_coro_ramp.py` | 搜索指向 coro_body 的 LEA/CALL/MOV/指针交叉引用 |
| `find_descriptor_refs.js` / `run_find_descriptor_refs.py` | 搜索指向协程类型描述符的交叉引用 |
| `dump_coro_frame.js` / `run_dump_coro_frame.py` | 运行时转储协程帧布局 |
| `trace_coro_creation.js` / `run_trace_coro_creation.py` | Hook 帧初始化 + 描述符函数 |
| `deep_search_send.js` / `run_deep_search.py` | 在 net_submit 时进行全 RW 内存扫描查找 text/wxid |
| `dump_net_submit_data.js` / `run_dump_net_submit.py` | 在 net_submit 时转储托管对象 |
| `find_protobuf_send.js` / `run_find_protobuf.py` | 反汇编关键函数，查找 protobuf 字符串引用 |
