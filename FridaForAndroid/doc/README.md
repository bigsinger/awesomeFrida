| 文件描述 | 路径 |
|------|------|
| 全书目录 | SUMMARY.md |
| 项目说明 | README.md |
| 修订记录 | CHANGELOG.md |

## 资料引用

本书内容基于以下资料创作：

1. **《安卓Frida逆向与抓包实战》（r0ysue）** — /mnt/e/reads/Android/AndroidFridaBeginnersBook-main/
   - 随书附件：11章完整逆向教程（含SO层Chap11）
   - 代码示例集合（Java层 + Native层 + SSL绕过）

2. **awesomeFrida** — https://github.com/bigsinger/awesomeFrida
   - 40+ 实战Frida脚本（Java层Hook + Native层Hook + 脱壳 + 高级主题）
   - 包含：r0capture、hook_RegisterNatives、init_array、pthread_create 等

3. **Frida 官方文档** — https://frida.re/docs/
   - JavaScript API 参考
   - Android 示例

## 书籍大纲（12篇72节）

| 篇 | 主题 | 节数 | 核心内容 |
|----|------|------|----------|
| 一 | 环境准备 | 5 | Frida架构、环境搭建、frida-server、CLI工具 |
| 二 | Frida入门 | 6 | Hello World、Spawn/Attach、Python客户端 |
| 三 | Java层Hook | 6 | Java.use、重载、构造、字段、枚举类 |
| 四 | 主动调用与RPC | 5 | 静态调用、Java.choose、rpc.exports |
| 五 | 网络协议Hook | 6 | OkHttp、Socket、SSL Pinning、Objection |
| 六 | BoringSSL通杀 | 4 | JustTrustMe、BoringSSL、字节系、r0capture |
| 七 | SO/ELF逆向基础 | 4 | ELF结构、dlopen加载、JNI注册、符号枚举 |
| 八 | Native Hook核心 | 6 | Interceptor、导出/未导出、JNI/libc |
| 九 | 高级Native技术 | 6 | dlopen拦截、RegisterNatives、反调试、init_array |
| 十 | DEX脱壳加固 | 6 | DEX结构、FRIDA-DEXDump、360加固、Lua |
| 十一 | 高级主题 | 7 | Stalker、加密追踪、Cocos2d、WebView、Gadget |
| 十二 | 综合实战 | 6 | 电商抓包、M3U8、Protobuf、混淆脱壳 |

## 文件统计

- 总章节文件：67 节（sections）
- 篇导读文件：12 个（Part README）
- 总文件数：83 个 .md 文件
- 总内容：623,299 字符
- 代码示例：1,466 个代码块
- 表格：133 个
- 导航链接：79/79 完整
