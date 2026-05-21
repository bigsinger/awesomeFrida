# 《Android Frida 逆向从入门到精通》

> 基于《安卓Frida逆向与抓包实战》（r0ysue）与 bigsinger/awesomeFrida 的实战参考书
> 定位：从零基础到 SO 逆向精通，覆盖 Java Hook → Native Hook → 脱壳加固 → 综合实战全链路

## 项目结构

全书共 **12 篇（章）72 节**，循序渐进从环境搭建到 SO 层高级逆向：

| 篇 | 主题 | 节数 | 核心内容 |
|----|------|------|----------|
| 一 | 环境准备 | 5 | Frida 架构、环境搭建、frida-server、CLI |
| 二 | Frida入门 | 6 | Hello World、Spawn/Attach、Python客户端 |
| 三 | Java层Hook | 6 | Java.use、重载、构造、字段、枚举 |
| 四 | 主动调用与RPC | 5 | 静态调用、Java.choose、rpc.exports |
| 五 | 网络协议Hook | 6 | OkHttp、Socket、SSL Pinning、Objection |
| 六 | BoringSSL通杀 | 4 | JustTrustMe、BoringSSL、字节系、r0capture |
| 七 | SO/ELF逆向基础 | 4 | ELF结构、dlopen加载、JNI注册、符号枚举 |
| 八 | Native Hook核心 | 6 | Interceptor、导出/未导出、JNI、libc |
| 九 | 高级Native技术 | 6 | dlopen拦截、RegisterNatives、反调试 |
| 十 | DEX脱壳加固 | 6 | DEX结构、FRIDA-DEXDump、360加固 |
| 十一 | 高级主题 | 7 | Stalker、加密追踪、Cocos2d、WebView |
| 十二 | 综合实战 | 6 | 电商抓包、M3U8、Protobuf、混淆脱壳 |

## 素材来源

- **E:\reads\Android\AndroidFridaBeginnersBook-main** — 《安卓Frida逆向与抓包实战》随书附件（Chap01~Chap11）
- **F:\bigsinger\awesomeFrida** — 40+ 个实战 Frida 脚本
- GitHub **CreditTone/hooker** (5.1K⭐) — Frida 逆向工具包
- GitHub **deathmemory/FridaContainer** (1.5K⭐) — Frida 脚本容器
- GitHub **Margular/frida-skeleton** (884⭐) — Hook 框架

## 编写规范

- 所有代码块格式：```javascript / ```python / ```bash / ```java
- 每处代码标注来源：`> 以上代码引用自 ChapXX/xxx.js / awesomeFrida/xxx.js`
- 每节字数：1000~2500 字，至少 2 个可直接运行的代码块
- 导航链接：所有 .md 文件通过 add_navigation.py 自动生成「上一篇/下一篇」


---

**下一篇**：[第1章 · Frida基础与环境搭建](./part1/README.md)
