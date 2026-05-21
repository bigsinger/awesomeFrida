# 第十二篇 · 综合实战

> 核心能力：**综合运用前十一篇所学知识，完成电商 App 抓包、视频 App M3U8 解密、Protobuf/gRPC 协议逆向、Xposed 与 Frida 混合使用、混淆 App 脱壳分析与性能优化等全套实战任务**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [12.1 电商App抓包方案](./sections/12.1.md) | OkHttp Hook + Socket Hook + SSL 绕过组合使用，全方位捕获电商 App 网络请求 | `awesomeFrida/hook_okhttp3.js`、`Chap08/hookSocket.js`、`awesomeFrida/r0capture.js` |
| [12.2 视频App解密：M3U8替换](./sections/12.2.md) | Hook java.net.URL 替换 M3U8 地址参数，突破视频时长/试看限制 | `awesomeFrida/replaceM3U8url.js`（完整29行代码） |
| [12.3 Protobuf/gRPC协议逆向](./sections/12.3.md) | gRPC Hook 方法、Protobuf 序列化拦截、Binder 通信监控 | `awesomeFrida/BinderProxy.js`（完整40行代码） |
| [12.4 Xposed与Frida混合使用](./sections/12.4.md) | Xposed 与 Frida 优劣对比、联合使用策略、模块化注入架构 | Xposed API 框架、Frida Gadget |
| [12.5 混淆App分析与脱壳](./sections/12.5.md) | 360 加固字符串解密、Dump DEX/Lua 脚本、SO 文件提取 | `awesomeFrida/360getString.js`（17行）、`awesomeFrida/MT.js`（262行） |
| [12.6 Frida性能优化与调试技巧](./sections/12.6.md) | 脚本执行优化、内存泄漏排查、反检测绕过、稳定性提升 | Frida 官方文档、社区最佳实践 |

## 前置知识

- 第五篇：网络协议 Hook（OkHttp、HttpURLConnection、Socket）
- 第六篇：BoringSSL 与通杀 SSL 方案
- 第七篇：SO/ELF 逆向基础（JNI、符号枚举）
- 第八篇：Native Hook 核心技术（Interceptor.attach）
- 第九篇：动态拦截与反调试（dlopen 延迟 Hook、RegisterNatives）
- 第十篇：DEX 加固与脱壳（FRIDA-DEXDump、360 加固分析）
- 第十一篇：高级 Frida 技术（Stalker、加密追踪、Bitmap 解密）

## 核心概念

| 概念 | 说明 |
|------|------|
| **联合 Hook** | 同时使用 OkHttp 层、Socket 层、SSL 层三层 Hook，实现无死角网络监控 |
| **M3U8 替换** | 通过 Hook URL 构造函数，动态修改视频流请求参数（如 start/end） |
| **gRPC** | Google 开源的高性能 RPC 框架，基于 HTTP/2 + Protobuf 序列化 |
| **Protobuf** | Protocol Buffers，Google 的跨语言数据序列化格式 |
| **BinderProxy** | Android Binder 通信的代理类，Hook transact 可监控 IPC 调用 |
| **Xposed** | Android 框架 Hook 方案，通过替换 app_process 实现全局注入 |
| **360 加固** | 奇虎 360 的 APK 加固方案，包含字符串加密、DEX 保护等 |
| **反检测优化** | 针对 Frida 检测的绕过策略，包括端口检测、线程检测、扫描检测 |

## 综合实战技术体系

```
电商 App 抓包（12.1）
    ├── OkHttp 拦截器注入 → 捕获 HTTP 请求/响应
    ├── Socket 读写 Hook → 捕获原始 TCP 数据
    └── SSL 绕过 → r0capture 通杀 / JustTrustMe
    ↓
视频 App 解密（12.2）
    ├── M3U8 URL 参数替换 → 突破试看/时长限制
    └── Hook URL 构造函数 → 全局 URL 监控
    ↓
协议逆向（12.3）
    ├── gRPC Hook → 拦截 HTTP/2 流式调用
    ├── Protobuf 序列化拦截 → 解析二进制协议
    └── BinderProxy Hook → 监控跨进程调用
    ↓
混合框架（12.4）
    ├── Xposed 持久化 Hook → 开机自启
    └── Frida 动态注入 → 运行时灵活调试
    ↓
混淆脱壳（12.5）
    ├── 360 字符串解密 → StubApp.getString2
    ├── Lua 脚本提取 → Cocos2d getFileData
    └── DEX/SO Dump → FRIDA-DEXDump / dump-so.js
    ↓
性能优化（12.6）
    ├── 脚本执行优化 → setImmediate / setTimeout 策略
    ├── 内存泄漏排查 → Stalker.garbageCollect
    └── 反检测绕过 → 端口/线程/扫描检测绕过
```

## 资源引用

- **awesomeFrida/r0capture.js**（338行）：通杀 SSL 抓包脚本，支持 SSL_read/SSL_write Hook + 客户端证书 Dump + Socket 读写监控
- **awesomeFrida/byPassSSL.js**（59行）：字节系 App BoringSSL 绕过方案，使用 SSL_CTX_set_custom_verify 通杀
- **awesomeFrida/BinderProxy.js**（40行）：Hook BinderProxy.transact 监控 Android Binder 跨进程调用
- **awesomeFrida/replaceM3U8url.js**（29行）：通过 Hook java.net.URL 构造函数实现 M3U8 地址参数替换
- **awesomeFrida/byteDance.js**（118行）：字节系 App SSL Pinning 绕过，含 3 种绕过方法
- **awesomeFrida/MT.js**（262行）：MT 管理器 Lua 脚本提取，含 dlopen 延迟 Hook + getFileData + luaL_loadbuffer
- **awesomeFrida/360getString.js**（17行）：360 加固字符串解密工具
- **Chap10/hookBitmap.js**（164行）：四种 Bitmap 保存方案 + 加密图片解密
- **Chap10/saveBitmap.py**（63行）：Python 自动化 Bitmap 解密框架（AES-CBC 解密）
- **Chap08/OkHttpLogger-Frida**：OkHttp 拦截器注入方案，利用 Java.registerClass 动态创建拦截器
- **Chap08/hookSocket.js**（98行）：Socket 读写 Hook + SSL Socket Hook 完整方案


---

**上一篇**：[11.7 Frida Gadget集成与免root注入](../part11/sections/11.7.md)
**下一篇**：[12.1 电商App抓包方案](sections/12.1.md)
