# 第六篇 · BoringSSL与高级SSL绕过

> 核心能力：**从 JustTrustMe 到 r0capture，掌握 Android SSL Pinning 的完整绕过体系**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [6.1 JustTrustMe通杀方案](./sections/6.1.md) | 全面分析 JustTrustMe 的 20+ 个 Hook 点，覆盖 OkHttp / 原生 TLS / HttpURLConnection | `awesomeFrida/just_trust_me.js`、`just_trust_me_okhttp_hook_finder.js` |
| [6.2 BoringSSL（Chromium系）绕过](./sections/6.2.md) | Hook `SSL_CTX_set_custom_verify`、内存 Patch 绕过 Chrome 系 App 的 BoringSSL | `awesomeFrida/byPassSSL.js` |
| [6.3 字节系App抓包方案](./sections/6.3.md) | 面向抖音/头条等 `libsscronet.so` 的三类绕过方案 | `awesomeFrida/byPassSSL.js`、`byteDance.js` |
| [6.4 r0capture通杀SSL抓包](./sections/6.4.md) | 生产级 SSL 抓包工具 r0capture 完整源码解析 | `awesomeFrida/r0capture.js` |

## 前置知识

- 第五篇：网络协议 Hook（OkHttp、Socket、SSL Pinning）
- Native Hook 基础（Interceptor.attach、Module.getExportByName）
- ARM64 汇编基础（6.2~6.3 节）

## 核心概念

| 概念 | 说明 |
|------|------|
| **JustTrustMe** | 基于 Xposed 的 SSL Pinning 绕过模块，Frida 重写了其所有 Hook 点 |
| **OkHttp Hook Finder** | 自动定位混淆后 OkHttp 类与方法名 |
| **BoringSSL** | Google 的 OpenSSL 分支，Chrome/Chromium/WebView 使用 |
| **SSL_CTX_set_custom_verify** | BoringSSL 自定义证书校验入口，绕过此函数即可绕过 SSL Pinning |
| **libsscronet.so** | Chromium 网络栈，字节系 App 使用 |
| **r0capture** | 《安卓Frida逆向与抓包实战》作者 r0ysue 开发的通杀 SSL 抓包工具 |

## SSL绕过方案演进

```
JustTrustMe (单App方案)
    ↓
just_trust_me.js (Frida化, 通杀OkHttp/原生TLS)
    ↓
byPassSSL.js (BoringSSL通用绕过)
    ↓
byteDance.js (字节系专用)
    ↓
r0capture.js (Native+Java双层面通杀)
```

## 资源引用

- **awesomeFrida/just_trust_me.js**（409行）：JustTrustMe Frida 完整移植
- **awesomeFrida/just_trust_me_okhttp_hook_finder.js**（70行）：混淆 OkHttp 自动定位
- **awesomeFrida/byPassSSL.js**（59行）：BoringSSL 通用绕过
- **awesomeFrida/byteDance.js**（118行）：字节系 App 专杀
- **awesomeFrida/r0capture.js**（338行）：通杀 SSL 抓包完整源码


---

**上一篇**：[5.6 Objection一键绕过SSL Pinning](../part5/sections/5.6.md)
**下一篇**：[6.1 JustTrustMe通杀方案](sections/6.1.md)
