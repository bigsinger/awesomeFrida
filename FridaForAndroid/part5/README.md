# 第五篇 · 网络协议Hook实战

> 核心能力：**掌握 Android 主流网络库的 Hook 技巧，从 OkHttp 到原生 Socket，从抓包到绕过 SSL Pinning**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [5.1 OkHttp Hook：拦截器注入](./sections/5.1.md) | 通过 `Java.registerClass` 注册自定义 Interceptor 注入 OkHttp 调用链 | `Chap08/hookInteceptor.js`、`awesomeFrida/hook_okhttp3.js` |
| [5.2 OkHttp newCall Hook](./sections/5.2.md) | Hook `OkHttpClient.newCall` 拦截 Request/Response | `Chap08/hookNewCall.js`、`awesomeFrida/hook_okhttp3.js` |
| [5.3 HttpURLConnection Hook](./sections/5.3.md) | Hook `URL.openConnection` + `HttpURLConnectionImpl` 系列方法 | `Chap08/HttpURLConnectionHook.js` |
| [5.4 Socket与SSL Socket Hook](./sections/5.4.md) | Hook `SocketOutputStream` / `InputStream`、SSL Socket 类 | `Chap08/SocketInit.txt`、`Chap08/SocketSuper.txt`、`Chap08/hookSocket.js`、`Chap11/hookSSL_write.js`、`awesomeFrida/BinderProxy.js` |
| [5.5 SSL Pinning绕过基础](./sections/5.5.md) | Hook `CertificatePinner.check`、`TrustManagerImpl.checkServerTrusted`、`KeyStore.load` | `Chap10/hookCertificatePinner.js`、`Chap10/hookCert.js` |
| [5.6 Objection一键绕过SSL Pinning](./sections/5.6.md) | 使用 Objection 的 `android sslpinning disable` 命令快速绕过 | Objection 官方文档 |

## 前置知识

- 第四篇：主动调用与 RPC
- Android 网络编程基础：OkHttp、HttpURLConnection、Socket
- 代理抓包工具（Charles / Burp Suite）的基本使用

## 核心概念

| 概念 | 说明 |
|------|------|
| **OkHttp Interceptor** | OkHttp 的拦截器设计模式，可拦截 Request/Response 做日志或篡改 |
| **OkHttpClient.newCall** | 每次网络请求的入口方法 |
| **HttpURLConnection** | Java 原生 HTTP 客户端，底层由 `com.android.okhttp` 实现 |
| **Socket/SSLSocket** | TCP 层与 TLS 层的直接读写 |
| **SSL Pinning** | 证书绑定，将服务端证书固定到客户端，防止中间人攻击 |
| **Objection** | 基于 Frida 的运行时移动安全探索框架 |

## 资源引用

- **Chap08/** 目录：OkHttp 拦截器、newCall、HttpURLConnection、Socket Hook 完整代码
- **Chap10/** 目录：SSL Pinning 绕过脚本
- **Chap11/hookSSL_write.js**：Native 层 SSL_write Hook
- **awesomeFrida/hook_okhttp3.js**：生产级 OkHttp 全量 Hook
- **awesomeFrida/BinderProxy.js**：Binder 调用追踪辅助


---

**上一篇**：[4.5 内部类Hook与调用](../part4/sections/4.5.md)
**下一篇**：[5.1 OkHttp Hook：拦截器注入](sections/5.1.md)
