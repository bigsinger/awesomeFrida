# 第十一篇 · 高级主题

> 核心能力：**掌握 Stalker CPU 指令级跟踪、Frida 自定义类注册、加密算法实时追踪、Cocos2d-js 游戏 XXTEA 密钥提取、WebView 网络监控、Bitmap 图片解密、以及 Frida Gadget 集成与免 root 注入等全套高级 Frida 技术**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [11.1 Stalker：CPU指令级跟踪](./sections/11.1.md) | Stalker 代码追踪引擎原理、ARM64 指令级监控、性能优化策略 | `awesomeFrida/ZenTracer.js`（117行完整代码） |
| [11.2 自定义类注册](./sections/11.2.md) | Java.registerClass 动态创建 Java 类、Runnable 回调注入 | `Chap03/hello_world.js` 类注册思路 |
| [11.3 加密算法实时追踪框架](./sections/11.3.md) | Hook SecretKeySpec、Cipher、MessageDigest、Mac，全方位追踪加密过程 | `awesomeFrida/javaEnc.js`（完整592行代码） |
| [11.4 Cocos2d-js游戏XXTEA密钥提取](./sections/11.4.md) | 通过 dlopen 拦截 + Interceptor 挂载，提取游戏 XXTEA 加密密钥 | `awesomeFrida/cocos2djs-xxtea-key.js`（完整75行代码） |
| [11.5 WebView网络请求监控](./sections/11.5.md) | Hook WebView.loadUrl 拦截所有 URL 加载请求 | `awesomeFrida/webview-load-url.js`（完整3行代码） |
| [11.6 Bitmap图片解密](./sections/11.6.md) | 四种 Bitmap 保存方案 + AES 解密 + Python 自动化解密框架 | `Chap10/hookBitmap.js`（164行）、`Chap10/saveBitmap.py`（63行） |
| [11.7 Frida Gadget集成与免root注入](./sections/11.7.md) | Gadget 编译集成、配置文件定制、免 root 场景下的注入策略 | Frida Gadget 官方文档 |

## 前置知识

- 第三篇：Java 层 Hook 核心技术（Java.use、overload）
- 第八篇：Native Hook 核心技术（Interceptor.attach、onEnter/onLeave）
- 第九篇：高级 Native 技术（dlopen 拦截、RegisterNatives Hook）
- Java 加密体系基础（JCA/JCE 架构）
- Android 图片编解码基础（BitmapFactory、Bitmap）

## 核心概念

| 概念 | 说明 |
|------|------|
| **Stalker** | Frida 内置的代码追踪引擎，可在 CPU 指令级别监控程序执行流 |
| **代码插桩** | 在目标代码中插入分析指令，不改变原始代码行为 |
| **Java.registerClass** | Frida 允许在运行时动态创建 Java 类并注入到目标进程 |
| **SecretKeySpec** | Java 加密 API 中用于构建密钥的规范类，Hook 可捕获密钥 |
| **XXTEA** | 修正版 TEA 加密算法，Cocos2d-js 游戏常用的脚本加密方案 |
| **WebView.loadUrl** | Android WebView 加载 URL 的核心方法，Hook 可监控页面跳转 |
| **BitmapFactory** | Android 图片解码工厂类，Hook 可截获解码前的加密/原始图片数据 |
| **Frida Gadget** | Frida 的动态链接库形式，可嵌入 APK 实现免 root 注入 |

## 高级技术体系

```
Stalker CPU 指令级跟踪（11.1）
    ↓
运行时动态创建类 —— Java.registerClass（11.2）
    ↓
加密算法全方位追踪（11.3）
    ├── 对称加密（AES/DES）
    ├── 非对称加密（RSA）
    ├── 哈希摘要（MD5/SHA）
    └── MAC 消息认证码
    ↓
游戏逆向专项
    ├── XXTEA 密钥提取（11.4）
    └── Cocos2d-js 游戏脚本解密
    ↓
WebView 网络请求监控（11.5）
    ↓
Bitmap 图片解密方案（11.6）
    ├── Frida 侧 4 种保存策略
    └── Python 自动化解密框架
    ↓
Frida Gadget 免 root 集成（11.7）
```

## 资源引用

- **awesomeFrida/ZenTracer.js**（117行）：Stalker 追踪封装框架，支持正则匹配类名追踪
- **awesomeFrida/javaEnc.js**（592行）：完整的加密算法 Hook 框架，覆盖 SecretKeySpec/Cipher/MessageDigest/Mac/RSA
- **awesomeFrida/cocos2djs-xxtea-key.js**（75行）：Cocos2d-js XXTEA 密钥提取脚本
- **awesomeFrida/webview-load-url.js**（3行）：WebView URL 加载监控脚本
- **Chap10/hookBitmap.js**（164行）：四种 Bitmap 保存方案 + 加密图片解密
- **Chap10/saveBitmap.py**（63行）：Python 自动化 Bitmap 解密框架


---

**上一篇**：[10.6 Dump Lua脚本](../part10/sections/10.6.md)
**下一篇**：[11.1 Stalker：CPU指令级跟踪](sections/11.1.md)
