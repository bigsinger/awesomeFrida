# 第十篇 · DEX加固与脱壳

> 核心能力：**掌握 DEX 文件结构分析、FRIDA-DEXDump 自动化脱壳、Frida 脚本手动 dump DEX/SO、360 加固逆向分析、以及游戏 Lua 脚本提取等完整脱壳技术体系**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [10.1 DEX文件结构与加载流程](./sections/10.1.md) | DEX 文件头、ClassDef、Data 段、加载流程详解 | Android DEX 格式官方规范 |
| [10.2 FRIDA-DEXDump脱壳](./sections/10.2.md) | 主流自动化脱壳工具使用与原理分析 | `awesomeFrida/FRIDA-DEXDump` 相关资料 |
| [10.3 Frida脚本手动Dump DEX](./sections/10.3.md) | Frida 脚本手动搜索并 dump 内存中的 DEX 文件 | `awesomeFrida/hook_RegisterNatives.js`（69行） |
| [10.4 内存Dump：SO文件提取](./sections/10.4.md) | 从内存中完整提取解密后的 SO 文件 | `awesomeFrida/dump_so.js`（51行完整代码） |
| [10.5 360加固分析与脱壳](./sections/10.5.md) | 360 加固特征识别、字符串解密与脱壳实战 | `awesomeFrida/360getString.js`（完整98行代码） |
| [10.6 Dump Lua脚本](./sections/10.6.md) | 从 Cocos2d-x 等游戏引擎中提取加密 Lua 脚本 | `awesomeFrida/MT.js`、`luaL_loadbuffer` Hook |

## 前置知识

- 第七篇：SO/ELF 逆向基础（ELF 结构、符号表）
- 第八篇：Native Hook 核心技术（Interceptor 框架、偏移 Hook）
- 第九篇：高级 Native 技术（dlopen 拦截、RegisterNatives Hook）
- Android DEX/ODEX 文件格式基础
- 常见加固厂商特征（360、腾讯、阿里等）

## 核心概念

| 概念 | 说明 |
|------|------|
| **DEX 脱壳** | 从内存中提取加固壳解密后的原始 DEX 文件 |
| **FRIDA-DEXDump** | 基于 Frida 的自动化 DEX 脱壳工具，通过扫描内存特征定位 DEX |
| **ClassDef** | DEX 文件中定义类的结构体数组，是定位 DEX 关键特征 |
| **DEX magic** | DEX 文件魔数 `dex\n035\0`，内存搜索 DEX 的入口特征 |
| **SO 脱壳** | 从内存中 dump 解密后的 SO 文件，修复 ELF 结构 |
| **360 加固** | 奇虎 360 的 Android 应用加固方案，含字符串加密、反调试等 |
| **StubApp** | 360 加固的核心桩类 `com.stub.StubApp`，包含解密方法 |
| **Lua 脚本提取** | 通过 Hook `luaL_loadbuffer` / `getFileData` 等函数获取游戏 Lua 字节码 |
| **XXTEA 加密** | Cocos2d-x 常用的 Lua 脚本加密算法，加密 key 通常内置于 libgame.so |

## DEX 脱壳技术体系

```
应用启动 → 加固壳加载（壳代码入口）
    ↓
壳解密原始 DEX → 将 DEX 加载到内存
    ↓
DEX 文件结构验证（Magic/Checksum/Signature）
    ↓
方法一：FRIDA-DEXDump 自动扫描（10.2）
    ↓
方法二：Frida 脚本手动搜索 DEX（10.3）
    ↓
SO 脱壳：从内存中 dump 解密 SO（10.4）
    ↓
厂商特定方案：360 加固脱壳（10.5）
    ↓
游戏专项：Lua 脚本提取（10.6）
```

## 资源引用

- **awesomeFrida/FRIDA-DEXDump**：自动化 DEX 脱壳工具集
- **awesomeFrida/hook_RegisterNatives.js**（69行）：RegisterNatives Hook 框架
- **awesomeFrida/dump_so.js**（51行）：SO 内存 dump 脚本
- **awesomeFrida/dump-so.js**（51行）：dlopen + SO dump 综合脚本
- **awesomeFrida/360getString.js**（17行）：360 加固字符串解密脚本
- **awesomeFrida/MT.js**（262行）：Cocos2d-x 游戏逆向框架，含 Lua dump
- **awesomeFrida/r0capture.js**（338行）：通杀 SSL 抓包框架
- **Chap11/traceLibc.js**（73行）：libc 导出函数追踪
- **Chap11/traceNative.js**（111行）：Native 导出符号追踪框架


---

**上一篇**：[9.6 init_array SO初始化函数追踪](../part9/sections/9.6.md)
**下一篇**：[10.1 DEX文件结构与加载流程](sections/10.1.md)
