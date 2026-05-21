# 第七篇 · SO/ELF逆向基础

> 核心能力：**掌握 ELF 文件格式与 Android SO 加载机制，为 Native 层 Hook 打下坚实基础**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [7.1 ELF文件结构解析](./sections/7.1.md) | ELF header / section headers / program headers / .symtab / .dynsym / .init_array 等关键段 | `Chap11/r0so/app/src/main/cpp/native-lib.cpp` 第1-47行 |
| [7.2 SO加载流程：dlopen与linker](./sections/7.2.md) | dlopen / android_dlopen_ext 流程、soinfo 结构体、linker 加载链路 | `awesomeFrida/dlopen.js`、`System.loadLibrary.js` |
| [7.3 JNI函数注册机制](./sections/7.3.md) | 静态注册 Java_com_xxx 命名、动态注册 JNI_OnLoad + RegisterNatives | `Chap11/r0so/native-lib.cpp` 第48-59行、`awesomeFrida/JNI_OnLoad.js`、`hook_RegisterNatives.js` |
| [7.4 SO导出表与符号枚举](./sections/7.4.md) | enumerateExports / enumerateSymbols / Process.enumerateModules | `Chap11/traceNative.js` 第25-59行 |

## 前置知识

- 第六篇：BoringSSL 与 SSL 绕过（Native Hook 初体验）
- ARM 汇编基础（了解函数调用约定）
- C/C++ 编译基础（了解链接过程）
- 基本的 JNI 编程概念

## 核心概念

| 概念 | 说明 |
|------|------|
| **ELF** | Executable and Linkable Format，可执行与可链接格式，Linux/Android 的可执行文件和共享库标准格式 |
| **SO** | Shared Object，ELF 格式的动态共享库，Android 中 native 代码的载体 |
| **Linker** | Android 中的动态链接器 (`/system/bin/linker` 或 `linker64`)，负责加载和链接 SO |
| **soinfo** | linker 内部用于描述已加载 SO 的核心结构体，包含基址、符号表、动态段等元信息 |
| **JNI_OnLoad** | SO 加载时由 Java 虚拟机调用的初始化函数，用于动态注册 JNI 函数 |
| **RegisterNatives** | JNI API，用于在运行时动态注册 native 方法与 C 函数的对应关系 |
| **.dynsym / .symtab** | 动态符号表 / 符号表，记录 SO 中导出的函数和全局符号信息 |
| **.init_array** | SO 加载时自动执行的初始化函数数组，常用于加固/反调试 |

## ELF逆向知识体系

```
ELF文件格式解析 (7.1)
       ↓
SO加载流程与linker (7.2)
       ↓
JNI函数注册机制 (7.3)
       ↓
导出表与符号枚举 (7.4)
       ↓
  ┌─── 进入 Part8 ───→ Native层Hook核心技术
  │
  └─── 进入 Part9 ───→ 高级Native技术（动态拦截/反调试）
```

## 资源引用

- **Chap11/r0so/app/src/main/cpp/native-lib.cpp**（60行）：JNI 静态注册 + 动态注册完整示例
- **awesomeFrida/dlopen.js**（35行）：Hook dlopen 监控 SO 加载
- **awesomeFrida/System.loadLibrary.js**（43行）：Hook Java 层 System.loadLibrary
- **awesomeFrida/JNI_OnLoad.js**（69行）：Hook JNI_OnLoad 监控动态注册
- **awesomeFrida/hook_RegisterNatives.js**（69行）：Hook RegisterNatives 追踪所有 JNI 注册
- **Chap11/traceNative.js**（111行）：枚举模块与导出符号框架


---

**上一篇**：[6.4 r0capture通杀SSL抓包](../part6/sections/6.4.md)
**下一篇**：[7.1 ELF文件结构解析](sections/7.1.md)
