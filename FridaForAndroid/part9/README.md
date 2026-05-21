# 第九篇 · 高级Native技术

> 核心能力：**掌握 SO 加载动态拦截、JNI 注册追踪、符号解析监控、反调试绕过与 init_array 追踪等高级 Native 逆向技术**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [9.1 dlopen动态拦截与延迟Hook](./sections/9.1.md) | 在 SO 加载瞬间拦截并 Hook，解决加载早于注入的问题 | `awesomeFrida/dlopen.js`、`dump-so.js` |
| [9.2 Hook RegisterNatives追踪JNI注册](./sections/9.2.md) | 精准定位所有动态注册的 JNI 函数，获取类名/方法名/C函数地址/偏移 | `awesomeFrida/hook_RegisterNatives.js` 完整69行代码 |
| [9.3 dlopen/dlsym符号解析监控](./sections/9.3.md) | 监控 SO 加载时通过 dlsym 解析的符号，追踪目标库的符号依赖 | `awesomeFrida/dlsym.js`、`System.loadLibrary.js` |
| [9.4 枚举模块与导出符号](./sections/9.4.md) | 系统化枚举模块和符号的技术，批量 Hook 与信息收集 | `Chap11/traceNative.js` traceNativeExport 函数 |
| [9.5 pthread_create反调试线程绕过](./sections/9.5.md) | 拦截、替换、伪造 pthread_create，三种绕过反调试线程方案 | `awesomeFrida/pthread_create.js`、`pthread_create-fake.js`、`pthread_create-replace-jni.js` |
| [9.6 init_array SO初始化函数追踪](./sections/9.6.md) | 使用 CModule 解析 soinfo 结构体，追踪 init_array 执行 | `awesomeFrida/init_array.js` 完整275行代码、`call_constructors.js` |

## 前置知识

- 第七篇：SO/ELF 逆向基础（ELF 结构、符号表、soinfo）
- 第八篇：Native Hook 核心技术（Interceptor 框架、onEnter/onLeave、偏移 Hook）
- ARM64/ARM32 汇编基础
- C 结构体内存布局知识

## 核心概念

| 概念 | 说明 |
|------|------|
| **延迟 Hook** | 在目标 SO 加载后才安装 Hook，解决 Frida 注入时 SO 尚未加载的问题 |
| **dlopen 拦截** | Hook dlopen/android_dlopen_ext，在 SO 加载时刻执行自定义代码 |
| **call_constructors** | linker 内部函数，负责执行 .init_array 构造函数，是拦截 SO 初始化的关键点 |
| **RegisterNatives** | JNI 动态注册的核心 API，Hook 它可以捕获所有动态注册的 native 方法 |
| **dlsym 监控** | 监控符号解析过程，了解目标 SO 依赖了哪些外部符号 |
| **pthread_create** | 线程创建函数，加固库常在此创建反调试监控线程 |
| **init_array** | SO 构造函数数组，加固的检测逻辑和反调试线程常在此执行 |
| **CModule** | Frida 的高级功能，允许在脚本中用 C 代码编写高性能 native 辅助函数 |

## 高级 Native 技术体系

```
SO 加载拦截 → 在 dlopen onLeave 立即行动（9.1）
    ↓
JNI 注册追踪 → Hook RegisterNatives 获取所有注册信息（9.2）
    ↓
符号解析监控 → 追踪 dlsym 调用发现 SO 依赖（9.3）
    ↓
枚举与批量 Hook → 系统化枚举模块和导出函数（9.4）
    ↓
反调试绕过 → 三种方式处理 pthread_create 反调试线程（9.5）
    ↓
init_array 追踪 → 深入 linker 内部拦截构造函数执行（9.6）
```

## 资源引用

- **awesomeFrida/dlopen.js**（35行）：基础 dlopen 拦截
- **awesomeFrida/dump-so.js**（51行）：SO dump + dlopen 延迟 Hook
- **awesomeFrida/hook_RegisterNatives.js**（69行）：完整的 RegisterNatives Hook 框架
- **awesomeFrida/dlsym.js**（100行）：dlopen + dlsym 双重监控
- **awesomeFrida/System.loadLibrary.js**（43行）：Java 层 SO 加载监控
- **awesomeFrida/pthread_create.js**（103行）：pthread_create 拦截方案
- **awesomeFrida/pthread_create-fake.js**（96行）：dlsym 替换方案
- **awesomeFrida/pthread_create-replace-jni.js**（156行）：综合方案
- **awesomeFrida/init_array.js**（275行）：CModule 实现的完整 init_array 追踪
- **awesomeFrida/call_constructors.js**（60行）：call_constructors 拦截基础版
- **Chap11/traceNative.js**（111行）：枚举模块与导出符号框架


---

**上一篇**：[8.6 Hook libc导出函数实战](../part8/sections/8.6.md)
**下一篇**：[9.1 dlopen动态拦截与延迟Hook](sections/9.1.md)
