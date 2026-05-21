# 第八篇 · Native层Hook核心技术

> 核心能力：**系统掌握 Frida Interceptor 框架，从导出函数到未导出函数，从 JNI 到 libc，全面覆盖 Native 层 Hook 技术栈**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [8.1 Interceptor.attach基础](./sections/8.1.md) | Interceptor 框架核心概念、attach/replace 区别、基础使用模式 | `Chap11/hookNative.js` 第1-12行 |
| [8.2 onEnter与onLeave详解](./sections/8.2.md) | args/retval 操作、context 访问、返回值修改 | `Chap11/hookNative.js` 第13-36行 |
| [8.3 Hook导出函数：getExportByName](./sections/8.3.md) | 通过导出符号名定位并 Hook 函数 | `Chap11/hookSSL_write.js` 完整代码 |
| [8.4 Hook未导出函数：基址+偏移](./sections/8.4.md) | Module.findBaseAddress + add(offset) 定位未导出函数 | `Chap11/hookNative.js` 第13-36行 |
| [8.5 Hook JNI函数实战](./sections/8.5.md) | JNIEnv 参数处理、jstring 读取与修改 | `Chap11/hookNative.js` + `traceNative.js` |
| [8.6 Hook libc导出函数](./sections/8.6.md) | 系统库函数 Hook、字符串函数追踪 | `Chap11/traceLibc.js` 完整代码 |

## 前置知识

- 第七篇：SO/ELF 逆向基础（符号表、导出表、偏移）
- Interceptor 是 Frida 中最核心的 Native Hook API
- JavaScript 回调函数和闭包概念

## 核心概念

| 概念 | 说明 |
|------|------|
| **Interceptor** | Frida 的 Native Hook 框架，提供 `attach` 和 `replace` 两种模式 |
| **Interceptor.attach** | 在函数执行前后插入回调，不修改函数本身，可随时 detach |
| **Interceptor.replace** | 用自定义实现替换整个函数，永久修改函数行为 |
| **onEnter** | 函数入口回调，此时 args 包含传入参数 |
| **onLeave** | 函数出口回调，此时 retval 包含返回值 |
| **args[]** | 函数的参数数组，通过索引访问（args[0] 为第一个参数） |
| **retval** | 函数返回值，在 onLeave 中可读取或修改 |
| **NativeCallback** | 用于创建新的 native 函数，配合 Interceptor.replace 使用 |

## Native Hook 技术体系

```
第一层：导出函数 Hook（8.3）
   → 适用于有符号的函数，最简单直接
   
第二层：未导出函数 Hook（8.4）
   → 需配合 IDA 分析获取偏移，更灵活
   
第三层：JNI 函数 Hook（8.5）
   → 需处理 JNIEnv、jstring 等特殊类型
   
第四层：系统库函数 Hook（8.6）
   → Hook libc、libssl 等系统库
```

## 资源引用

- **Chap11/hookNative.js**（39行）：基础 Native Hook 示例，含导出函数 Hook 和偏移 Hook
- **Chap11/hookSSL_write.js**（21行）：Hook libssl.so SSL_write 的完整实战
- **Chap11/traceNative.js**（111行）：批量枚举并 Hook 导出函数的框架
- **Chap11/traceLibc.js**（73行）：批量 Hook libc 字符串函数的完整代码


---

**上一篇**：[7.4 SO导出表与符号枚举](../part7/sections/7.4.md)
**下一篇**：[8.1 Interceptor.attach基础](sections/8.1.md)
