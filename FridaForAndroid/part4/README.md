# 第四篇 · 主动调用与RPC通信

> 核心能力：**从被动Hook到主动调用，从单机脚本到远程通信**

## 本篇章节目录

| 章节 | 内容 | 引用来源 |
|------|------|----------|
| [4.1 静态方法主动调用](./sections/4.1.md) | `Java.use.方法名()` 直接调用静态方法 | `Chap04/call.js` |
| [4.2 Java.choose枚举实例调用](./sections/4.2.md) | `Java.choose` 遍历已加载实例并调用方法 | `Chap04/call.js` Java.choose 用法 |
| [4.3 RPC导出机制：rpc.exports](./sections/4.3.md) | Frida RPC 导出接口、`rpc.exports` 语法 | `Chap04/call.js`、`awesomeFrida/r0capture.js` |
| [4.4 Python端调用RPC](./sections/4.4.md) | Python 端 `script.exports` 远程调用 | `Chap04/loader.py` |
| [4.5 内部类Hook与调用](./sections/4.5.md) | 内部类定位、`$` 符号用法、混淆内部类 | 综合 |

## 前置知识

- 第三篇：Java 方法 Hook 技术（`Java.use`、`Java.perform`）
- Java 反射机制基础
- Python 基础（4.4 节）

## 核心概念

| 概念 | 说明 |
|------|------|
| **主动调用** | 不等待 App 自身调用，由 Frida 脚本主动执行目标方法 |
| **静态方法** | 类级别方法，无需实例即可调用 |
| **实例方法** | 需要先获取对象实例，再调用其方法 |
| **Java.choose** | 在堆上枚举指定类的所有已加载实例 |
| **RPC** | Frida 内置的远程过程调用机制，JS 端导出、Python 端调用 |
| **内部类** | Java 内部类在 ART 中以 `OuterClass$InnerClass` 形式存在 |

## 使用场景

1. **算法逆向**：主动调用加密 / 解密函数，验证逆向结果
2. **自动化测试**：绕过 UI 操作，直接调用业务方法
3. **远程控制**：Python 端动态下发参数，JS 端实时执行并返回结果
4. **脱壳场景**：主动调用 `ClassLoader.loadClass` 触发类加载

## 资源引用

- **Chap04/call.js**（`AndroidFridaBeginnersBook-main/Chap04/call.js`）：静态方法调用 + RPC 导出示例
- **Chap04/loader.py**（`AndroidFridaBeginnersBook-main/Chap04/loader.py`）：Python 端 RPC 调用示例
- **awesomeFrida/r0capture.js**（`/mnt/f/bigsinger/awesomeFrida/r0capture.js`）：大规模使用 rpc.exports 的生产级脚本


---

**上一篇**：[3.6 枚举类与动态加载类](../part3/sections/3.6.md)
**下一篇**：[4.1 静态方法主动调用](sections/4.1.md)
