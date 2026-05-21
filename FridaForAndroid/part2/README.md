# 第二篇 · Frida 入门

> **核心目标**：掌握 Frida 脚本注入的基本原理和编程范式，从 Hello World 开始逐步深入 Java.perform、日志输出、Python 绑定等核心概念。

## 本篇内容

| 章节 | 主题 | 核心知识点 |
|------|------|-----------|
| 2.1 | Hello World 注入 | 第一个 Frida 脚本、setImmediate、setTimeout |
| 2.2 | Spawn 与 Attach | 两种注入模式的区别与选择 |
| 2.3 | Java.perform 详解 | 线程切换、作用域、异常处理 |
| 2.4 | 日志输出 | console.log 与 send 的区别与用法 |
| 2.5 | Python 绑定 | frida Python API、RPC 通信 |
| 2.6 | 脚本模板与最佳实践 | 标准模板、命名规范、目录结构 |

## 从 Part1 到 Part2

第一篇搭建好了完整环境，现在你已经可以：

```bash
frida-ps -U   # 看到设备上的进程列表
```

本篇将教会你如何编写和运行你的第一个 Frida 脚本，从最基础的注入到 Python 客户端完整开发。

## 学习路线

```
Hello World → Java.perform → 日志输出
       ↓
Spawn/Attach → Python绑定 → 脚本模板
       ↓
       准备进入 Java 层 Hook（第三篇）
```

## 重要概念

在开始之前，先了解几个核心概念：

| 概念 | 说明 |
|------|------|
| **注入（Injection）** | 将 JS 代码注入到目标 App 进程 |
| **脚本（Script）** | 由 JS 编写的 Frida Hook 逻辑 |
| **会话（Session）** | PC 端与目标进程的连接通道 |
| **运行时（Runtime）** | 脚本在目标进程中执行的环境 |

## 前置准备

确保第一篇内容已完成：

1. ✅ frida-server 已在设备上启动
2. ✅ 端口转发已设置：`adb forward tcp:27042 tcp:27042`
3. ✅ 测试连接：`frida-ps -U` 显示进程列表
4. ✅ 准备好一个目标 APK（如 `com.roysue.demo02`）


---

**上一篇**：[1.5 Frida CLI工具集详解](../part1/sections/1.5.md)
**下一篇**：[2.1 Hello World：注入脚本](sections/2.1.md)
