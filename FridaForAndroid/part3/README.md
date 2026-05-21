# 第三篇 · Java 层 Hook

> **核心目标**：系统掌握 Frida 在 Android Java 层的 Hook 技术，涵盖类定位、方法拦截、重载处理、构造函数、字段修改、类枚举等全部核心技能。

## 本篇内容

| 章节 | 主题 | 核心知识点 |
|------|------|-----------|
| 3.1 | Java.use 定位类与方法 | 类获取、方法枚举、包名解析 |
| 3.2 | Hook 方法与修改返回值 | implementation、参数篡改、返回值劫持 |
| 3.3 | 重载函数 Hook | overload、参数类型匹配、批量处理 |
| 3.4 | Hook 构造函数 | $init、实例创建拦截 |
| 3.5 | 修改成员变量与字段 | 字段读写、Java.choose、实例字段 |
| 3.6 | 枚举类与动态加载类 | enumerateLoadedClasses、DexClassLoader |

## 从 Part2 到 Part3

经过第二篇的学习，你已经掌握了：

- 编写 Frida 脚本并使用 `setImmediate(main)` + `Java.perform()`
- 使用 `console.log` 和 `send` 输出日志
- 通过 Python 客户端管理和调用 RPC

本篇将在此基础上，深入 Java 层的核心 Hook 技术。

## 前置要求

- 已完成 Part1 和 Part2 的内容
- 有一个可调试的 Android 目标 App（推荐 `com.roysue.demo02`）
- 理解 Java 基本概念：类、方法、构造函数、字段、重载

## Java 层 Hook 流程总览

```
┌─────────────────────────────────────────────┐
│  1. Java.use('com.example.MainActivity')    │  ← 定位类
├─────────────────────────────────────────────┤
│  2. className.method.implementation = fn    │  ← Hook 方法
├─────────────────────────────────────────────┤
│  3. function(args) {                        │
│       console.log(args);                    │  ← 查看参数
│       var ret = this.method(args);          │  ← 调用原方法
│       return modified_ret;                  │  ← 修改返回值
│   }                                         │
├─────────────────────────────────────────────┤
│  4. setImmediate(main)                      │  ← 入口
└─────────────────────────────────────────────┘
```

## 素材来源说明

本篇大量引用以下素材：

1. **《安卓Frida逆向与抓包实战》Chap03/** — 基础 Hook 示例
   - `1.js` — Java.use + implementation 基础
   - `2.js` — overload 重载处理
   - `3.js` — Java.choose 实例枚举
   - `4.js` — 字段访问
   - `hello_world.js` — 构造函数调用

2. **awesomeFrida/** — 实战脚本
   - `all_classes.js` — 枚举所有已加载类
   - `loadClass.js` — 动态加载类监控
   - `HashMap.js` — 系统类 Hook 实战

## 快速参考

```javascript
// ===== Java 层 Hook 速查表 =====

// 1. 定位类
var Cls = Java.use('com.roysue.demo02.MainActivity');

// 2. Hook 实例方法
Cls.method.implementation = function() { ... };

// 3. Hook 重载方法
Cls.method.overload('int', 'java.lang.String').implementation = ...;

// 4. Hook 构造函数
Cls.$init.overload('int').implementation = function(x) { ... };

// 5. 读取/修改字段
Cls.field.value = new_value;

// 6. 枚举实例
Java.choose('com.roysue.demo02.MainActivity', {
    onMatch: function(inst) { ... },
    onComplete: function() { ... }
});

// 7. 枚举所有类
Java.enumerateLoadedClasses({ onMatch: function(c) { ... } });
```


---

**上一篇**：[2.6 Frida脚本模板与最佳实践](../part2/sections/2.6.md)
**下一篇**：[3.1 Java.use定位类与方法](sections/3.1.md)
