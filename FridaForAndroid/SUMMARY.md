# 目录

* [README](README.md)

## 第一篇 · 环境准备
* [第1章 · Frida基础与环境搭建](./part1/README.md)
  * [1.1 Frida简介与核心架构](./part1/sections/1.1.md)
  * [1.2 环境搭建：Root设备与模拟器](./part1/sections/1.2.md)
  * [1.3 frida-server安装与启动](./part1/sections/1.3.md)
  * [1.4 Python + Node.js开发环境配置](./part1/sections/1.4.md)
  * [1.5 Frida CLI工具集详解](./part1/sections/1.5.md)

## 第二篇 · Frida入门
* [第2章 · 第一个Frida脚本](./part2/README.md)
  * [2.1 Hello World：注入脚本](./part2/sections/2.1.md)
  * [2.2 Spawn与Attach两种注入模式](./part2/sections/2.2.md)
  * [2.3 Java.perform详解](./part2/sections/2.3.md)
  * [2.4 日志输出：console.log与send](./part2/sections/2.4.md)
  * [2.5 Python绑定：Frida客户端编写](./part2/sections/2.5.md)
  * [2.6 Frida脚本模板与最佳实践](./part2/sections/2.6.md)

## 第三篇 · Java层Hook
* [第3章 · Java方法Hook核心技术](./part3/README.md)
  * [3.1 Java.use定位类与方法](./part3/sections/3.1.md)
  * [3.2 Hook方法与修改返回值](./part3/sections/3.2.md)
  * [3.3 重载函数Hook与批量处理](./part3/sections/3.3.md)
  * [3.4 Hook构造函数](./part3/sections/3.4.md)
  * [3.5 修改成员变量与字段](./part3/sections/3.5.md)
  * [3.6 枚举类与动态加载类](./part3/sections/3.6.md)

## 第四篇 · 主动调用与RPC
* [第4章 · 主动调用与RPC通信](./part4/README.md)
  * [4.1 静态方法主动调用](./part4/sections/4.1.md)
  * [4.2 Java.choose枚举实例调用](./part4/sections/4.2.md)
  * [4.3 RPC导出机制：rpc.exports](./part4/sections/4.3.md)
  * [4.4 Python端调用RPC](./part4/sections/4.4.md)
  * [4.5 内部类Hook与调用](./part4/sections/4.5.md)

## 第五篇 · 网络协议Hook
* [第5章 · 网络协议Hook实战](./part5/README.md)
  * [5.1 OkHttp Hook：拦截器注入](./part5/sections/5.1.md)
  * [5.2 OkHttp newCall Hook](./part5/sections/5.2.md)
  * [5.3 HttpURLConnection Hook](./part5/sections/5.3.md)
  * [5.4 Socket与SSL Socket Hook](./part5/sections/5.4.md)
  * [5.5 SSL Pinning绕过基础](./part5/sections/5.5.md)
  * [5.6 Objection一键绕过SSL Pinning](./part5/sections/5.6.md)

## 第六篇 · BoringSSL与通杀方案
* [第6章 · BoringSSL与高级SSL绕过](./part6/README.md)
  * [6.1 JustTrustMe通杀方案](./part6/sections/6.1.md)
  * [6.2 BoringSSL（Chromium系）绕过](./part6/sections/6.2.md)
  * [6.3 字节系App抓包方案](./part6/sections/6.3.md)
  * [6.4 r0capture通杀SSL抓包](./part6/sections/6.4.md)

## 第七篇 · SO/ELF逆向基础
* [第7章 · SO文件结构与逆向基础](./part7/README.md)
  * [7.1 ELF文件结构解析](./part7/sections/7.1.md)
  * [7.2 SO加载流程：dlopen与linker](./part7/sections/7.2.md)
  * [7.3 JNI函数注册机制](./part7/sections/7.3.md)
  * [7.4 SO导出表与符号枚举](./part7/sections/7.4.md)

## 第八篇 · Native层Hook核心技术
* [第8章 · Interceptor与Native Hook](./part8/README.md)
  * [8.1 Interceptor.attach基础](./part8/sections/8.1.md)
  * [8.2 onEnter与onLeave详解](./part8/sections/8.2.md)
  * [8.3 Hook导出函数：getExportByName](./part8/sections/8.3.md)
  * [8.4 Hook未导出函数：基址+偏移](./part8/sections/8.4.md)
  * [8.5 Hook JNI函数实战](./part8/sections/8.5.md)
  * [8.6 Hook libc导出函数实战](./part8/sections/8.6.md)

## 第九篇 · 高级Native技术
* [第9章 · 动态拦截与反调试](./part9/README.md)
  * [9.1 dlopen动态拦截与延迟Hook](./part9/sections/9.1.md)
  * [9.2 Hook RegisterNatives追踪JNI注册](./part9/sections/9.2.md)
  * [9.3 dlopen/dlsym符号解析监控](./part9/sections/9.3.md)
  * [9.4 枚举模块与导出符号](./part9/sections/9.4.md)
  * [9.5 pthread_create反调试线程绕过](./part9/sections/9.5.md)
  * [9.6 init_array SO初始化函数追踪](./part9/sections/9.6.md)

## 第十篇 · DEX加固与脱壳
* [第10章 · 脱壳与加固逆向](./part10/README.md)
  * [10.1 DEX文件结构与加载流程](./part10/sections/10.1.md)
  * [10.2 FRIDA-DEXDump脱壳](./part10/sections/10.2.md)
  * [10.3 Frida脚本手动Dump DEX](./part10/sections/10.3.md)
  * [10.4 内存Dump：SO文件提取](./part10/sections/10.4.md)
  * [10.5 360加固分析与脱壳](./part10/sections/10.5.md)
  * [10.6 Dump Lua脚本](./part10/sections/10.6.md)

## 第十一篇 · 高级主题
* [第11章 · 高级Frida技术](./part11/README.md)
  * [11.1 Stalker：CPU指令级跟踪](./part11/sections/11.1.md)
  * [11.2 自定义类注册](./part11/sections/11.2.md)
  * [11.3 加密算法实时追踪框架](./part11/sections/11.3.md)
  * [11.4 Cocos2d-js游戏XXTEA密钥提取](./part11/sections/11.4.md)
  * [11.5 WebView网络请求监控](./part11/sections/11.5.md)
  * [11.6 Bitmap图片解密](./part11/sections/11.6.md)
  * [11.7 Frida Gadget集成与免root注入](./part11/sections/11.7.md)

## 第十二篇 · 综合实战
* [第12章 · 综合实战案例](./part12/README.md)
  * [12.1 电商App抓包方案](./part12/sections/12.1.md)
  * [12.2 视频App解密：M3U8替换](./part12/sections/12.2.md)
  * [12.3 Protobuf/gRPC协议逆向](./part12/sections/12.3.md)
  * [12.4 Xposed与Frida混合使用](./part12/sections/12.4.md)
  * [12.5 混淆App分析与脱壳](./part12/sections/12.5.md)
  * [12.6 Frida性能优化与调试技巧](./part12/sections/12.6.md)
