# awesomeFrida

> Frida 实战脚本集 & 语法参考手册
>
> 配合 [ADBGUI](https://github.com/bigsinger/adbgui) 工具，更加高效快捷。

---

# 目录概览

## 目录结构

```
awesomeFrida/
├── README.md              ← 本文档（目录 + 语法参考）
├── ssl-bypass/            HTTPS 证书校验绕过
├── native/                Native 层 Hook（SO/JNI/ART）
│   └── jni/               JNI 相关专项脚本
├── java/                  Java 层 Hook
├── stalker/               Stalker CPU 指令追踪
└── app-specific/          特定 APP 专项分析脚本
    └── bili/              哔哩哔哩专项
```

## 脚本索引

### 🔐 SSL Pinning Bypass（`ssl-bypass/`）

| 脚本 | 说明 |
| :--- | :--- |
| `byPassSSL.js` | 通用 SSL Pinning 绕过 |
| `just_trust_me.js` | 知名 SSL 绕过脚本 |
| `just_trust_me_okhttp_hook_finder.js` | just_trust_me 的 OkHttp Hook 定位 |
| `r0capture.js` | r0capture 抓包工具脚本 |

### ⚙️ Native 层 Hook（`native/`）

| 脚本 | 说明 |
| :--- | :--- |
| `hook_RegisterNatives.js` | 拦截 RegisterNatives 获取注册的 native 函数 |
| `JNI_OnLoad.js` | JNI_OnLoad 函数 Hook |
| `init_array.js` | init_array 段 Hook |
| `dlopen.js` | dlopen 调用 Hook |
| `dlopen-replace.js` | dlopen 替换实现 |
| `dlsym.js` | dlsym 符号查找 Hook |
| `pthread_create.js` | pthread_create 线程创建 Hook |
| `pthread_create-fake.js` | 伪造 pthread_create 返回 |
| `pthread_create-replace-jni.js` | 替换 pthread_create 的 JNI 实现 |
| `call_constructors.js` | 调用构造函数 Hook |
| `System.loadLibrary.js` | System.loadLibrary 拦截 |
| `System.loadLibrary-libmsaoaidsec.js` | 针对 libmsaoaidsec 的 loadLibrary 拦截 |
| `clone.js` | 监控 clone 调用 + 子线程 SO 加载 |
| `open.js` | Hook open 函数获取打开的文件名（针对 libmsaoaidsec.so） |
| `BinderProxy.js` | BinderProxy Hook |
| `dump-so.js` | SO 文件 Dump |
| `dump_so.js` | SO 文件 Dump（另一版本） |

**`native/jni/` 子目录：**

| 脚本 | 说明 |
| :--- | :--- |
| `hook_art.js` | ART 运行时 Hook |
| `hook_artmethod.js` | ART Method Hook |
| `hook_RegisterNatives.js` | JNI RegisterNatives 拦截（JNI 版） |
| `hook_RegisterNatives2.js` | JNI RegisterNatives 拦截（v2） |
| `RegisterNatives.js` | RegisterNatives 信息展示 |
| `jni.md` | JNI Hook 使用说明文档 |

### ☕ Java 层 Hook（`java/`）

| 脚本 | 说明 |
| :--- | :--- |
| `HashMap.js` | Hook HashMap.put 操作 |
| `hook_okhttp3.js` | OkHttp3 网络请求 Hook |
| `hook_reg.js` | 正则 Hook 辅助 |
| `hookUrl.js` | URL 相关 Hook |
| `javaEnc.js` | Java 加密方法追踪 |
| `android-make-toast.js` | 主动弹出 Toast |
| `webview-load-url.js` | 获取 WebView 加载的 URL |
| `all_classes.js` | 枚举所有已加载的类 |
| `loadClass.js` | 拦截类加载过程 |

### 🔍 Stalker CPU 指令追踪（`stalker/`）

| 脚本 | 说明 |
| :--- | :--- |
| `stalker.js` | Stalker 指令跟踪基础实现 |
| `stalker-decode.js` | Stalker 解码分析 |
| `stalker-template.js` | Stalker 模版框架 |

### 📱 APP 专项分析（`app-specific/`）

| 脚本 | 说明 |
| :--- | :--- |
| `byteDance.js` | 字节跳动系 APP 分析 |
| `dygod.js` | 电影天堂 APP Hook |
| `MT.js` | MT 相关 Hook（dlopen + 第三方库） |
| `NIMClient.js` | 网易云信 IM 客户端 Hook |
| `nimlibChatAttachParser.js` | 网易云信聊天附件解析 |
| `360getString.js` | 360 加固字符串解密 |
| `ZenTracer.js` | ZenTracer 方法调用追踪 |
| `cn.zhilianda.photo.scanner.pro.js` | 照片扫描特定 APP Hook |
| `cocos2djs-xxtea-key.js` | Cocos2d-js XXTEA 密钥提取 |
| `privacy.js` | 隐私数据获取（Android ID 等） |
| `replaceBaiduAPI_KEY.js` | 替换百度 API Key |
| `replaceM3U8url.js` | 替换 M3U8 视频 URL |
| `replaceInitProcAndPatch.js` | 替换初始化过程并 Patch |

**`app-specific/bili/` 子目录（哔哩哔哩专项）：**

| 脚本 | 说明 |
| :--- | :--- |
| `7.26.1.js` | BiliBili v7.26.1 分析脚本 |
| `7.76.0.js` | BiliBili v7.76.0 分析脚本 |
| `bypass_bilibili.js` | BiliBili 绕过脚本 |
| `create_fake_pthread_create.js` | 伪造 BiliBili 的 pthread_create |
| `hook_pthread_create-7.26.1.js` | v7.26.1 的 pthread_create Hook |
| `replace_init_proc-7.26.1.js` | v7.26.1 初始化过程替换 |
| `replace_init_proc-7.76.0.js` | v7.76.0 初始化过程替换 |

---

# 安装配置

请确保已安装 Frida 及对应版本的 frida-server：

```bash
pip install frida-tools
```

将 frida-server 推送到 Android 设备并启动：

```bash
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

# 注入方式

```bash
# spawn 方式：启动 APP 时注入
frida -U --no-pause -f com.abc.xxx -l xxx.js

# attach 方式：附加到已运行的进程
frida -U pid -l xxx.js
```

---

# 基础语法

## 核心 API

| API 名称 | 描述 |
| :--- | :--- |
| `Java.use(className)` | 获取指定的 Java 类并使其在 JavaScript 代码中可用 |
| `Java.perform(callback)` | 确保回调函数在 Java 的主线程上执行 |
| `Java.choose(className, callbacks)` | 枚举指定类的所有实例 |
| `Java.cast(obj, cls)` | 将一个 Java 对象转换成另一个 Java 类的实例 |
| `Java.enumerateLoadedClasses(callbacks)` | 枚举进程中已经加载的所有 Java 类 |
| `Java.enumerateClassLoaders(callbacks)` | 枚举进程中存在的所有 Java 类加载器 |
| `Java.enumerateMethods(targetClassMethod)` | 枚举指定类的所有方法 |

## 日志输出

| 日志方法 | 描述 | 说明 |
| :--- | :--- | :--- |
| `console.log()` | 使用 JavaScript 直接进行日志打印 | 多用于 CLI 模式，`console.log()` 直接输出到命令行界面。在 RPC 模式中，输出同样在命令行，但可能被 Python 脚本的输出掩盖 |
| `send()` | Frida 专有方法，发送数据/日志到外部 Python 脚本 | 多用于 RPC 模式，允许 JS 发送数据到 Python 脚本进一步处理 |

## 模板代码

```js
function main(){
    Java.perform(function(){
        hook();
    });
}
setImmediate(main);
```

---

# Java 层常用代码

## 打印堆栈

```js
console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈

console.log(' called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');//SO打印堆栈
```

```js
// 打印jni函数参数
function hook_native_function(addr) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            var module = Process.findModuleByAddress(addr);
            this.args0 = args[0];
            this.args1 = args[1];
            this.args2 = args[2];
            this.args3 = args[3];
            this.args4 = args[4];
            this.logs = []
            this.logs.push("call " + module.name + "!" + ptr(addr).sub(module.base) + "\r\n");
            this.logs.push("this.args0: " + print_arg(this.args0));
            this.logs.push("this.args1: " + print_arg(this.args1));
            this.logs.push("this.args2: " + print_arg(this.args2));
            this.logs.push("this.args3: " + print_arg(this.args3));
            this.logs.push("this.args4: " + print_arg(this.args4));
        }, onLeave: function (ret) {
            this.logs.push("this.args0: onLeave: " + print_arg(this.args0));
            this.logs.push("this.args1: onLeave: " + print_arg(this.args1));
            this.logs.push("this.args2: onLeave: " + print_arg(this.args2));
            this.logs.push("this.args3: onLeave: " + print_arg(this.args3));
            this.logs.push("this.args4: onLeave: " + print_arg(this.args4));
            this.logs.push("retValue: " + print_arg(ret));
            console.log(this.logs)
        }
    })
}

function print_arg(addr){
    var range = Process.findRangeByAddress(addr);
    if(range!=null){
        return hexdump(addr)+"\r\n";
    }else{
        return ptr(addr)+"\r\n";
    }
}

function main() {
    // hook_14E20()
    var baseAddr = Module.findBaseAddress("libnative-lib.so")
    hook_native_function(baseAddr.add(0x12c0c));
    // hook_native_function(baseAddr.add(0xf6e0));  free
    hook_native_function(baseAddr.add(0x5796c));
    hook_native_function(baseAddr.add(0x103a4));
    hook_native_function(baseAddr.add(0x13e18));
    hook_native_function(baseAddr.add(0x157fc));
    // hook_native_function(baseAddr.add(0xf670));  malloc
    hook_native_function(baseAddr.add(0x5971c));
    hook_native_function(baseAddr.add(0x59670));
    hook_native_function(baseAddr.add(0x177f8));
    hook_native_function(baseAddr.add(0x19a84));
    hook_native_function(baseAddr.add(0x57bec));
    // hook_native_function(baseAddr.add(0xf310));     new
    // hook_native_function(baseAddr.add(0xf580));      delete
    hook_native_function(baseAddr.add(0x16a94));
    // hook_native_function(baseAddr.add(0xf6a0));       memset
    hook_native_function(baseAddr.add(0xff10));
    hook_native_function(baseAddr.add(0x16514));
    hook_native_function(baseAddr.add(0x151a4));
    hook_native_function(baseAddr.add(0xfcac));
    hook_native_function(baseAddr.add(0x18024));
    // hook_native_function(baseAddr.add(0xf680));         memcpy
    hook_native_function(baseAddr.add(0x57514));
    // hook_native_function(baseAddr.add(0xf630));     strlen
    hook_native_function(baseAddr.add(0x167c0));
    hook_native_function(baseAddr.add(0x12580));
    hook_native_function(baseAddr.add(0x17ce8));
    hook_native_function(baseAddr.add(0x18540));
}

setImmediate(main)
```

## 字节序列操作

### 字节序列转字符串

```js
let s = String.fromCharCode.apply(null, bytes);	// 字节序列转字符串
```

### 字节序列打印输出

```js
// 输出显示十六进制数据
function printDataHexStr(byteArr, size){
	var len = size;
	if(len==undefined){len=0x40;}
	console.log(byteArr);

/* 	var b = new Uint8Array(byteArr);
	var str = "";

	for(var i = 0; i < len; i++) {
		str += (b[i].toString(16) + " ");
	}
	console.log(str); */
}
```

### 保存数据到文件

```js
// 字节序列保存到文件中
function save2File(filename, bytes){
	console.log("save file to: " + filename);
	var file = new File(filename, "w");
	file.write(bytes);
	file.flush();
	file.close();
}
```

### Java 对象、byte[] 输出

```js
function jobj2Str(jobject) {
    var ret = JSON.stringify(jobject);
    return ret;
}
```

### jstring、jbytearray 输出

```js
function jstring2Str(jstring) {
   var ret;
   Java.perform(function() {
       var String = Java.use("java.lang.String");
       ret = Java.cast(jstring, String);
   });
   return ret;
}
 
function jbyteArray2Array(jbyteArray) {
   var ret;
   Java.perform(function() {
       var b = Java.use('[B');
       var buffer = Java.cast(jbyteArray, b);
       ret = Java.array('byte', buffer);
   });
   return ret;
}
```

### base64 编码

```js
function byte2Base64(bytes) {
    var jBase64 = Java.use('android.util.Base64');
    return jBase64.encodeToString(bytes, 2);
}
```

## Hook 各类函数

### HOOK Base64

```js
function hookBase64() {
    // Base64
    var Base64Class = Java.use("android.util.Base64");
    Base64Class.encodeToString.overload("[B", "int").implementation = function (a, b) {
        var rc = this.encodeToString(a, b);
        console.log(">>> Base64 " + rc);
        return rc;
    }
}
```

### HOOK HashMap

```js
function hookHashMap() {
    var Build = Java.use("java.util.HashMap");
    Build["put"].implementation = function (key, val) {
        console.log("key : " + key)
        console.log("val : " + val)
        return this.put(key, val)
    }
}
```

### HOOK 构造函数

```js
function hook(){
    var utils = Java.use("com.xxx.Demo");
    
    // $init表示构造函数
    utils.$init.overload('java.lang.String').implementation = function(str){
        console.log(str);
        this.$init(str);
    }
}
```

### HOOK 所有重载函数

```js
function hookAllOverloads(targetClass, targetMethod) {
    Java.perform(function () {
         var targetClassMethod = targetClass + '.' + targetMethod;
         var hook = Java.use(targetClass);
         var overloadCount = hook[targetMethod].overloads.length;
         for (var i = 0; i < overloadCount; i++) {
                hook[targetMethod].overloads[i].implementation = function() {
                     var retval = this[targetMethod].apply(this, arguments);
                     //这里可以打印结果和参数
                     return retval;
                 }
              }
   });
 }
```

### HOOK 内部类

```js
function hook(){
    Java.perform(function(){
        var innerClass = Java.use("com.xxx.Demo$innerClass");
        console.log(innerClass);
        innerClass.$init.implementation = function(){
            console.log("内部类");
        }
    });
}
```

## 成员操作

### 修改成员变量

```js
function hook(){
    Java.perform(function(){
        
        // 修改静态成员变量
        var cls = Java.use("com.xxx.Demo");
        cls.staticField.value = "hello";
        console.log(cls.staticField.value);
        
        //非静态字段的修改。 使用`Java.choose()`枚举类的所有实例
        Java.choose("com.xxx.Demo", {
            onMatch: function(obj){
                obj._privateInt.value = "hello";
                obj.privateInt.value = 123456;
            },
            onComplete: function(){
            }
        });
    });
}
```

### 调用成员函数

```js
// 调用静态函数
var cls=Java.use("com.xxx.Demo"); 
cls.func("args");

// 调用非静态成员函数
Java.choose("com.xxx.Demo", {
    onMatch:function(obj){
        var ret = obj.func("args");
    },
    onComplete:function() {
    }
});

// 调用jni函数
function invoke(str){
    Java.perform(function (){
        var javaString = Java.use('java.lang.String').$new(str)
        var result = Java.use("com.xxx.MainActivity").encodeFromJni_70(javaString);
        console.log("result is => ",result)
    })
}
```

## 类与方法枚举

### 获取动态加载的类

```js
var cls = Java.use("dalvik.system.DexClassLoader");
cls.loadClass.overload('java.lang.String').implementation = function (name) {
    var result = this.loadClass(name);
    console.log(name);
    return result;
}
```

### 获取所有加载的类

```js

// 异步枚举所有的类与类的所有方法
Java.enumerateLoadedClasses({
    onMatch: function(name, handle) {
        console.log(name);
        if(name.indexOf("com.xxx.Demo") !=-1){
            console.log(name);
            var clazz = Java.use(name);
            console.log(clazz);
            var methods = clazz.class.getDeclaredMethods();
            console.log(methods);
        }
    },
    onComplete: function(){}
})

```

### 获取类所有方法

```js
var cls = Java.use(targetClass);
var methods = cls.class.getDeclaredMethods();
methods.forEach(function(s) {
    console.log(s);
})

for(var j=0; j < methods.length; j++){
    var methodName = methods[j].getName();
    console.log(methodName);
    for(var k=0; k<Demo[methodName].overloads.length;k++){
        Demo[methodName].overloads[k].implementation = function(){
            for(var i=0;i<arguments.length;i++){
                console.log(arguments[i]);
            }
            return this[methodName].apply(this,arguments);
        }
    }
}
```

## 辅助技巧

### 获取方法名

```js
function getMethodName() {
    var ret;
    Java.perform(function() {
        var Thread = Java.use("java.lang.Thread")
        ret = Thread.currentThread().getStackTrace()[2].getMethodName();
    });
    return ret;
}
```

### 免写参数

```js
var xx = Java.use("xx.xx.xx");
xx.yy.implementation = function() {
    var ret = this.yy.apply(this, arguments);
    return ret;
}
```

### 主动弹出 Toast

```js
// 0 = // https://developer.android.com/reference/android/widget/Toast#LENGTH_LONG
Java.scheduleOnMainThread(() => {
  Java.use("android.widget.Toast")
    .makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.StringBuilder").$new("Text to Toast here"), 0).show();
});
```

### 获取 Webview 加载的 URL

```js
Java.use("android.webkit.WebView").loadUrl.overload("java.lang.String").implementation = function (s) {
    send(s.toString());
    this.loadUrl.overload("java.lang.String").call(this, s);
};
```

---

# Native 层常用代码

## 文件操作 Hook

### fopen

```js
Interceptor.attach(Module.findExportByName("libc.so" , "open"),{
    onEnter:function (args){
        var name = Memory.readUtf8String(args[0]);
        if(name.indexOf("xxx.xxx")!=-1){
            console.log(
                "open(" +
                "path=\"" + name + "\"" +
                ", flag=" + args[1] +
                ")"
            );
            console.log('called from:\n' +Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');	
        }
    }
});
```

## 模块加载拦截

### 拦截模块加载并 hook

```js
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if(android_dlopen_ext != null){
    Interceptor.attach(android_dlopen_ext,{
        onEnter: function(args){
            var soName = args[0].readCString();
            if(soName.indexOf("libgame.so") != -1){//libcocos2dlua.so
                console.log("android_dlopen_ext: " + soName);
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) {
                dlopentodo();
                console.log("hook ok");
            };
        }
    });
}
```

### Hook 模块中的函数

```js
//getFileData
Interceptor.attach(Module.findExportByName("libgame.so" , "_ZN7cocos2d11CCFileUtils11getFileDataEPKcS2_Pmb"),{
    onEnter:function (args) {
        var name = Memory.readCString(args[1]);
        this.sizePtr = ptr(args[3]);
        console.log("getFileData onEnter, name: " + name);
    },
    onLeave:function (retval) {
    }			
});
```

## 模块信息查询

### 枚举进程模块列表

```js
var modules = Process.enumerateModules();
for(var i = 0; i < modules.length; i++) {
    if(modules[i].path.indexOf("libgame")!=-1) {
        console.log("模块名称:",modules[i].name);
        console.log("模块地址:",modules[i].base);
        console.log("大小:",modules[i].size);
        console.log("文件系统路径",modules[i].path);
    }
}
```

### 获取模块基址

```js
// 获取基地址
var baseAddr = Module.findBaseAddress("libnative-lib.so")
```

### 获取模块所有导出函数

```js
// 获取所有导出函数
var symbols = Module.enumerateSymbolsSync("libart.so");
symbols.forEach(function (item) {
	console.log(JSON.stringify(item))
})
```

## Lua 相关

### luaL_loadbuffer

```js
//luaL_loadbuffer 加载lua文件函数 libcocos2dlua.so
var addr = Module.findExportByName('libgame.so', "luaL_loadbuffer");
console.log("luaL_loadbuffer: " + addr);
if(addr!=null){
    Interceptor.attach(addr,{
        onEnter:function (args){
            var name = Memory.readCString(args[3]);
            if(name=="xxxx"){	//测试使用，具体dump时可以去掉
                var buff = Memory.readCString(args[1]);
                var size = args[2].toInt32();
                //console.log("lual_loadbuffer, name: " + name + " size: ", size);
                //console.log(buff);
                var byteArr = Memory.readByteArray(args[1], size);
                printDataHexStr(byteArr);

                if(!name.endsWith(".lua")){name=name+".lua";}
                var filename = "/data/user/0/" + PACKAGENAME + "/" + SAVEDIR + "/" + name.split("/").join(".");
                save2File(filename, byteArr);
            }
        }
    });
}

// 字节序列保存到文件中
function save2File(filename, byteArr){
	console.log("save file to: " + filename);
	var file = new File(filename, "w");
	file.write(byteArr);
	file.flush();
	file.close();
}

// 输出显示十六进制数据
function printDataHexStr(byteArr, size){
	var len = size;
	if(len==undefined){len=0x40;}
	console.log(byteArr);
}
```

## 实时跟踪与内存操作

### 实时跟踪 CPU 指令（Stalker）

```js
// 实时跟踪cpu指令

"use strict"
console.log("Hello world");
const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
events: {
    call: true, // 调用指令

    // 其他事件:
    ret: false, // 返回指令
    exec: false, // 全部指令:不推荐, 因为数据量过大
    block: false, // 已计算的块: 粗略执行轨迹
    compile: false // 已编译的块: 对覆盖率很有用
  },

 onReceive: function (events) {
   var parsedEvent = Stalker.parse(events);
   //console.log("buring"+parsedEvent);
 },

 transform: function (iterator) {
   let instruction = iterator.next();
   do {
     console.log("instruction:"+instruction);
     iterator.keep();
   } while ((instruction = iterator.next()) !== null);
 }
})
```

### DUMP 数据

```js
function dumpAddr(address, length) {
    length = length || 1024;
    console.log(hexdump(address, {
        offset: 0,
        length: length,
        header: true,
        ansi: false
    }));
}
```

### 读取内存数据

```js
// 读取内存中的字符串
var s = Memory.readUtf8String(addr);
var s = Memory.readCString(addr);

// 读取内存中的字节序列
var bytes = Memory.readByteArray(addr, size)

// 读取内存中的数值
var size = Memory.readInt(addr);
```

### DUMP SO 文件

```js
function dump_so(so_name) {
  Java.perform(function () {
    var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
    var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
    var libso = Process.getModuleByName(so_name);
    console.log("[name]:", libso.name);
    console.log("[base]:", libso.base);
    console.log("[size]:", ptr(libso.size));
    console.log("[path]:", libso.path);
    var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
    var file_handle = new File(file_path, "wb");
    if (file_handle && file_handle != null) {
      Memory.protect(ptr(libso.base), libso.size, 'rwx');
      var libso_buffer = ptr(libso.base).readByteArray(libso.size);
      file_handle.write(libso_buffer);
      file_handle.flush();
      file_handle.close();
      console.log("[dump]:", file_path);
    }
  });
}
setImmediate(dump_so("libshield.so"))
```

---

# 参考

- [ADBGUI](https://github.com/bigsinger/adbgui) — 配合本脚本集使用的桌面工具
- https://github.com/lasting-yang/frida_hook_libart
- https://github.com/hookmaster/frida-all-in-one
