说明：配合 [ADBGUI](https://github.com/bigsinger/adbgui)  工具，更加高效快捷。



# 安装配置

# 注入方式

```
// spawn方式
frida -U --no-pause -f com.abc.xxx -l xxx.js

// attach方式
frida -U pid -l xxx.js
```



# 常用代码

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

## fopen

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

## 拦截模块加载并hook

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



## 获取模块基址

```js
// 获取基地址
var baseAddr = Module.findBaseAddress("libnative-lib.so")
```

## 调用jni函数

```js
// 调用jni函数
function invoke(str){
    Java.perform(function (){
        var javaString = Java.use('java.lang.String').$new(str)
        var result = Java.use("com.xxx.yyy.MainActivity").encodeFromJni_70(javaString);
        console.log("result is => ",result)
    })
}
```

## 保存数据到文件

```js
// 字节序列保存到文件中
function save2File(filename, byteArr){
	console.log("save file to: " + filename);
	var file = new File(filename, "w");
	file.write(byteArr);
	file.flush();
	file.close();
}
```

## luaL_loadbuffer

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



## 获取模块所有导出函数

```js
// 获取所有导出函数
var symbols = Module.enumerateSymbolsSync("libart.so");
symbols.forEach(function (item) {
	console.log(JSON.stringify( item))
})
```

## 实时跟踪cpu指令

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



# 参考

- https://github.com/lasting-yang/frida_hook_libart
- https://github.com/hookmaster/frida-all-in-one

