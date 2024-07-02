
var targetLib = 'libxyz.so';


function hook_NativeMethodByRegister(fnName) {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrRegisterNatives = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];

        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
        }
    }

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                var methods_ptr = ptr(args[2]);
                var method_count = parseInt(args[3]);
                for (var i = 0; i < method_count; i++) {
                    var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));
                    var methodName = Memory.readCString(name_ptr);
                    if (methodName == fnName) {
                        console.log(methodName, fnPtr_ptr);
                        printStack();
                        traceNative(null, fnPtr_ptr);
                    }

                }
            }
        });
    }
}

// stalker
function traceNative(moduleName, addr) {
    var p = addr;
    if (moduleName) {
        var baseAddr = Module.findBaseAddress(targetLib)
        if (!baseAddr) { return; }
        p = baseAddr.add(addr);
    }
    Interceptor.attach(p, {
        onEnter: function (args) {
            console.log("Enter " + addr)
            printStack();
            this.tid = Process.getCurrentThreadId();

            Stalker.follow(this.tid, {
                events: {
                    call: true, // CALL instructions: yes please

                    // Other events:
                    ret: false, // RET instructions
                    exec: false, // all instructions: not recommended as it's
                    //                   a lot of data
                    block: false, // block executed: coarse execution trace
                    compile: false // block compiled: useful for coverage
                },
                // onReceive(events) {
                //     var all_events = Stalker.parse(events);
                //     console.log("onReceive: ", all_events.length);
                //     all_events.forEach(function (i) {
                //         // console.log(i);
                //         try {
                //             var addr1 = i[1];
                //             var module1 = Process.getModuleByAddress(addr1);
                //             if (module1 != null && module1.name === targetLib) {
                //                 var addr2 = i[2];
                //                 var module2 = Process.getModuleByAddress(addr2);
                //                 console.log("call: ", module1.name + "!" + addr1.sub(module1.base), module2.name + "!" + addr2.sub(module2.base))
                //             }
                //         } catch (error) {
                //             console.log("error:", error)
                //         }
                //     })
                // },
                onCallSummary(summary) {
                    // console.log(JSON.stringify(summary))
                    for (const target in summary) {
                        const number = summary[target];
                        if (number == 1) {
                            var module = Process.findModuleByAddress(target);
                            if (module != null && module.name === targetLib) {
                                console.log(module.name + "!" + ptr(target).sub(module.base));
                            }
                        }
                    }

                }
            })
        }, onLeave: function (retVal) {
            console.log("Entering 0x14E20...")
            Stalker.unfollow(this.tid)

        }
    })
}

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
            this.logs.push("------------------------\n");
            this.logs.push("call " + module.name + "!" + ptr(addr).sub(module.base) + "\n");
            this.logs.push("onEnter args0: " + print_arg(this.args0));
            this.logs.push("onEnter args1: " + print_arg(this.args1));
            this.logs.push("onEnter args2: " + print_arg(this.args2));
            this.logs.push("onEnter args3: " + print_arg(this.args3));
            this.logs.push("onEnter args4: " + print_arg(this.args4));
        }, onLeave: function (ret) {
            this.logs.push("onLeave args0: " + print_arg(this.args0));
            this.logs.push("onLeave args1:" + print_arg(this.args1));
            this.logs.push("onLeave args2:" + print_arg(this.args2));
            this.logs.push("onLeave args3:" + print_arg(this.args3));
            this.logs.push("onLeave args4:" + print_arg(this.args4));
            this.logs.push("onLeave return: " + print_arg(ret));
            console.log(this.logs)
        }
    })
}

function print_arg(addr) {
    var range = Process.findRangeByAddress(addr);
    console.log(range)
    if (range != null) {
        return hexdump(addr) + "\r\n";
    } else {
        return ptr(addr) + "\r\n";
    }
}

// 打印堆栈
function printStack() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}


function main() {
    hook_NativeMethodByRegister('decode');
    // var baseAddr = Module.findBaseAddress("libnative-lib.so");
    // hook_native_function(baseAddr.add(0x57514));
    // hook_native_function(baseAddr.add(0x5971c));
    // hook_native_function(baseAddr.add(0x157fc));
    // //hook_native_function(baseAddr.add(0xf6e0));   //free
    // hook_native_function(baseAddr.add(0x151a4));
    // hook_native_function(baseAddr.add(0x59670));
    // //hook_native_function(baseAddr.add(0xf630));   //strlen
    // hook_native_function(baseAddr.add(0x19a84));
    // hook_native_function(baseAddr.add(0x12580));
    // //hook_native_function(baseAddr.add(0xf6a0));   //memset
    // hook_native_function(baseAddr.add(0x16a94));
    // //hook_native_function(baseAddr.add(0x18540));  //短的字符串的时候无
    // hook_native_function(baseAddr.add(0xfcac));
    // hook_native_function(baseAddr.add(0x12c0c));
    // hook_native_function(baseAddr.add(0x5796c));
}


// 主动调用App的jni函数
function callJni(str) {
    Java.perform(function () {
        var javaString = Java.use('java.lang.String').$new(str);
        var result = Java.use("com.kanxue.algorithmbase.MainActivity").encodeFromJni_70(javaString);
        console.log("result is => ", result)
    })
}
setImmediate(main)