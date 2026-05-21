/**
功能: 跟踪native函数调用情况。
 */


var TargetLibName = 'libxyz.so';    // 待分析的so库文件名
var TargetFuncOffset = 0x5B50;          // 待分析的native函数偏移, 先在IDA里找到
var TraceCallNum = 1;                   // 默认只输出调用1次的函数


function hookTargetFunc() {
    var baseAddr = Module.findBaseAddress(TargetLibName)
    console.log(TargetLibName + " Module Base: " + baseAddr);
    if (baseAddr == null) {
        console.log('Please makesure ' + TargetLibName + ' is Loaded, by setting extractNativeLibs true.');
        return;
    }

    // hook指定的函数地址
    Interceptor.attach(baseAddr.add(TargetFuncOffset), {
        onEnter: function (args) {
            console.log('\nCall ' + TargetFuncOffset.toString(16).toUpperCase() + ' In')
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

                /* // 这段暂时不开启，不稳定
                onReceive(events) {
                    var all_events = Stalker.parse(events);
                    console.log("onReceive: ", all_events.length);
                    all_events.forEach(function (i) {
                        // console.log(i);
                        try {
                            var addr1 = i[1];
                            var module1 = Process.getModuleByAddress(addr1);
                            if (module1 != null && module1.name == TargetLibName) {
                                var addr2 = i[2];
                                var module2 = Process.getModuleByAddress(addr2);
                                console.log("call: ", module1.name + "!" + addr1.sub(module1.base), module2.name + "!" + addr2.sub(module2.base))
                            }
                        } catch (error) {
                            console.log("error:", error)
                        }
                    })
                },
                */

                onCallSummary(summary) {
                    //console.log(JSON.stringify(summary)); // 调用的所有函数及次数，注意并不是实际调用顺序。
                    for (const target in summary) {
                        const number = summary[target];
                        if (number == TraceCallNum) {
                            var module = Process.findModuleByAddress(target);
                            if (module != null && module.name == TargetLibName) {
                                console.log(module.name + "!" + ptr(target).sub(module.base));
                            }
                        }
                    }
                }

            })
        }, onLeave: function (retVal) {
            console.log('Call ' + TargetFuncOffset.toString(16).toUpperCase() + ' Out\n')
            Stalker.unfollow(this.tid)
        }
    })
}

function hook(addr) {
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


function main() {
    // 需要hook的函数地址列表
    var funcAddr = [
        // 0xbd84,
        // 0x12190,
    ];

    if (funcAddr.length == 0) {
        hookTargetFunc();
    } else {
        var baseAddr = Module.findBaseAddress(TargetLibName);
        console.log(TargetLibName + " Module Base: " + baseAddr);

        for (var i = 0; i < funcAddr.length; i++) {
            hook(baseAddr.add(funcAddr[i]));
        }
    }
}


setImmediate(main)