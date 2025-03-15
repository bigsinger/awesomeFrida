/*
 * - 监视 `dlopen` 和 `android_dlopen_ext`，拦截 `libmsaoaidsec.so` 的加载。
 * - 跳过其init_proc函数的调用，并通过补丁nop的方式跳过崩溃的函数调用。
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
const init_offsets = [0x14400, 0x83fc, 0x8448, 0x8460, 0x84b4, 0x85a8]; // 这里填init函数列表，先通过init_array.js脚本获取
const patch_offsets = [0x8750]; // 这里填需要nop掉的偏移地址
var TargetLibModule = null;     // 存储目标库模块信息



function nop_code(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new Arm64Writer(code, { pc: ptr(addr) });// 64位
        cw.putNop();
        cw.putNop();
        cw.flush();
    })
}

function bypass() {
    patch_offsets.forEach(offset => {
        console.log(`patch ${offset.toString(16)}`);
        nop_code(TargetLibModule.base.add(offset));	// 64位不用减一
    });
}


function find_call_constructors() {
    is64Bit = Process.pointerSize === 8;
    var linkerModule = Process.getModuleByName(is64Bit ? "linker64" : "linker");
    var symbols = linkerModule.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name.indexOf('call_constructors') > 0) {
            console.warn(`call_constructors symbol name: ${symbols[i].name} address: ${symbols[i].address}`);
            return symbols[i].address;
        }
    }
}

function hook_call_constructors() {
    var ptr_call_constructors = find_call_constructors();
    var listener = Interceptor.attach(ptr_call_constructors, {
        onEnter(args) {
            if (!TargetLibModule) {
                TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
            }

            if (TargetLibModule != null) {
                init_offsets.forEach(offset => {
                    Interceptor.replace(TargetLibModule.base.add(offset), new NativeCallback(function () {
                        console.log(`replace ${offset.toString(16)}`);
                    }, "void", []));
                });

                bypass();
                listener.detach()
            }

        },
        onLeave(retval) {
            if (this.shouldSkip) {
                retval.replace(0); // 直接返回，不执行 `.init_array`
            }
        }
    });
}

function hook_dlopen() {
    ["android_dlopen_ext", "dlopen"].forEach(funcName => {
        let addr = Module.findExportByName(null, funcName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    let libName = ptr(args[0]).readCString();
                    if (libName && libName.indexOf(TARGET_LIB_NAME) >= 0) {
                        console.warn(`[!] Blocking ${funcName} loading: ${libName}`);
                        hook_call_constructors();
                    }
                },
                onLeave(retval) {
                }
            });
        }
    });
}

var is64Bit = Process.pointerSize === 8;
hook_dlopen();
