// 目标动态库名称
const TARGET_LIB_NAME = "libmsaoaidsec.so";


function hook_dlopen(target_so_name) {
    ["android_dlopen_ext", "dlopen"].forEach(funcName => {
        let addr = Module.findExportByName(null, funcName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    let libName = ptr(args[0]).readCString();
                    if (libName) {
                        console.log(`[+] ${funcName} onEnter: ${libName}`);
                    }
                },
                onLeave: function (retval) {
                    console.log(`[+] ${funcName} onLeave`);
                }
            });
        }
    });
}

// 执行加载动态库并 Hook 的逻辑
hook_dlopen();