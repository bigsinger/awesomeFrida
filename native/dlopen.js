/*
 * Frida Hook 脚本：监控目标动态库的加载
 * 
 * 目标：
 * - 监视 `dlopen` 和 `android_dlopen_ext` 函数的调用，以检测指定的动态库是否被加载。
 * - 在库加载时打印日志，方便调试和分析。
 * 
 * 说明：
 * - `dlopen` 和 `android_dlopen_ext` 是 Android 用于加载动态库的常见 API。
 * - `Interceptor.attach` 允许我们在函数进入 (`onEnter`) 和返回 (`onLeave`) 时执行自定义代码。
 */

// 目标动态库名称
const TARGET_LIB_NAME = "libmsaoaidsec.so";


function hook_dlopen() {
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

hook_dlopen();