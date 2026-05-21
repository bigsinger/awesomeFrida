/**
 * 替换模板库的加载
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
const REPLACE_LIB_NAME = "libdummy.so";


function hook_dlopen() {
    ["android_dlopen_ext", "dlopen"].forEach(funcName => {
        let addr = Module.findExportByName(null, funcName);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    let libName = ptr(args[0]).readCString();
                    if (libName && libName.indexOf(TARGET_LIB_NAME) >= 0) {
                        console.log(`[+] ${funcName} onEnter: ${libName}`);

                        // 替换为加载 REPLACE_LIB_NAME
                        let newLib = Memory.allocUtf8String(REPLACE_LIB_NAME);
                        args[0] = newLib;
                        console.log(`[+] ${funcName}: 替换 ${libName} -> ${REPLACE_LIB_NAME}`);
                    }
                },
                onLeave: function (retval) {
                }
            });
        }
    });
}

hook_dlopen();
