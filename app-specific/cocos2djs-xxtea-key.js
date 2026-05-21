/**
 * 脚本名称：Cocos2d-js XXTEA 密钥提取工具
 * 适用对象：基于 Cocos2d-js 引擎开发的游戏
 * 作用：通过 Frida 挂载动态链接库（.so 文件），捕获并提取 XXTEA 加密算法所使用的密钥
 * 原理：
 * 1. 使用 Frida 挂载 `dlopen` 和 `android_dlopen_ext` 函数，监控目标动态库（如 libcocos2djs.so）的加载过程。
 * 2. 当目标动态库加载时，通过 `Interceptor.attach` 挂载目标函数（如 xxtea_decrypt）。
 * 3. 在目标函数被调用时，捕获其参数（通常是密钥），并将其打印到控制台。
 * 使用说明：
 * 1. 安装 Frida：确保你的设备已安装 Frida，并且可以正常运行。推荐使用ROOT真机，模拟器可能存在问题。
 * 2. 启动目标应用：使用以下命令启动目标应用并加载脚本：
 *    `frida -U -f com.example.app -l your_script.js --no-pause`
 *    其中：
 *    - `-U` 表示连接到设备。
 *    - `-f` 表示启动目标应用（替换为实际应用的包名）。
 *    - `-l` 表示加载脚本（替换为你的脚本文件名）。
 *    - `--no-pause` 表示启动应用后不暂停。
 * 3. 查看输出：脚本运行后，控制台会输出捕获到的密钥。
 * 注意事项：
 * 1. 确保目标应用使用了 XXTEA 加密算法，并且密钥通过参数传递。
 * 2. 如果目标动态库名称或函数名称与脚本中的不一致，请自行修改 `TARGET_LIB_NAME` 和 `TargetFuncName`。
 * 3. 本脚本仅用于学习和研究目的，请勿用于非法用途。
 */

// 目标动态库名称
var TARGET_LIB_NAME = "libcocos2djs.so";

// 目标函数名称
var TargetFuncName = "xxtea_decrypt";

/**
 * 挂载目标函数的 Hook
 */
function do_hook() {
    // 查找目标函数的地址
    var addr = Module.findExportByName(TARGET_LIB_NAME, TargetFuncName);
    console.log("找到目标函数地址:", addr);

    // 挂载目标函数
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // args[2] 是目标函数的第三个参数（假设是密钥）
            // 读取并打印密钥
            console.log("捕获到的密钥: " + Memory.readCString(args[2]));
        },
        onLeave: function (retval) {
            // 函数返回时的操作（此处无操作）
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
                        this.is_can_hook = true;
                        console.log(`[+] ${funcName} onEnter: ${libName}`);
                    }
                },
                onLeave: function (retval) {
                    if (this.is_can_hook) {
                        console.log(`[+] ${funcName} onLeave, start hook ${TargetFuncName} `);
                        do_hook();
                    }
                }
            });
        }
    });
}

hook_dlopen();