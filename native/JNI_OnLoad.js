/**
 * Frida Hook 脚本：监控动态库加载并 Hook `JNI_OnLoad`
 * 
 * 目标：
 * - 监视 `dlopen` 和 `android_dlopen_ext`，检测目标so是否被加载。
 * - 在库加载后，尝试找到并 Hook 其 `JNI_OnLoad` 函数。
 * - 提供调试日志，便于分析动态库的加载及其 `JNI_OnLoad` 调用情况。
 * 
 * 说明：
 * - `dlopen` 和 `android_dlopen_ext` 用于动态加载 `.so` 库，Hook 这些函数可拦截库的加载过程。
 * - `JNI_OnLoad` 是 JNI（Java Native Interface）中初始化的入口点，许多 Android 应用在此执行 native 代码初始化。
 * - `Module.findExportByName` 用于查找导出符号，如果找不到 `JNI_OnLoad`，则遍历所有符号进行匹配。
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";

function hook_JNI_OnLoad() {
  // 先尝试通过 `findExportByName`
  let jniOnLoad = Module.findExportByName(TARGET_LIB_NAME, "JNI_OnLoad");

  // 如果找不到，就遍历所有导出符号
  if (!jniOnLoad) {
    console.log("[Info] `JNI_OnLoad` 未导出，尝试遍历导出符号...");
    for (let symbol of module.enumerateSymbols()) {
      if (symbol.name.indexOf("JNI_OnLoad") >= 0) {
        jniOnLoad = symbol.address;
        console.log("[Success] 找到 JNI_OnLoad: ", jniOnLoad);
        break;
      }
    }
  }

  if (!jniOnLoad) {
    console.error("[Error] 未找到 `JNI_OnLoad` 函数");
    return;
  }

  // Hook `JNI_OnLoad`
  Interceptor.attach(jniOnLoad, {
    onEnter(args) {
      console.log("[Hooked] JNI_OnLoad 被调用");
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
            console.log(`[+] ${funcName} onLeave, start hook JNI_OnLoad `);
            hook_JNI_OnLoad();
          }
        }
      });
    }
  });
}

hook_dlopen();
