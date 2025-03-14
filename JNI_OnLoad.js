/**
 * 
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";

function hook_JNI_OnLoad() {
  // 1. 先尝试通过 `findExportByName`
  let jniOnLoad = Module.findExportByName(TARGET_LIB_NAME, "JNI_OnLoad");

  // 2. 如果找不到，就遍历所有导出符号
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

  // 3. 如果还是找不到，终止
  if (!jniOnLoad) {
    console.log("[Error] 未找到 `JNI_OnLoad` 函数");
    return;
  }

  // 4. Hook `JNI_OnLoad`
  Interceptor.attach(jniOnLoad, {
    onEnter(args) {
      console.log("[Hooked] JNI_OnLoad 被调用");
    }
  });
}

function hook_dlopen() {
  Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function (args) {
      var pathptr = args[0];
      if (pathptr) {
        var path = ptr(pathptr).readCString();
        console.log("[android_dlopen_ext]", path)
        if (path.indexOf(TARGET_LIB_NAME) > -1) {
          this.is_can_hook = true;
        }
      }
    },
    onLeave: function (retval) {
      if (this.is_can_hook) {
        hook_JNI_OnLoad()
      }
    }
  });
}

hook_dlopen()
