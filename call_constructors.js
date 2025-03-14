/**
 * Frida Hook 脚本：监视 `call_constructors` 并拦截目标动态库加载
 * 
 * 目标：
 * - 监视 `dlopen` 和 `android_dlopen_ext`，检测目标so是否被加载。
 * - 通过 `call_constructors` 确保拦截目标库的全局构造函数调用。
 * - 在 `call_constructors` 进入时打印日志，并自动解除 Hook 以减少干扰。
 * 
 * 说明：
 * - `call_constructors` 是 ELF 动态库加载过程中执行全局构造函数的关键函数。
 * - `dlopen` 和 `android_dlopen_ext` 用于加载 `.so` 库，Hook 这些函数可拦截库的加载过程。
 * - `find_call_constructors()` 在 `linker` 或 `linker64` 中查找 `call_constructors` 的地址。
 * - `hook_call_constructors()` 在 `call_constructors` 执行时打印日志，并在第一次调用后解除 Hook。
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";


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
    onEnter: function (args) {
      console.warn(`call_constructors onEnter`);
      listener.detach();
    },
  })
}

function hook_dlopen() {
  ["android_dlopen_ext", "dlopen"].forEach(funcName => {
    let addr = Module.findExportByName(null, funcName);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter(args) {
          let libName = ptr(args[0]).readCString();
          if (libName && libName.indexOf(TARGET_LIB_NAME) >= 0) {
            hook_call_constructors();
          }
        },
        onLeave: function (retval) {
        }
      });
    }
  });
}

var is64Bit = Process.pointerSize === 8;
hook_dlopen()
