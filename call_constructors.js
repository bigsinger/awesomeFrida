const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息
var ptr_call_constructors;


function find_call_constructors() {
  is64Bit = Process.pointerSize === 8;
  var linkerModule = Process.getModuleByName(is64Bit ? "linker64" : "linker");
  var Symbols = linkerModule.enumerateSymbols();
  for (var i = 0; i < Symbols.length; i++) {
    if (Symbols[i].name.indexOf('call_constructors') > 0) {
      console.warn(`call_constructors: ${Symbols[i].name} at ${Symbols[i].address}`,);
      return Symbols[i].address;
    }
  }
}

function hook_call_constructors() {
  if (!ptr_call_constructors) {
    ptr_call_constructors = find_call_constructors();
  }
  var listener = Interceptor.attach(ptr_call_constructors, {
    onEnter: function (args) {
      if (!TargetLibModule) {
        TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
      }
      console.warn(`call_constructors onEnter`);
      listener.detach();
    },
  })
}

function hook_dlopen() {
  Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
    {
      onEnter: function (args) {
        var pathptr = args[0];
        if (pathptr) {
          var path = ptr(pathptr).readCString();
          console.log("[android_dlopen_ext]", path)
          if (path.indexOf(TARGET_LIB_NAME) > -1) {
            hook_call_constructors();
          }
        }
      }
    }
  )
}

var is64Bit = Process.pointerSize === 8;
hook_dlopen()
