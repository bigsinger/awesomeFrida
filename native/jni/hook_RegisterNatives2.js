// hook register 打印动态注册的函数地址
function hook_register(){
    // libart.so 所有导出函数表
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addr_register = null;
    for(var i = 0; i < symbols.length; i++){
        var symbol = symbols[i];
        var method_name = symbol.name;
        if(method_name.indexOf("art") >= 0){

            if(method_name.indexOf("_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi") >= 0){
                addr_register = symbol.address;
            }
        }
    }

    // 开始hook
    if(addr_register){
        Interceptor.attach(addr_register, {
            onEnter: function(args){
                var methods = ptr(args[2]);
                var method_count = args[3];
                console.log("[RegisterNatives] method_count:", method_count);
                for(var i = 0; i < method_count; i++){
                    var fn_ptr = methods.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
                    var find_module = Process.findModuleByAddress(fn_ptr);
                    if(i == 0){
                        console.log("module name", find_module.name);
                        console.log("module base", find_module.base);
                    }
                    console.log("\t method_name:", methods.add(i * Process.pointerSize * 3).readPointer().readCString(), "method_sign:", methods.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString(), "method_fnPtr:", fn_ptr, "method offset:", fn_ptr.sub(find_module.base));
                }
            }, onLeave(retval){

            }
        })
    }

}