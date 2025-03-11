/*
先动态获取 libart 里所有可以动态注册native函数的函数，然后逐个拦截。
*/

var RegisterNativesarray  = [];
var symbols = Module.enumerateSymbolsSync("libart.so");
for (var i = 0; i < symbols.length; i++) {
    var symbol = symbols[i];
    if (symbol.name.indexOf("art") >= 0 &&symbol.name.indexOf("JNI") >= 0 && symbol.name.indexOf("RegisterNatives") >= 0
        ) {
        RegisterNativesarray.push(symbol.address);
        console.log("RegisterNatives is at ", symbol.address, symbol.name);
        continue;
    }
}


if (RegisterNativesarray.length > 0) {
    for (let i = 0; i < RegisterNativesarray.length; i++) {
        // 使用闭包确保当前的 i 被正确捕获
        (function(i) {
            Interceptor.attach(RegisterNativesarray[i], {
                onEnter: function (args) {
                    console.log("come to addrRegisterNatives[" + i + "]"); // 输出正确的 i
                    var env = args[0];        // jni对象
                    var java_class = args[1]; // 类
                    var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                    var taget_class = "com.luckincoffee.safeboxlib.CryptoHelper"; // 目标类名
                    if (class_name === taget_class) {
                        console.log("\n[RegisterNatives] method_count:", args[3]);
                        var methods_ptr = ptr(args[2]);
                        var method_count = parseInt(args[3]);
                        for (var j = 0; j < method_count; j++) {  // 这里使用另一个 i 作为方法索引
                            var name_ptr = Memory.readPointer(methods_ptr.add(j * Process.pointerSize * 3));
                            var sig_ptr = Memory.readPointer(methods_ptr.add(j * Process.pointerSize * 3 + Process.pointerSize));
                            var fnPtr_ptr = Memory.readPointer(methods_ptr.add(j * Process.pointerSize * 3 + Process.pointerSize * 2));
                            var name = Memory.readCString(name_ptr);
                            var sig = Memory.readCString(sig_ptr);
                            var find_module = Process.findModuleByAddress(fnPtr_ptr);
                            var offset = ptr(fnPtr_ptr).sub(find_module.base);
                            console.log('class_name:', class_name, "name:", name, "sig:", sig, 'module_name:', find_module.name, "offset:", offset);
                        }
                    }
                }
            });
        })(i);  // 在此传入当前的 i
    }
}