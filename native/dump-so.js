/**
 * 在目标库加载时dump so文件
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息

/////////////////////////////////////////

function dump_so(so_name) {
	// 获取加载的模块信息
	var module = Process.getModuleByName(so_name);
	console.log("[name]:", module.name);
	console.log("[base]:", module.base);
	console.log("[size]:", ptr(module.size));
	console.log("[path]:", module.path);

	var path = "/data/local/tmp/" + module.name + "_" + module.base + "_" + ptr(module.size) + ".so";
	var handle = new File(path, "wb");
	if (handle && handle != null) {
		Memory.protect(ptr(module.base), module.size, 'rwx');
		var buffer = ptr(module.base).readByteArray(module.size);
		handle.write(buffer);
		handle.flush();
		handle.close();
		console.log("[dump]:", path);
	}
}


function hook_dlopen() {
	["android_dlopen_ext", "dlopen"].forEach(funcName => {
		let addr = Module.findExportByName(null, funcName);
		if (addr) {
			Interceptor.attach(addr, {
				onEnter(args) {
					let libName = ptr(args[0]).readCString();
					if (libName && libName.indexOf(TARGET_LIB_NAME) >= 0) {
						this.canHook = true;
					}
				},
				onLeave: function (retval) {
					if (this.canHook) {
						dump_so(TARGET_LIB_NAME);
					}
				}
			});
		}
	});
}

hook_dlopen();