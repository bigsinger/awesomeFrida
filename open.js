/**
 * 通过hook open函数来获取打开的文件名
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息

/////////////////////////////////////////

function hook_open() {
	var pth = Module.findExportByName(null, "open");
	Interceptor.attach(ptr(pth), {
		onEnter: function (args) {
			this.filename = args[0];
			console.log(this.filename.readCString())
		}, onLeave: function (retval) {
		}
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
						hook_open();
					}
				},
				onLeave: function (retval) {
				}
			});
		}
	});
}

hook_dlopen();