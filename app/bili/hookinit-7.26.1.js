/**
 * Frida Hook - 直接 Hook pthread_create，动态检测目标库
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息
var ptr_call_constructors;

/////////////////////////////////////////

function replaceInitArray() {
	if (TargetLibModule) {
		Interceptor.replace(TargetLibModule.base.add(0xc40d), new NativeCallback(function () {
			console.log("replace 0xc40d")
		}, "void", []));

		Interceptor.replace(TargetLibModule.base.add(0x53a9), new NativeCallback(function () {
			console.log("replace 0x53a9")
		}, "void", []));

		Interceptor.replace(TargetLibModule.base.add(0x53e5), new NativeCallback(function () {
			console.log("replace 0x53e5")
		}, "void", []));

		Interceptor.replace(TargetLibModule.base.add(0x53f5), new NativeCallback(function () {
			console.log("replace 0x53f5")
		}, "void", []));
	}
}

function nop_code(addr) {
	Memory.patchCode(ptr(addr), 4, code => {
		const cw = new ThumbWriter(code, { pc: ptr(addr) });
		cw.putNop();
		cw.putNop();
		cw.flush();
	})
}

function bypass() {
	nop_code(TargetLibModule.base.add(0xc74d - 1))
}

function hook_JNI_OnLoad(target_so_name) {
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
			replaceInitArray();
			bypass();
			listener.detach();
		},
	})
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
					hook_call_constructors();
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

var is64Bit = Process.pointerSize === 8;
hook_dlopen()
