/**
 * 替换目标库使用的pthread_create函数。
 * @description 该脚本使用 Frida 进行动态分析，主要目标是：
 *  1. 监听 `dlopen` / `android_dlopen_ext`，在加载目标库时执行后续 Hook 操作。
 *  2. 监听 `call_constructors` 以确保目标库完全初始化后再 Hook `dlsym`。
 *  3. Hook `dlsym` 并拦截特定符号（如 `pthread_create`），替换其返回值。
 *  4. 通过 `fake_pthread_create` 生成虚假 `pthread_create` 实现，使目标库无法正确调用线程创建函数。
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息


function create_fake_pthread_create() {
	const fake_pthread_create = Memory.alloc(4096)
	Memory.protect(fake_pthread_create, 4096, "rwx")
	Memory.patchCode(fake_pthread_create, 4096, code => {
		const cw = new Arm64Writer(code, { pc: ptr(fake_pthread_create) })
		cw.putRet()
	})
	return fake_pthread_create
}

function hook_dlsym() {
	var dlsym = Module.findExportByName(null, "dlsym");
	if (dlsym !== null) {
		Interceptor.attach(dlsym, {
			onEnter: function (args) {
				// 获取调用 dlsym 的返回地址
				let caller = this.context.lr;
				if (caller.compare(TargetLibModule.base) > 0 &&
					caller.compare(TargetLibModule.base.add(TargetLibModule.size)) < 0) {
					var name = ptr(args[1]).readCString(); 		// 读取符号名
					if (name == 'pthread_create') {
						console.warn(`replace symbol name: pthread_create`);
						this.canFake = true;
					}
				}
			},
			onLeave: function (retval) {
				if (this.canFake) {
					retval.replace(fake_pthread_create);
				}
			}
		});
	}
}

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
			if (!TargetLibModule) {
				TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
			}
			console.warn(`call_constructors onEnter: ${TARGET_LIB_NAME} Module Base: ${TargetLibModule.base}`);
			hook_dlsym();
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
// 创建虚假pthread_create
var fake_pthread_create = create_fake_pthread_create();
hook_dlopen()
