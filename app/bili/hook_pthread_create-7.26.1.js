/**
 * Frida Hook - 监视目标库 `libmsaoaidsec.so`，拦截线程创建并进行指令修改
 * 
 * 目标：
 * - 监视 `dlopen` 和 `android_dlopen_ext`，检测 `libmsaoaidsec.so` 何时加载。
 * - 通过 `call_constructors` 确保 `pthread_create` Hook 在目标库加载后执行。
 * - 拦截 `pthread_create`，检查线程函数是否在目标库 `so` 的范围内，并阻止其执行。
 * - 通过 `nop_code()` 修改目标库代码，使其关键逻辑失效（NOP 掉特定指令）。
 * 
 * 说明：
 * - `pthread_create` 是创建线程的标准函数，Hook 它可以拦截所有新建线程。
 * - `call_constructors` 由 `linker` 调用，用于执行动态库的全局构造函数。
 * - `hook_call_constructors()` 确保 `TargetLibModule` 记录目标库的基地址，并在适当时机 Hook `pthread_create`。
 * - `nop_code()` 通过 `Memory.patchCode()` 修改代码，将关键指令替换为 NOP（空指令）。
 */

const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息

/////////////////////////////////////////

function nop_code(addr) {
	Memory.patchCode(ptr(addr), 4, code => {
		const cw = new ThumbWriter(code, { pc: ptr(addr) });
		cw.putNop();
		cw.putNop();
		cw.flush();
	})
}

function bypass() {
	nop_code(TargetLibModule.base.add(0xc603 - 1));
}

/////////////////////////////////////////

/**
 * Hook pthread_create，拦截目标库创建的线程
 */
function hook_pthread_create() {
	let pthread_create_addr = Module.findExportByName("libc.so", "pthread_create");
	if (!pthread_create_addr) {
		console.error("Failed to find pthread_create!");
		return;
	}

	Interceptor.attach(pthread_create_addr, {
		onEnter(args) {
			let thread_func_ptr = args[2];  // 线程函数地址
			console.log("[+] pthread_create called, thread function address: " + thread_func_ptr);

			// 确保目标库已加载
			if (!TargetLibModule) {
				//console.warn("Target library not loaded yet!");
				return;
			}

			// 判断线程函数是否在目标库 `so` 的范围内
			if (thread_func_ptr.compare(TargetLibModule.base) > 0 &&
				thread_func_ptr.compare(TargetLibModule.base.add(TargetLibModule.size)) < 0) {

				console.warn("[!] Intercepted thread function at: " + thread_func_ptr +
					" (Offset: " + thread_func_ptr.sub(TargetLibModule.base) + ")");

				// 替换线程函数，防止执行
				Interceptor.replace(thread_func_ptr, new NativeCallback(() => {
					console.log("[*] Fake thread function executed, doing nothing...");
				}, "void", []));
			}
		}
	});
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
			console.warn(`call_constructors onEnter`);
			if (!TargetLibModule) {
				TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
			}
			hook_pthread_create();
			bypass();
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
