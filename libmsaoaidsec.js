/**
 * Frida Hook Script for Target Library (libmsaoaidsec.so)
 * -------------------------------------------------------
 * 📌 **目的 (Purpose)**：
 *   本脚本用于 Hook Android 应用中的 `libmsaoaidsec.so` 共享库，以执行以下任务：
 *   1. 监视 `dlopen` / `android_dlopen_ext`，检测目标库何时加载。
 *   2. Hook `__system_property_get`，在应用获取 `ro.build.version.sdk` 版本时执行后续 Hook。
 *   3. Hook `pthread_create`，拦截目标库创建的线程，防止执行特定逻辑。
 *   4. 通过 `NOP` 指令 Patch 关键代码，绕过某些安全检查。
 *   5. 提供 `create_fake_pthread_create`，可用于伪造 `pthread_create`，防止目标库反调试检测。
 *
 * 🚀 **执行流程 (Execution Flow)**：
 *   1️⃣ Hook `dlopen` / `android_dlopen_ext`，监听目标 `so` 何时加载。
 *   2️⃣ 在 `dlopen` 触发后，调用 `locate_init()`，尝试找到 `TargetLibModule`。
 *   3️⃣ Hook `__system_property_get`，检测 `ro.build.version.sdk` 访问，作为早期初始化切入点。
 *   4️⃣ 触发 `hook_pthread_create()`，拦截目标库创建的线程，阻止其执行特定逻辑。
 *   5️⃣ 可选：调用 `bypass()`，使用 `NOP` 指令 Patch 关键逻辑，绕过检测。
 *
 * ⚠ **注意 (Note)**：
 *   - 本脚本仅适用于 **ARM64** 设备，如需在 ARM32 上运行，请修改 `Arm64Writer` 相关代码。
 *   - 若目标应用使用 `ptrace` 反调试保护，可能需要额外 Hook `ptrace` 以绕过检测。
 *   - 使用 Frida 运行此脚本： `frida -U -n target.app -s script.js`
 */

// 目标库名称
const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息

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
				console.warn("Target library not loaded yet!");
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

/**
 * Hook `__system_property_get` 来检测 `ro.build.version.sdk` 读取时机
 * 这个是 `libc.so` 提供的 API，应用可能会调用它来获取 Android 版本号
 */
function locate_init() {
	let system_property_get_addr = Module.findExportByName(null, "__system_property_get");
	if (!system_property_get_addr) {
		console.error("Failed to find __system_property_get!");
		return;
	}

	Interceptor.attach(system_property_get_addr, {
		onEnter(args) {
			let property_name = ptr(args[0]).readCString();
			console.log("[+] __system_property_get: " + property_name);

			if (!TargetLibModule) {
				TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
				if (TargetLibModule) {
					console.log("[+] Target library loaded at: " + TargetLibModule.base);
				} else {
					console.warn("[!] Target library not found yet.");
				}
			}

			// 触发时机：应用访问 `ro.build.version.sdk`，通常出现在早期初始化阶段
			if (property_name.indexOf("ro.build.version.sdk") >= 0) {
				console.log("[!] Detected property access: ro.build.version.sdk");
				hook_pthread_create();  // 开始 Hook 线程创建
				// bypass();  // 可选：进行 bypass 处理
			}
		}
	});
}


function hook_JNI_OnLoad(target_so_name) {
	let module = Process.findModuleByName(target_so_name);
	if (!module) {
		console.log("[Error] 目标库未找到");
		return;
	}

	// 1. 先尝试通过 `findExportByName`
	let jniOnLoad = Module.findExportByName(target_so_name, "JNI_OnLoad");

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

/**
 * Hook `dlopen` 以监视 `so` 加载
 * 适用于 `android_dlopen_ext` 和 `dlopen`
 */
function hook_dlopen(target_so_name) {
	["android_dlopen_ext", "dlopen"].forEach(funcName => {
		let addr = Module.findExportByName(null, funcName);
		if (addr) {
			Interceptor.attach(addr, {
				onEnter(args) {
					let so_path = ptr(args[0]).readCString();
					if (so_path) {
						console.log("[+] " + funcName + " called: " + so_path);
						if (so_path.includes(target_so_name)) {
							this.hitTargetLib = true;
							console.log("[!] Target library loaded: " + TARGET_LIB_NAME);
							locate_init();  // 触发 `locate_init` 进行后续 Hook
						}
					}
				},
				onLeave: function (retval) {
					if (this.hitTargetLib) {
						hook_JNI_OnLoad(target_so_name);
					}
				}
			});
		}
	});
}

/**
 * 在指定地址打 `NOP` 指令，绕过某些校验
 */
function nop(addr) {
	// 1. 调用 Memory.patchCode 以修改目标地址的代码
	Memory.patchCode(ptr(addr), 4, code => {

		// 2. 创建一个 ThumbWriter，指定 `pc` 为 `addr`
		const cw = new ThumbWriter(code, { pc: ptr(addr) });

		// 3. 写入两个 NOP 指令
		cw.putNop();
		cw.putNop();

		// 4. 刷新指令缓存，确保修改生效
		cw.flush();
	});
}


/**
 * 通过 NOP 关键指令来绕过目标库的某些检查逻辑
 */
function bypass() {
	if (!TargetLibModule) {
		console.error("Target library is not loaded yet, cannot apply bypass.");
		return;
	}

	nop(TargetLibModule.base.add(0x10AE4));
	nop(TargetLibModule.base.add(0x113F8));
	console.log("[+] Bypass applied successfully.");
}



// 运行 Hook 逻辑，监听目标库的加载
hook_dlopen(TARGET_LIB_NAME);
