/**
 * Frida Hook 脚本 - 监控动态库加载与符号解析
 * 
 * 本脚本的主要功能：
 * 1. 监听 `dlopen` 和 `android_dlopen_ext`，记录加载的动态库及其基地址。
 * 2. 维护 `libMap`，存储已加载库的基地址与库名称的映射关系。
 * 3. Hook `dlsym`，拦截符号解析并输出符号来源库的信息。
 * 
 * 适用环境：
 * - Android 平台
 * - 目标应用加载多个 `.so` 库，且需要分析库的加载与符号解析情况
 * - Frida 框架支持
 * 
 * 使用方式：
 * 1. 启动目标应用。
 * 2. 在终端运行 `frida -U -n <应用包名> -s <本脚本路径> --no-pause`。
 * 3. 观察日志输出，查看加载的动态库及解析的符号信息。
 * 
 * 注意事项：
 * - `libMap` 仅记录通过 `dlopen` 或 `android_dlopen_ext` 加载的库，某些库可能未被捕获。
 * - 该脚本不会修改应用行为，仅用于监控和分析。
 * - 仅用于安全研究和逆向分析，切勿用于非法用途。
 */

var libMap = {};  // 存储库的基地址 -> 库名称映射


/**
 * 记录已加载库的基地址
 */
function load_so_load() {
	// 获取 dlopen 函数的地址
	var dlopen = Module.findExportByName(null, "dlopen");
	// 获取 android_dlopen_ext 函数的地址
	var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");

	// 挂载 dlopen 函数
	Interceptor.attach(dlopen, {
		onEnter: function (args) {
			// 获取动态库路径的指针
			var path_ptr = args[0];
			// 将指针转换为字符串
			var path = ptr(path_ptr).readCString();
			// 保存路径
			this.path = path;
			console.log("[+] dlopen onEnter: ", path);
		},
		onLeave: function (retval) {
			if (retval.toInt32() !== 0) { // 确保加载成功
				var baseAddr = ptr(retval);
				libMap[baseAddr] = this.path;
				console.log("[+] dlopen onLeave: " + this.path + " at " + baseAddr);
			}
		}
	});

	// 挂载 android_dlopen_ext 函数
	Interceptor.attach(android_dlopen_ext, {
		onEnter: function (args) {
			// 获取动态库路径的指针
			var path_ptr = args[0];
			// 将指针转换为字符串
			var path = ptr(path_ptr).readCString();
			// 保存路径
			this.path = path;
			console.log("[+] android_dlopen_ext onEnter: ", path);
		},
		onLeave: function (retval) {
			if (retval.toInt32() !== 0) { // 确保加载成功
				var baseAddr = ptr(retval);
				libMap[baseAddr] = this.path;
				console.log("[+] android_dlopen_ext onLeave: " + this.path + " at " + baseAddr);
			}
		}
	});
}

// Hook dlsym 解析符号并输出库名
function hook_dlsym() {
	var dlsym = Module.findExportByName(null, "dlsym");
	if (dlsym !== null) {
		Interceptor.attach(dlsym, {
			onEnter: function (args) {
				this.handle = args[0]; 						// 记录库的 handle
				this.symbol = ptr(args[1]).readCString(); 	// 读取符号名

				this.libName = "Unknown";
				this.libName = libMap[this.handle];
				//console.log("\t[+] dlsym: " + this.symbol + " (from " + this.libName + ")");
			},
			onLeave: function (retval) {
				console.log("\t[+] dlsym: " + this.symbol + " (from " + this.libName + ") -> " + retval.toString());
			}
		});
	}
}

console.log("[+] hook dlopen android_dlopen_ext dlsym--------");
load_so_load();
hook_dlsym();
