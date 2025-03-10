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
			console.log("[+] dlopen: ", path);
		},
		onLeave: function (retval) {
			if (retval.toInt32() !== 0) { // 确保加载成功
				var baseAddr = ptr(retval);
				libMap[baseAddr] = this.path;
				console.log("[+] dlopen: " + this.path + " at " + baseAddr);
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
			console.log("[+] android_dlopen_ext: ", path);
		},
		onLeave: function (retval) {
			if (retval.toInt32() !== 0) { // 确保加载成功
				var baseAddr = ptr(retval);
				libMap[baseAddr] = this.path;
				console.log("[+] android_dlopen_ext: " + this.path + " at " + baseAddr);
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
