/**
 * Frida Hook 脚本 - 动态拦截并修改目标库 `libmsaoaidsec.so` 的init函数
 * 
 * 本脚本的主要功能：
 * 1. 监听 `dlopen`，在目标库加载时执行 Hook 逻辑。
 * 2. Hook `call_constructors`，在目标库初始化时执行自定义逻辑。
 * 3. 通过 `replace_init_proc` 替换多个关键函数，阻止它们的执行。
 * 4. 通过 `bypass` 进行指令 NOP 处理，绕过特定的校验代码。
 * 
 * 适用环境：
 * - Android 平台
 * - 目标进程加载 `libmsaoaidsec.so` 并执行其内部逻辑
 * - Frida 框架支持
 * 
 * 使用方式：
 * 1. 启动目标应用。
 * 2. 在终端运行 `frida -U -n <应用包名> -s <本脚本路径> --no-pause`。
 * 3. 观察日志输出，确保 Hook 生效。
 * 
 * 注意事项：
 * - 目标库偏移地址可能随版本更新而变化，使用前请校准。
 * - 该脚本的 Hook 逻辑可能影响应用稳定性，请谨慎使用。
 * - 仅用于安全研究和逆向分析，切勿用于非法用途。
 */


const TARGET_LIB_NAME = "libmsaoaidsec.so";
var TargetLibModule = null;  // 存储目标库模块信息

/////////////////////////////////////////

/**
 * 替换目标库中的多个关键函数，阻止其执行
 */
function replace_init_proc() {
	if (!TargetLibModule) return;

	// 需要替换的偏移地址列表
	const offsets = [0x14400, 0x83fc, 0x8448, 0x8460, 0x84b4, 0x85a8];

	offsets.forEach(offset => {
		Interceptor.replace(TargetLibModule.base.add(offset), new NativeCallback(function () {
			console.log(`replace ${offset.toString(16)}`);
		}, "void", []));
	});
}

function nop_code(addr) {
	Memory.patchCode(ptr(addr), 4, code => {
		const cw = new Arm64Writer(code, { pc: ptr(addr) });// 64位
		cw.putNop();
		cw.putNop();
		cw.flush();
	})
}

function bypass() {
	nop_code(TargetLibModule.base.add(0x8750));	// 64位不用减一
	//nop_code(TargetLibModule.base.add(0x13b38));	// 64位不用减一

	// 
	// var libbili_core = Process.getModuleByName('libbili_core.so');
	// console.log(libbili_core.base)
	// nop_code(libbili_core.base.add(0x93b8));		// 64位不用减一
}

/////////////////////////////////////////

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
			replace_init_proc();
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