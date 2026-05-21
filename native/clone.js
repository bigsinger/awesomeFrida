/**
 * Frida Hook 脚本：
 * 主要功能：
 * 1. 监控 `clone` 调用，获取子线程的加载库信息。
 * 2. Hook `android_dlopen_ext`，在目标库 `libDexHelper.so` 加载时进行处理。
 * 3. 在目标库加载后，对指定偏移地址的指令进行 NOP 处理（屏蔽部分功能）。
 * 
 * 适用架构：ARM32 & ARM64
 */
const TARGET_LIB_NAME = "libDexHelper.so";
const patch_offsets = [0x34b79, 0x334fd, 0x38c29, 0x394b9]; // 这里填需要nop掉的偏移地址
var TargetLibModule = null;     // 存储目标库模块信息


var clone = Module.findExportByName('libc.so', 'clone');
Interceptor.attach(clone, {
    onEnter: function (args) {
        // args[3] 子线程的栈地址。如果这个值为 0，可能意味着没有指定栈地址
        if (args[3] != 0) {
            var addr = args[3].add(48).readPointer()
            var so_name = Process.findModuleByAddress(addr).name;
            var so_base = Module.getBaseAddress(so_name);
            var offset = (addr - so_base);
            console.log('clone(pthread_create ): ', so_name, addr, '0x' + offset.toString(16));
        }
    },
    onLeave: function (retval) {
    }
});

function hook_dlopen(so_name) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            var pathptr = args[0];
            if (pathptr !== undefined && pathptr != null) {
                var path = ptr(pathptr).readCString();
                if (path.indexOf(so_name) !== -1) {
                    this.match = true
                }
            }
        },
        onLeave: function (retval) {
            if (this.match) {
                console.log(so_name, "加载成功");
                if (!TargetLibModule) {
                    TargetLibModule = Process.findModuleByName(TARGET_LIB_NAME);
                }

                bypass();
            }
        }
    });
}

function bypass() {
    patch_offsets.forEach(offset => {
        console.log(`patch 0x${offset.toString(16)}`);
        nopCodeArm32(TargetLibModule.base.add(offset - 1));	    // 32位应用减一
        //nopCodeArm64(TargetLibModule.base.add(offset));	    // 64位应用不用减一
    });
}

function nopCodeArm32(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new ThumbWriter(code, { pc: ptr(addr) });
        cw.putNop();
        cw.putNop();
        cw.flush();
    })
}

function nopCodeArm64(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new Arm64Writer(code, { pc: ptr(addr) });// 64位
        cw.putNop();
        cw.putNop();
        cw.flush();
    })
}

hook_dlopen(TARGET_LIB_NAME)
// find_clone();