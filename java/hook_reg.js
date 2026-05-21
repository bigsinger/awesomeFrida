
function get_func_addr(module, offset) {
    var base_addr = Module.findBaseAddress(module);
    var func_addr = base_addr.add(offset);
    if (Process.arch == 'arm')
        return func_addr.add(1);  //如果是32位地址+1
    else
        return func_addr;
}


// 对指定的寄存器进行hook
// module : so库
// offset : IDA中的偏移地址
function hook_native(module, offset) {

    var fun_addr = get_func_addr(module, offset)
    console.log("fun_addr:", fun_addr);
    if (fun_addr) {
        Interceptor.attach(fun_addr, {
            onEnter: function (args) {
                // 自定义对指定寄存器hook
                console.log("len:", this.context.r1);
            }, onLeave: function (retval) {
            }
        });
    }


}

function hook_dlopen() {
    var targetLib = 'libxyz.so';
    var base_android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (base_android_dlopen_ext) {
        Interceptor.attach(base_android_dlopen_ext, {
            onEnter: function (args) {
                //加个判断标识位
                this.dist_so = false;
                var so_name = ptr(args[0]).readCString();
                if (so_name.indexOf(targetLib) >= 0) {
                    //打印android_dlopen_ext打开的so文件
                    console.log("hook_android_dlopen_ext:", ptr(args[0]).readCString())
                    this.dist_so = true;
                }
            }, onLeave: function (retval) {
                if (this.dist_so) {
                    hook_native(targetLib, 0x89FE);
                }
            }
        })
    }
}

function main() {
    hook_dlopen();

}

setImmediate(main);