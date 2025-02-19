/**
适用对象：通用
作用：获取cocos2djs游戏的xxtea的key
参考：
*/
var so_name = "libcocos2djs.so";
var fun_name = "xxtea_decrypt";
function do_hook() {
    var addr = Module.findExportByName(so_name, fun_name);
    console.log(addr);
    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log('key: ' + Memory.readCString(args[2]));
        },
        onLeave: function (retval) {
        }
    })
}
function load_so_and_hook() {
    var dlopen = Module.findExportByName(null, "dlopen");
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            console.log("[dlopen:]", path);
            this.path = path;
        }, onLeave: function (retval) {
            if (this.path.indexOf(so_name) !== -1) {
                // 目标so文 件
                console.log("[dlopen:]", this.path);
                do_hook();
            }
        }
    });
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var path_ptr = args[0];
            var path = ptr(path_ptr).readCString();
            this.path = path;
        }, onLeave: function (retval) {
            if (this.path.indexOf(so_name) !== -1) {
                console.log("\nandroid_dlopen_ext加载：", this.path);
                do_hook();
            }
        }
    });
}


load_so_and_hook();