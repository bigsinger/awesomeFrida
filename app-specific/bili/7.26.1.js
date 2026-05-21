function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) {
            var pathptr = args[0];
            if (pathptr) {
                var path = ptr(pathptr).readCString();
                console.log("Loading: " + path);
                if (path.indexOf(soName) >= 0) {
                    console.log("Already loading: " + soName);
                    hook_system_property_get();
                }
            }
        }
    });
}

function hook_system_property_get() {
    var system_property_get_addr = Module.findExportByName(null, "__system_property_get");
    if (!system_property_get_addr) {
        console.log("__system_property_get not found");
        return;
    }

    Interceptor.attach(system_property_get_addr, {
        onEnter: function(args) {
            var nameptr = args[0];
            if (nameptr) {
                var name = ptr(nameptr).readCString();
                if (name.indexOf("ro.build.version.sdk") >= 0) {
                    console.log("Found ro.build.version.sdk, need to patch");
                    hook_pthread_create();
                    // bypass()
                }
            }
        }
    });
}

function hook_pthread_create() {
    var pthread_create = Module.findExportByName("libc.so", "pthread_create");
    var libmsaoaidsec = Process.findModuleByName("libmsaoaidsec.so");

    if (!libmsaoaidsec) {
        console.log("libmsaoaidsec.so not found");
        return;
    }

    console.log("libmsaoaidsec.so base: " + libmsaoaidsec.base);

    if (!pthread_create) {
        console.log("pthread_create not found");
        return;
    }

    Interceptor.attach(pthread_create, {
        onEnter: function(args) {
            var thread_ptr = args[2];
            if (thread_ptr.compare(libmsaoaidsec.base) < 0 || thread_ptr.compare(libmsaoaidsec.base.add(libmsaoaidsec.size)) >= 0) {
                console.log("pthread_create other thread: " + thread_ptr);
            } else {
                console.log("pthread_create libmsaoaidsec.so thread: " + thread_ptr + " offset: " + thread_ptr.sub(libmsaoaidsec.base));
            }
        },
        onLeave: function(retval) {}
    });
}
function nop_code(addr)
{
    Memory.patchCode(ptr(addr),4,code => {
        const cw =new ThumbWriter(code,{pc:ptr(addr)});
        cw.putNop();
        cw.putNop();
        cw.flush();
    })
}

function bypass()
{
    let module = Process.findModuleByName("libmsaoaidsec.so")
    nop_code(module.base.add(0x010AE4))
    nop_code(module.base.add(0x113F8))
}
setImmediate(hook_dlopen, "libmsaoaidsec.so");