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
                Interceptor.replace(libmsaoaidsec.base.add(0x1c544),new NativeCallback(function(){
                    console.log("Interceptor.replace: 0x1c544")
                },"void",[]))
                Interceptor.replace(libmsaoaidsec.base.add(0x1b8d4),new NativeCallback(function(){
                    console.log("Interceptor.replace: 0x1c544")
                },"void",[]))
                Interceptor.replace(libmsaoaidsec.base.add(0x26e5c),new NativeCallback(function(){
                    console.log("Interceptor.replace: 0x1c544")
                },"void",[]))
            }
        },
        onLeave: function(retval) {}
    });
}