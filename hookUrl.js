
/**
适用对象：通用
作用：对App进行抓包
参考：
https://blog.csdn.net/weixin_42840266/article/details/132279975
https://www.anquanke.com/post/id/197657#h2-9
 */


// hook java.net.URL
function hookURL() {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (a) {
        console.log('URL：' + a)
        //printStack();
        this.$init(a)
    }
}

// hook okhttp3 HttpUrl
function hookOkhttp3() {
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('okhttp3.HttpUrl').implementation = function (a) {
            console.log('okhttp3.HttpUrl: ' + a)
            var res = this.url(a);
            //printStack();
            //console.log("res: " + res)
            return res;
        }
    } catch (error) {
        console.log(error);
    }
}

// hook okhttp3 addHeader
function hookOkhttp3addHeader() {
    try {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder["addHeader"].implementation = function (str, str2) {
            console.log("key: " + str)
            console.log("val: " + str2)
            //printStack();
            var result = this["addHeader"](str, str2);
            console.log("result: " + result);
            return result;
        };
    } catch (error) {
        console.log(error);
    }
}


function hook_KeyStore_load() {
    var StringClass = Java.use("java.lang.String");
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (arg0) {
        //printStack();
        console.log("KeyStore.load1:", arg0);
        this.load(arg0);
    };
    KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (arg0, arg1) {
        //printStack();
        console.log("KeyStore.load2:", arg0, arg1 ? StringClass.$new(arg1) : null);
        this.load(arg0, arg1);
    };

    console.log("hook_KeyStore_load...");
}

function hookOkHttpClient() {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request) {
            var result = this.newCall(request);
            console.log(request.toString());
            return result;
        };
    } catch (error) {
        console.log(error);
    }
}

// 打印堆栈
function printStack() {
    Java.perform(function () {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
    });
}

// hook Base64 
function hookBase64() {
    // Base64
    var Base64Class = Java.use("android.util.Base64");
    Base64Class.encodeToString.overload("[B", "int").implementation = function (a, b) {
        var rc = this.encodeToString(a, b);
        console.log(">>> Base64 " + rc);
        return rc;
    }
}

// hook HashMap
function hookHashMap() {
    var Build = Java.use("java.util.HashMap");
    Build["put"].implementation = function (key, val) {
        console.log("key : " + key)
        console.log("val : " + val)
        return this.put(key, val)
    }
}



function hook() {
    Java.perform(function () {
        hookURL();
        hookOkhttp3();
        hookOkHttpClient();
        hookOkhttp3addHeader();
        hook_KeyStore_load();
        //hookBase64();
        //hookHashMap();
    });
  }

setImmediate(hook());