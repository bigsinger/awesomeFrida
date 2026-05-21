/**
适用对象：通用
作用：对App进行抓包Okhttp
参考：
https://blog.csdn.net/cqcre/article/details/107602760
 */ 
 
function hook_okhttp3() {
    // 1. frida Hook java层的代码必须包裹在Java.perform中，Java.perform会将Hook Java相关API准备就绪。
    Java.perform(function () {
 
 
        // 2. 准备相应类库，用于后续调用，前两个库是Android自带类库，后三个是使用Okhttp网络库的情况下才有的类
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var Buffer = Java.use("com.android.okhttp.okio.Buffer");
        var Interceptor = Java.use("okhttp3.Interceptor");
        var ArrayList = Java.use("java.util.ArrayList");
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
 
 
        //  注册一个Java类
        var MyInterceptor = Java.registerClass({
            name: "okhttp3.MyInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    var request = chain.request();
                    try {
                        console.log("MyInterceptor.intercept onEnter:", request, "\nrequest headers:\n", request.headers());
                        var requestBody = request.body();
                        var contentLength = requestBody ? requestBody.contentLength() : 0;
                        if (contentLength > 0) {
                            var BufferObj = Buffer.$new();
                            requestBody.writeTo(BufferObj);
                            try {
                                console.log("\nrequest body String:\n", BufferObj.readString(), "\n");
                            } catch (error) {
                                try {
                                    console.log("\nrequest body ByteString:\n", ByteString.of(BufferObj.readByteArray()).hex(), "\n");
                                } catch (error) {
                                    console.log("error 1:", error);
                                }
                            }
                        }
                    } catch (error) {
                        console.log("error 2:", error);
                    }
                    var response = chain.proceed(request);
                    try {
                        console.log("MyInterceptor.intercept onLeave:", response, "\nresponse headers:\n", response.headers());
                        var responseBody = response.body();
                        var contentLength = responseBody ? responseBody.contentLength() : 0;
                        if (contentLength > 0) {
                            console.log("\nresponsecontentLength:", contentLength, "responseBody:", responseBody, "\n");
 
 
                            var ContentType = response.headers().get("Content-Type");
                            console.log("ContentType:", ContentType);
                            if (ContentType.indexOf("video") == -1) {
                                if (ContentType.indexOf("application") == 0) {
                                    var source = responseBody.source();
                                    if (ContentType.indexOf("application/zip") != 0) {
                                        try {
                                            console.log("\nresponse.body StringClass\n", source.readUtf8(), "\n");
                                        } catch (error) {
                                            try {
                                                console.log("\nresponse.body ByteString\n", source.readByteString().hex(), "\n");
                                            } catch (error) {
                                                console.log("error 4:", error);
                                            }
                                        }
                                    }
                                }
 
 
                            }
 
 
                        }
 
 
                    } catch (error) {
                        console.log("error 3:", error);
                    }
                    return response;
                }
            }
        });
 
 
        OkHttpClient.$init.overload('okhttp3.OkHttpClient$Builder').implementation = function (Builder) {
            console.log("OkHttpClient.$init:", this, Java.cast(Builder.interceptors(), ArrayList));
            this.$init(Builder);
        };
 
 
        var MyInterceptorObj = MyInterceptor.$new();
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        console.log(Builder);
        Builder.build.implementation = function () {
            this.interceptors().clear();
            this.interceptors().add(MyInterceptorObj);
            var result = this.build();
            return result;
        };
 
 
        Builder.addInterceptor.implementation = function (interceptor) {
            this.interceptors().clear();
            this.interceptors().add(MyInterceptorObj);
            return this;
        };
 
 
        console.log("hook_okhttp3...");
    });
}
 
 
setImmediate(hook_okhttp3());
 
 