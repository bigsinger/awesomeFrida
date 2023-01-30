// 获取App中的appkey

var targetClassName = "com.netease.nimlib.sdk.NIMClient";

function hook() {
  Java.perform(function () {

    //遍历所有类加载器
  // Java.enumerateClassLoaders({
  //   onMatch: function (loader) {
  //       try {
  //           if (loader.findClass(targetClassName)) {
  //               Java.classFactory.loader = loader;
  //               console.log("find: ", targetClassName);
  //           }
  //       } catch {
  //       }
  //   },
  //   onComplete: function () {
  //   }
  // });


  var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
  dexclassLoader.loadClass.overload('java.lang.String').implementation = function(name){
    var result = this.loadClass(name);
    console.log(name);

    // APP自己的Application时，想要hook的类一定是加载了的，否则时机过早会出现类找不到的情况。
    if (name.indexOf("Application")!=-1 && name!="android.app.Application"){
      var application = Java.use(name);
      console.log("application:"+ application);
      application.onCreate.implementation = function(){
        //realHook(); //二选一均可
        var ret = this.onCreate();
        return ret;
      }
    }

    // 这里一般找不到
    if(name === targetClassName){
      console.log("got targetClass: ", targetClassName);
    }
    return result;
  }


  var application = Java.use('android.app.Application');
  console.log("application:"+ application);

  application.attach.overload('android.content.Context').implementation = function(context){
    console.log("application attach called");
    var result = this.attach(context);

    realHook();

    return result;
  }

  application.onCreate.implementation = function(){
    console.log("application onCreate called");
    
    realHook(); //二选一均可

    var result = this.onCreate();
    return result;
  }

  });
}

function realHook(){
  var NIMClient = Java.use(targetClassName);
  console.log("NIMClient:"+ NIMClient);
  NIMClient.init.implementation = function(context, loginInfo, sDKOptions){
    console.log("[NIMClient.init] SDKOptions: " , sDKOptions.appKey.value, sDKOptions.sdkStorageRootPath.value);
    //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
    return this.init(context, loginInfo, sDKOptions);
  }
}

setImmediate(hook());