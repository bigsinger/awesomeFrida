/**
适用对象：通用
作用：获取动态加载的类(loadClass)
参考：
*/

function hook() {
  Java.perform(function () {

    var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    dexclassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
      var result = this.loadClass(name);
      console.log(name);

      // APP自己的Application时，想要hook的类一定是加载了的，否则时机过早会出现类找不到的情况。
      if (name.indexOf("Application") != -1 && name != "android.app.Application") {
        var application = Java.use(name);
        console.log("application:" + application);
        application.onCreate.implementation = function () {
          //hookTargetClass(); //二选一均可
          var ret = this.onCreate();
          return ret;
        }
      }

      return result;
    }


    var application = Java.use('android.app.Application');
    console.log("application:" + application);

    application.attach.overload('android.content.Context').implementation = function (context) {
      console.log("application attach called");
      var result = this.attach(context);

      hookTargetClass();

      return result;
    }

    application.onCreate.implementation = function () {
      console.log("application onCreate called");

      hookTargetClass(); //二选一均可

      var result = this.onCreate();
      return result;
    }

  });
}

function hookTargetClass() {
}

// 打印堆栈
function printStack() {
  Java.perform(function () {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
  });
}

setImmediate(hook());