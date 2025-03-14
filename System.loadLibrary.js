/**
适用对象：通用
作用：监控 System.loadLibrary 加载的库文件
*/

const TargetLibName = 'cocos2djs'
const MyLibName = 'test'

function hook() {
  const System = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');
  const VMStack = Java.use('dalvik.system.VMStack');

  System.loadLibrary.implementation = function (libName) {
    try {
      console.log('\nSystem.loadLibrary("' + libName + '")');
      //printStack(); // 想知道是哪个类加载的可以打开日志

      const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), libName);
      if (libName == TargetLibName) {
        console.log(TargetLibName + " is loaded!");
        try {
          Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), MyLibName);
        } catch (e) {
          console.log(e);
        }
      }

      return loaded;
    } catch (ex) {
      //console.log(ex);
    }
  }
}


// 打印堆栈
function printStack() {
  Java.perform(function () {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
  });
}

hook();