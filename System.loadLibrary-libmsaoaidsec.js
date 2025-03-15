/**
适用对象：通用
作用：监控 System.loadLibrary 加载的库文件，替换msaoaidsec的加载。
*/

const TargetLibName = 'msaoaidsec'
const MyLibName = 'dummy'

function hook() {
  const System = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');
  const VMStack = Java.use('dalvik.system.VMStack');

  System.loadLibrary.implementation = function (libName) {
    try {
      console.log('System.loadLibrary("' + libName + '")');
      //printStack(); // 想知道是哪个类加载的可以打开日志

      var name = libName;
      if (libName == TargetLibName) {
        console.warn(`replace ${TargetLibName} as ${MyLibName}`);
        name = MyLibName;
      }
      return Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), name);
    } catch (e) {
      //console.log(e);
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