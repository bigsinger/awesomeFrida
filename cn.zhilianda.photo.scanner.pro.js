// 照片恢复大师
/**
 思路：导出时弹出登录页面，此时获取登录页面的Activity名，然后搜索引用，找到启动登录页面的上下文代码，找到判断登录状态的函数调用：checkLogin
 然后找到checkLogin的上下文代码，hook之。  
 */


function hook() {
  Java.perform(function () {
    var SimplifyUtil = Java.use("cn.zld.data.http.core.utils.SimplifyUtil");
    SimplifyUtil.checkLogin.implementation = function(){
      console.log("checkLogin called");
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkServiceTime.implementation = function(){
      console.log("checkServiceTime called");
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkFeedBackTime.implementation = function(){
      console.log("checkFeedBackTime called");
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkIsGoh.implementation = function(){
      console.log("checkIsGoh called");
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkIsSgoh.implementation = function(){
      console.log("checkIsSgoh called");
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
  });
}

setImmediate(hook());