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
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkMode.implementation = function(){
      console.log("checkMode called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.isShowPay.implementation = function(){
      console.log("isShowPay called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return false;
    }
    SimplifyUtil.checkServiceTime.implementation = function(){
      console.log("checkServiceTime called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkFeedBackTime.implementation = function(){
      console.log("checkFeedBackTime called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkIsGoh.implementation = function(){
      console.log("checkIsGoh called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.checkIsSgoh.implementation = function(){
      console.log("checkIsSgoh called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }
    SimplifyUtil.isShowPromotionDialog.implementation = function(){
      console.log("isShowPromotionDialog called");
      //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
      return true;
    }

    var SPCommonUtil = Java.use("cn.zld.data.http.core.utils.sp.SPCommonUtil");
    SPCommonUtil.get.implementation = function(str, obj){
      var ret = this.get(str, obj);
      console.log("SPCommonUtil.get called: " + str + " ret: ", ret);
      if(str!=null){
        if(str.indexOf('time_interval')!=-1){
          //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
        } else if(str.indexOf('goods_type_ranknum')!=-1){
          //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
          return "1";
        } else if(str.indexOf('buy_')!=-1){
          //return true;
        }
      }
      return ret;
    }


  });
}

setImmediate(hook());