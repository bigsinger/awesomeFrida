// 照片恢复大师

function hook() {
  Java.perform(function () {
    var SimplifyUtil = Java.use("cn.zld.data.http.core.utils.SimplifyUtil");
    SimplifyUtil.checkLogin.implementation = function(){
      console.log("checkLogin called");
      return true;
    }
    SimplifyUtil.checkServiceTime.implementation = function(){
      console.log("checkServiceTime called");
      return true;
    }
    SimplifyUtil.checkFeedBackTime.implementation = function(){
      console.log("checkFeedBackTime called");
      return true;
    }
    SimplifyUtil.checkIsGoh.implementation = function(){
      console.log("checkIsGoh called");
      return true;
    }
    SimplifyUtil.checkIsSgoh.implementation = function(){
      console.log("checkIsSgoh called");
      return true;
    }
  });
}

setImmediate(hook());