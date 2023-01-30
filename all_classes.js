// 遍历App加载的所有类

var targetClassName = "com.netease.nimlib.sdk.NIMClient";

function hook() {
  Java.perform(function () {
	  
	Java.enumerateLoadedClasses({
        onMatch: function(className) {
            console.log(className);
        },
        onComplete: function() {}
    });


  });
}

setImmediate(hook());