Java.perform(function(){
	var textUtils = Java.use("android.text.TextUtils")
	textUtils.isEmpty.overload('java.lang.CharSequence').implementation=function(a) {
		printStack();
		console.log("TextUtils.isEmpty: " + a);
		return this.isEmpty(a);
	};
	
	var hashMap = Java.use("java.util.HashMap");//HOOK系统函数HashMap去实现打印
	hashMap.put.implementation = function(key, value) {
		console.log("HashMap.put key: " + key + " value: " + value);
		if(key.equals("targetKey")){
			printStack();
		}
		return this.put(key, value);
	}
});

function printStack() {
  Java.perform(function () {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
  });
}