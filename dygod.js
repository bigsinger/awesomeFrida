function hook() {
  Java.perform(function () {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    symbols.forEach(function (item) {
        console.log(JSON.stringify( item))
    })


  // var Verify = Java.use("com.movies.jni.Verify");
	// Verify.headerRequestKey.implementation = function(context, s1, s2){
	// 	console.log("s1: ", s1);
	// 	console.log("s2: ", s2);
	// 	var ret = this.headerRequestKey(context, s1, s2);
	// 	console.log("ret: ", ret);
	// 	//showStacks3("111");
	// 	//console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
	// 	return ret;
  //   };
	
	// var TelephonyManager = Java.use("android.telephony.TelephonyManager");
	// TelephonyManager.getDeviceId.overload().implementation = function(){
	// 	var ret = this.getDeviceId();
	// 	console.log("TelephonyManager.getDeviceId() called ret: ", ret);
	// 	return ret;
	// };
	// TelephonyManager.getDeviceId.overload('int').implementation = function(p){
	// 	var ret = this.getDeviceId(p);
	// 	console.log("TelephonyManager.getDeviceId(int) called ret: ", ret);
	// 	return ret;
	// };
	// TelephonyManager.getImei.implementation = function(){
	// 	var ret = this.getImei();
	// 	console.log("TelephonyManager.getImei() called ret: ", ret);
	// 	return ret;
	// };
	// TelephonyManager.getSimSerialNumber.overload().implementation = function () {
  //              var ret = this.getSimSerialNumber();
  //              console.log("TelephonyManager.getSimSerialNumber() called ret: ", ret);
  //              return ret;
  //   };
	
	//  //android的hidden API，需要通过反射调用
  //   var SP = Java.use("android.os.SystemProperties");
  //   SP.get.overload('java.lang.String').implementation = function (p) {
  //   	var tmp = this.get(p);
  //   	console.log("[*]android.os.SystemProperties "+p+" : "+tmp);
  //   	return tmp;
  //   }
  //   SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (p1,p2) {
  //   	var tmp = this.get(p1,p2)
  //   	console.log("[*]android.os.SystemProperties "+p1+","+p2+" : "+tmp);
  //   	return tmp;
  //   } 
  //   // hook MAC
  //   var wifi = Java.use("android.net.wifi.WifiInfo");
  //   wifi.getMacAddress.implementation = function () {
  //   	var tmp = this.getMacAddress();
  //   	console.log("[*]android.net.wifi.WifiInfo.getMacAddress() ret: "+tmp);
  //   	return tmp;
  //   }
	
   });
}


function showStacks2(name) 
{ 
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();
    if (straces != undefined && straces != null) 
    {
        var strace = straces.toString();
        var replaceStr = strace.replace(/,/g, "\\n");
        console.log("=============================" + name + " Stack strat=======================");
        console.log(replaceStr);
        console.log("=============================" + name + " Stack end=======================\r\n");
        Exception.$dispose();
    } 
}

 function showStacks3(str_tag) 
 {
    var Exception=  Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();

    if (undefined == straces || null  == straces) 
    {
        return;
    }

    console.log("=============================" + str_tag + " Stack strat=======================");
    console.log("");


    for (var i = 0; i < straces.length; i++)
     {
            var str = "   " + straces[i].toString();
            console.log(str);
    }

    console.log("");
    console.log("=============================" + str_tag + " Stack end=======================\r\n");
    Exception.$dispose();
}

setImmediate(hook());
// frida -U 2345 -l dygod.js