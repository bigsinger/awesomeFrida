function getContext() {
  return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
}                                         
function logAndroidId() {
  console.log('[?] android_id: ', Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id'));
}


function hook() {
  Java.perform(function () {
	var TelephonyManager = Java.use("android.telephony.TelephonyManager");
	TelephonyManager.getDeviceId.overload().implementation = function(){
		var ret = this.getDeviceId();
		console.log("TelephonyManager.getDeviceId() called ret: ", ret);
		return ret;
	};
	TelephonyManager.getDeviceId.overload('int').implementation = function(p){
		var ret = this.getDeviceId(p);
		console.log("TelephonyManager.getDeviceId(int) called ret: ", ret);
		return ret;
	};
	TelephonyManager.getImei.overload("int").implementation = function(i){
		var ret = this.getImei(i);
		console.log("TelephonyManager.getImei() called ret: ", ret);
		return ret;
	};
	TelephonyManager.getSimSerialNumber.overload().implementation = function () {
               var ret = this.getSimSerialNumber();
               console.log("TelephonyManager.getSimSerialNumber() called ret: ", ret);
               return ret;
  };


  var secure = Java.use("android.provider.Settings$Secure");
  secure.getString.implementation = function(obj, s){
    var ret = this.getString(obj, s);
    console.log("Settings$Secure.getString called: " + s + " ret: ", ret);
    return ret;
  }
	
	// //android的hidden API，需要通过反射调用
  // var SP = Java.use("android.os.SystemProperties");
  // SP.get.overload('java.lang.String').implementation = function (p) {
  //   var tmp = this.get(p);
  //   console.log("[*]android.os.SystemProperties "+p+" : "+tmp);
  //   return tmp;
  // }
  // SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (p1,p2) {
  //   var tmp = this.get(p1,p2)
  //   console.log("[*]android.os.SystemProperties "+p1+","+p2+" : "+tmp);
  //   return tmp;
  // } 
  
  // hook MAC
  var wifi = Java.use("android.net.wifi.WifiInfo");
  wifi.getMacAddress.implementation = function () {
    var tmp = this.getMacAddress();
    console.log("[*]android.net.wifi.WifiInfo.getMacAddress() ret: "+tmp);
    return tmp;
  }

  });
}

setImmediate(hook());