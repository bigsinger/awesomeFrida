function hookUrl() {
  Java.perform(function () {
    var tryPlayVideoBean = Java.use("com.fcppkgslhz.yhvrvbuznt.bean.TryPlayVideoBean");
	console.log(tryPlayVideoBean);
	tryPlayVideoBean.class.getDeclaredMethods().forEach(function (method) {
      console.log(method);
    });
	

	tryPlayVideoBean.getUrl.implementation = function(){
		var url = this.getUrl();
		console.log("url: ", url);
		//console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));//java打印堆栈
		var p1 = -1;
		var p2 = -1;
		var start = '';
		var end = '';
		var newUrl = '';
		console.log("url: " + url);
		
		p1 = url.indexOf('start=');
		if(p1==-1){
			this.setUrl(url);
			return url;
		}
		p2 = url.indexOf('&', p1);
		start = url.substring(p1, p2);
		
		p1 = url.indexOf('end=');
		if(p1==-1){
			this.setUrl(url);
			return url;
		}
		p2 = url.indexOf('&', p1);
		end = url.substring(p1, p2);
		
		newUrl = url.replace(start, 'start=0');
		newUrl = newUrl.replace(end, 'end=9');
		console.log("new: " + newUrl);
		
		return newUrl;
	}
	
  });
}
setImmediate(hookUrl());
// frida -U com.fcppkgslhz.yhvrvbuznt -l replaceM3U8url.js