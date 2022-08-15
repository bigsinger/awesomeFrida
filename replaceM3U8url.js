function hookUrl() {
  Java.perform(function () {
    var tryPlayVideoBean = Java.use("com.fcppkgslhz.yhvrvbuznt.bean.TryPlayVideoBean");
	tryPlayVideoBean.setUrl.implementation = function(url){
		var p1 = -1;
		var p2 = -1;
		var start = '';
		var end = '';
		var newUrl = '';
		console.log("url: ", url);
		
		p1 = url.indexOf('start=');
		if(p1==-1){
			this.setUrl(url);
			return;
		}
		p2 = url.indexOf('&', p1);
		start = url.substring(p1, p2);
		
		p1 = url.indexOf('end=');
		if(p1==-1){
			this.setUrl(url);
			return;
		}
		p2 = url.indexOf('&', p1);
		end = url.substring(p1, p2);
		
		newUrl = url.replace(start, 'start=0');
		newUrl = newUrl.replace(end, 'end=99999');
		console.log("new: ", newUrl);
        this.setUrl(newUrl);
    }
	
  });
}
setImmediate(hookUrl());
// frida -U com.fcppkgslhz.yhvrvbuznt -l replaceM3U8url.js