function hookURL() {
	var URL = Java.use('java.net.URL');
	URL.$init.overload('java.lang.String').implementation = function (url) {
		if (url.indexOf('start=') > 0 && url.indexOf('end=') > 0) {
			//console.log('URL：' + url);
			var url2 = replaceUrlArgs(url, "start", 0);
			url2 = replaceUrlArgs(url2, "end", 99999);
			console.log('URL：' + url2);
			this.$init(url2);
		}
	}
}

function replaceUrlArgs(url, name, value) {
	const re = new RegExp(name + '=[^&]*', 'gi')
	return url.replace(re, name + '=' + value)
}

function replaceUrlArgs2(url, name, value) {
	const re = new RegExp(`(?<=${name}=)[^&]*`, 'g');
	return url.replace(re, value)
}

function hook() {
	Java.perform(function () {
		hookURL();
	});
}

setImmediate(hook());