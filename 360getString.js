
/*
360加固字符串解密
*/

function decode360String(s){
	if (!s) {
		console.log('请输入360加固的密文字符串!');
		return;
	}
		
    Java.perform(function(){
        var Class = Java.use('com.stub.StubApp');
        var result = Class.getString2(s);
        console.log('解密结果: ' + result);
    });
}
