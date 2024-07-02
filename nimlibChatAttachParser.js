/**
适用对象：通用
作用：获取云信聊天附件信息
参考：
 */


// hook java.net.URL
function hookURL() {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (a) {
        console.log('URL：' + a)
        printStack();
        this.$init(a)
    }
}

function hookChatAttachParser() {
    var clsName = 'com.android.common.nim.parser.ChatAttachParser';
    var cls = Java.use(clsName);
    cls.parse.overload('java.lang.String').implementation = function (s) {
        var ret = this.parse(s);
        console.log(clsName + '.parse(): \n\t' + s);
        printStack();
        return ret;
    }
}

function hookIMMessageImpl() {
    var clsName = "com.netease.nimlib.session.IMMessageImpl";
    var cls = Java.use(clsName);
    cls.setAttachStr.overload('java.lang.String').implementation = function (s) {
        console.log(clsName + '.setAttachStr(): \n\t' + s);
        printStack();
        return this.setAttachStr(s);
    };
    cls.setAttachStrOnly.overload('java.lang.String').implementation = function (s) {
        console.log(clsName + '.setAttachStrOnly(): \n\t' + s);
        printStack();
        return this.setAttachStrOnly(s);
    };
    cls.getContent.overload().implementation = function () {
        var text = this.toStringSimple(this);
        console.log(`${clsName}.getContent(): \n\tnick: ${this.getFromNick()} \n\ttext: ${text} \n\tAttachStr: ${this.getAttachStr()}`);
        printStack();
        return text;
    };
}

// 打印堆栈
function printStack() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function byte2Base64(bytes) {
    //let s = String.fromCharCode.apply(null, bytes);   // 字节序列转字符串
    var jBase64 = Java.use('android.util.Base64');
    return jBase64.encodeToString(bytes, 2);
}

function hook() {
    Java.perform(function () {
        hookURL();
        hookIMMessageImpl();
        hookChatAttachParser();
    });
}

setImmediate(hook());