/**
 * refer: https://codeshare.frida.re/@dvdface/trace-android-binder-call-from-binderproxy/
 */
function hookBinderProxy() {
	// used to add trace
	const Trace = Java.use('android.os.Trace');
	// used to get callstack
	const Thread = Java.use('java.lang.Thread');
	// used to hook binder call from binder proxy
	const BinderProxy = Java.use('android.os.BinderProxy');
	// hook transact of BinderProxy
	BinderProxy.transact.implementation = function (...args) {
		// get callstacks
		const stacktrace = Thread.currentThread().getStackTrace();
		// the binder call is in the 4th line
		const callingStack = stacktrace[3];
		// begin trace
		Trace.beginSection(callingStack.toString());
		// call
		var result = this.transact(...args);
		// end trace
		Trace.endSection();
		// return
		return result;
	}
}

// 打印堆栈
function printStack() {
	Java.perform(function () {
		console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
	});
}

function hook() {
	Java.perform(function () {
		hookBinderProxy();
	});
}

setImmediate(hook());