/**
适用对象：通用
作用：
*/

Java.perform(function () {
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");

    ApplicationPackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
        var appInfo = this.getApplicationInfo(packageName, flags);
        if (appInfo !== null && appInfo.metaData !== null) {
            var originalKey = appInfo.metaData.getString("com.baidu.lbsapi.API_KEY");
            console.log("Old Key: " + originalKey);

            // 修改 API_KEY
            appInfo.metaData.putString("com.baidu.lbsapi.API_KEY", "xxxxxxxxxxxxxxx");
        }
        return appInfo;
    };
});
