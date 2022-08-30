// 0 = // https://developer.android.com/reference/android/widget/Toast#LENGTH_LONG
Java.scheduleOnMainThread(() => {
  Java.use("android.widget.Toast")
    .makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.StringBuilder").$new("Text to Toast here"), 0).show();
});