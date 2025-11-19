// Monitor StringFactory (String construction)
// hook String 的构造函数，字符串生成的地方
Java.perform(function() {
    var stringFactory = Java.use("java.lang.StringFactory");
    
    stringFactory.newStringFromString.implementation = function (a) {
        var retval = this.newStringFromString(a);
        console.log("stringFactory.newStringFromString: ", retval);
        return retval;
    }
    
    stringFactory.newStringFromChars.overload('[C').implementation = function (a) {
        var retval = this.newStringFromChars(a);
        console.log("stringFactory.newStringFromChars: ", retval);
        return retval;
    }
    
    console.warn("[*] hook_monitor_StringFactory is injected");
});
