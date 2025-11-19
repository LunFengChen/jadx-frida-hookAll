package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 3: Hook JDK APIs (Hook JDK)
 * Scripts for hooking Java standard library APIs
 */
public class HookJDK {
    
    private static final String BASE_PATH = "frida-scripts/03-hook-jdk/";
    
    public static final ScriptEntry MONITOR_ALL_MAP = new ScriptEntry(
        "Monitor All Map",
        "监控所有Map",
        ScriptLoader.loadScript(BASE_PATH + "monitor-all-map.js")
    );
    
    public static final ScriptEntry MONITOR_ARRAYLIST = new ScriptEntry(
        "Monitor ArrayList",
        "监控ArrayList",
        ScriptLoader.loadScript(BASE_PATH + "monitor-arraylist.js")
    );
    
    public static final ScriptEntry MONITOR_BASE64_ANDROID = new ScriptEntry(
        "Monitor Base64 (Android)",
        "监控Base64(Android)",
        ScriptLoader.loadScript(BASE_PATH + "monitor-base64-android.js")
    );
    
    public static final ScriptEntry MONITOR_BASE64_JAVA = new ScriptEntry(
        "Monitor Base64 (Java)",
        "监控Base64(Java)",
        ScriptLoader.loadScript(BASE_PATH + "monitor-base64-java.js")
    );
    
    public static final ScriptEntry MONITOR_COLLECTIONS = new ScriptEntry(
        "Monitor Collections",
        "监控Collections",
        ScriptLoader.loadScript(BASE_PATH + "monitor-collections.js")
    );
    
    public static final ScriptEntry MONITOR_FILE = new ScriptEntry(
        "Monitor File",
        "监控File",
        ScriptLoader.loadScript(BASE_PATH + "monitor-file.js")
    );
    
    public static final ScriptEntry MONITOR_STRING = new ScriptEntry(
        "Monitor String",
        "监控String",
        ScriptLoader.loadScript(BASE_PATH + "monitor-string.js")
    );
    
    public static final ScriptEntry MONITOR_STRINGBUILDER = new ScriptEntry(
        "Monitor StringBuilder",
        "监控StringBuilder",
        ScriptLoader.loadScript(BASE_PATH + "monitor-stringbuilder.js")
    );
    
    public static final ScriptEntry MONITOR_STRINGFACTORY = new ScriptEntry(
        "Monitor StringFactory",
        "监控StringFactory",
        ScriptLoader.loadScript(BASE_PATH + "monitor-stringfactory.js")
    );
    
    public static final ScriptEntry MONITOR_URL = new ScriptEntry(
        "Monitor URL",
        "监控URL",
        ScriptLoader.loadScript(BASE_PATH + "monitor-url.js")
    );
    
    public static final ScriptEntry PRINT_MAP = new ScriptEntry(
        "Print Map",
        "打印Map",
        ScriptLoader.loadScript(BASE_PATH + "print-map.js")
    );
}
