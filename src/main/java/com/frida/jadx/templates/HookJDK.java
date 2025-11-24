package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 3: Hook JDK APIs (Hook JDK)
 * Scripts for hooking Java standard library APIs
 */
public class HookJDK {
    
    private static final String BASE_PATH = "frida-scripts/03-hook-jdk/";
    
    public static final ScriptEntry MONITOR_STRING = new ScriptEntry(
        "Monitor String",
        "监控String",
        ScriptLoader.loadScript(BASE_PATH + "01-monitor-string.js")
    );
    
    public static final ScriptEntry MONITOR_STRINGBUILDER = new ScriptEntry(
        "Monitor StringBuilder",
        "监控StringBuilder",
        ScriptLoader.loadScript(BASE_PATH + "02-monitor-stringbuilder.js")
    );
    
    public static final ScriptEntry MONITOR_BASE64_JAVA = new ScriptEntry(
        "Monitor Base64 (Java)",
        "监控Base64(Java)",
        ScriptLoader.loadScript(BASE_PATH + "05-monitor-base64-java.js")
    );
    
    public static final ScriptEntry MONITOR_URL = new ScriptEntry(
        "Monitor URL",
        "监控URL",
        ScriptLoader.loadScript(BASE_PATH + "06-monitor-url.js")
    );
    
    public static final ScriptEntry MONITOR_FILE = new ScriptEntry(
        "Monitor File",
        "监控File",
        ScriptLoader.loadScript(BASE_PATH + "07-monitor-file.js")
    );
    
    public static final ScriptEntry MONITOR_ALL_MAP = new ScriptEntry(
        "Monitor All Map",
        "监控所有Map",
        ScriptLoader.loadScript(BASE_PATH + "08-monitor-all-map.js")
    );
    
    public static final ScriptEntry MONITOR_ARRAYLIST = new ScriptEntry(
        "Monitor ArrayList",
        "监控ArrayList",
        ScriptLoader.loadScript(BASE_PATH + "09-monitor-arraylist.js")
    );
    
    public static final ScriptEntry MONITOR_COLLECTIONS = new ScriptEntry(
        "Monitor Collections",
        "监控Collections",
        ScriptLoader.loadScript(BASE_PATH + "10-monitor-collections.js")
    );
    
    public static final ScriptEntry MONITOR_JSON = new ScriptEntry(
        "Monitor JSON",
        "监控JSON",
        ScriptLoader.loadScript(BASE_PATH + "13-monitor-json.js")
    );
    
    public static final ScriptEntry MONITOR_CRYPTO = new ScriptEntry(
        "Monitor Crypto",
        "监控加解密(Crypto)",
        ScriptLoader.loadScript(BASE_PATH + "15-monitor-crypto.js")
    );
    
    public static final ScriptEntry MONITOR_PROCESS = new ScriptEntry(
        "Monitor Process",
        "监控Process",
        ScriptLoader.loadScript(BASE_PATH + "16-monitor-process.js")
    );
    
    public static final ScriptEntry MONITOR_SYSTEM_LOAD = new ScriptEntry(
        "Monitor System Load",
        "监控System.load",
        ScriptLoader.loadScript(BASE_PATH + "17-monitor-system-load.js")
    );
    
    public static final ScriptEntry MONITOR_THREAD = new ScriptEntry(
        "Monitor Thread",
        "监控Thread",
        ScriptLoader.loadScript(BASE_PATH + "18-monitor-thread.js")
    );
}
