package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 4: Hook Android APIs (Hook Android)
 * Scripts for hooking Android framework APIs
 */
public class HookAndroid {
    
    private static final String BASE_PATH = "frida-scripts/04-hook-android/";
    
    public static final ScriptEntry MONITOR_BASE64_ANDROID = new ScriptEntry(
        "Monitor Base64 (Android)",
        "监控Base64(Android)",
        ScriptLoader.loadScript(BASE_PATH + "01-monitor-base64-android.js")
    );
    
    public static final ScriptEntry MONITOR_STRINGFACTORY = new ScriptEntry(
        "Monitor StringFactory",
        "监控StringFactory",
        ScriptLoader.loadScript(BASE_PATH + "03-monitor-stringfactory.js")
    );
    
    public static final ScriptEntry MONITOR_ACTIVITY = new ScriptEntry(
        "Monitor Activity",
        "监控Activity",
        ScriptLoader.loadScript(BASE_PATH + "02-monitor-activity.js")
    );
    
    public static final ScriptEntry MONITOR_DIALOG = new ScriptEntry(
        "Monitor Dialog",
        "监控Dialog",
        ScriptLoader.loadScript(BASE_PATH + "03-monitor-dialog.js")
    );
    
    public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
        "Monitor Toast",
        "监控Toast",
        ScriptLoader.loadScript(BASE_PATH + "04-monitor-toast.js")
    );
    
    public static final ScriptEntry MONITOR_EDITTEXT = new ScriptEntry(
        "Monitor EditText",
        "监控EditText",
        ScriptLoader.loadScript(BASE_PATH + "05-monitor-edittext.js")
    );
    
    public static final ScriptEntry MONITOR_WEBVIEW = new ScriptEntry(
        "Monitor WebView",
        "监控WebView",
        ScriptLoader.loadScript(BASE_PATH + "06-monitor-webview.js")
    );
    
    public static final ScriptEntry MONITOR_LOG = new ScriptEntry(
        "Monitor Log",
        "监控Log",
        ScriptLoader.loadScript(BASE_PATH + "07-monitor-log.js")
    );
    
    public static final ScriptEntry MONITOR_TEXTUTILS = new ScriptEntry(
        "Monitor TextUtils",
        "监控TextUtils",
        ScriptLoader.loadScript(BASE_PATH + "08-monitor-textutils.js")
    );
    
    public static final ScriptEntry MONITOR_SHAREDPREFERENCES = new ScriptEntry(
        "Monitor SharedPreferences",
        "监控SharedPreferences",
        ScriptLoader.loadScript(BASE_PATH + "09-monitor-sharedpreferences.js")
    );
    
    public static final ScriptEntry BLOCK_POPUP = new ScriptEntry(
        "Block Popup",
        "阻止弹窗",
        ScriptLoader.loadScript(BASE_PATH + "10-block-popup.js")
    );
    
    public static final ScriptEntry MONITOR_CRASH = new ScriptEntry(
        "Monitor Crash",
        "监控崩溃",
        ScriptLoader.loadScript(BASE_PATH + "11-monitor-crash.js")
    );
}
