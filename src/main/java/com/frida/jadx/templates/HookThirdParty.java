package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 5: Hook Third-Party Libraries (Hook第三方库)
 * Scripts for hooking popular third-party libraries
 */
public class HookThirdParty {
    
    private static final String BASE_PATH = "frida-scripts/05-hook-third-party/";
    
    public static final ScriptEntry MONITOR_JSONOBJECT = new ScriptEntry(
        "Monitor JSONObject",
        "监控JSONObject",
        ScriptLoader.loadScript(BASE_PATH + "monitor-jsonobject.js")
    );
    
    public static final ScriptEntry MONITOR_OKHTTP = new ScriptEntry(
        "Monitor OkHttp",
        "监控OkHttp",
        ScriptLoader.loadScript(BASE_PATH + "monitor-okhttp.js")
    );
}
