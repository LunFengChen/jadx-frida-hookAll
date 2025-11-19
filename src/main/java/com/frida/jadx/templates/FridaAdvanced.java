package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 7: Frida Advanced (Frida进阶)
 * Advanced Frida features and utilities
 */
public class FridaAdvanced {
    
    private static final String BASE_PATH = "frida-scripts/07-frida-advanced/";
    
    public static final ScriptEntry CALL_METHODS = new ScriptEntry(
        "Call Methods Actively",
        "主动调用方法",
        ScriptLoader.loadScript(BASE_PATH + "call-methods.js")
    );
    
    public static final ScriptEntry CLASSLOADER_HELPER = new ScriptEntry(
        "ClassLoader Helper",
        "ClassLoader辅助",
        ScriptLoader.loadScript(BASE_PATH + "classloader-helper.js")
    );
    
    public static final ScriptEntry DUMP_CERTIFICATE = new ScriptEntry(
        "Dump Certificate",
        "Dump证书",
        ScriptLoader.loadScript(BASE_PATH + "dump-certificate.js")
    );
    
    public static final ScriptEntry LOAD_DEX = new ScriptEntry(
        "Load DEX Dynamically",
        "动态加载DEX",
        ScriptLoader.loadScript(BASE_PATH + "load-dex.js")
    );
}
