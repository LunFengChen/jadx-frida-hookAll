package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 1: Frida Basics (Frida基本使用)
 * Basic Frida hook examples and common patterns
 */
public class FridaBasics {
    
    private static final String BASE_PATH = "frida-scripts/01-frida-basics/";
    
    public static final ScriptEntry HOOK_EXAMPLES = new ScriptEntry(
        "Hook Examples",
        "Hook示例",
        ScriptLoader.loadScript(BASE_PATH + "hook-examples.js")
    );
}
