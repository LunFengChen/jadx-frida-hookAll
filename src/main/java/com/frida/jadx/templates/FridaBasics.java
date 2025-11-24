package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 1: Frida Basics (Frida基本使用)
 * Basic Frida hook examples and fundamental usage
 */
public class FridaBasics {
    
    private static final String BASE_PATH = "frida-scripts/01-frida-basics/";
    
    public static final ScriptEntry HOOK_BASIC = new ScriptEntry(
        "Hook Basic Method",
        "Hook普通方法",
        ScriptLoader.loadScript(BASE_PATH + "hook-basic.js")
    );
    
    public static final ScriptEntry HOOK_OVERLOAD = new ScriptEntry(
        "Hook Overloaded Method",
        "Hook重载方法",
        ScriptLoader.loadScript(BASE_PATH + "hook-overload.js")
    );
    
    public static final ScriptEntry HOOK_CONSTRUCTOR = new ScriptEntry(
        "Hook Constructor",
        "Hook构造函数",
        ScriptLoader.loadScript(BASE_PATH + "hook-constructor.js")
    );
    
    public static final ScriptEntry HOOK_FIELD = new ScriptEntry(
        "Hook Field",
        "Hook字段",
        ScriptLoader.loadScript(BASE_PATH + "hook-field.js")
    );
    
    public static final ScriptEntry HOOK_INNER_CLASS = new ScriptEntry(
        "Hook Inner Class",
        "Hook内部类",
        ScriptLoader.loadScript(BASE_PATH + "hook-inner-class.js")
    );
    
    public static final ScriptEntry ENUMERATE_CLASSES = new ScriptEntry(
        "Enumerate Classes",
        "枚举类和方法",
        ScriptLoader.loadScript(BASE_PATH + "enumerate-classes.js")
    );
}
