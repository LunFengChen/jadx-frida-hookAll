package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 2: Helper Functions (辅助函数)
 * Utility functions commonly used in Frida scripts
 */
public class HelperFunctions {
    
    private static final String BASE_PATH = "frida-scripts/02-helper-functions/";
    
    public static final ScriptEntry PRINT_CALLSTACK = new ScriptEntry(
        "Print Call Stack",
        "打印调用栈",
        ScriptLoader.loadScript(BASE_PATH + "01-print-callstack.js")
    );
    
    public static final ScriptEntry DATA_CONVERT = new ScriptEntry(
        "Data Format Converter",
        "数据格式转换",
        ScriptLoader.loadScript(BASE_PATH + "02-data-convert.js")
    );
    
    public static final ScriptEntry PRINT_ARGS = new ScriptEntry(
        "Print Method Args",
        "打印方法参数",
        ScriptLoader.loadScript(BASE_PATH + "03-print-method-args.js")
    );
    
    public static final ScriptEntry PRINT_MAP = new ScriptEntry(
        "Print Map Object",
        "打印Map对象",
        ScriptLoader.loadScript(BASE_PATH + "04-print-map.js")
    );
    
    public static final ScriptEntry PRINT_STRING_ARRAY = new ScriptEntry(
        "Print String Array",
        "打印字符串数组",
        ScriptLoader.loadScript(BASE_PATH + "05-print-stringArray.js")
    );
    
    public static final ScriptEntry PRINT_METHOD_SIGNATURE = new ScriptEntry(
        "Print Method Signature",
        "打印方法签名",
        ScriptLoader.loadScript(BASE_PATH + "06-print-method-signature.js")
    );
    
    public static final ScriptEntry PRINT_CUSTOM_OBJECT = new ScriptEntry(
        "Print Custom Object",
        "打印自定义对象",
        ScriptLoader.loadScript(BASE_PATH + "07-print-custom-object.js")
    );
}
