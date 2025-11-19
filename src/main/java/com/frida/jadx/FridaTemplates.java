package com.frida.jadx;

/**
 * Frida Hook Script Library
 * 
 * This is the main entry point that organizes scripts into 7 categories:
 * 1. Frida Basics - Basic Frida usage examples
 * 2. Helper Functions - Utility functions
 * 3. Hook JDK - Java standard library hooks
 * 4. Hook Android - Android framework hooks
 * 5. Hook Third-Party - Third-party library hooks
 * 6. Hook JNI - JNI and native method hooks
 * 7. Frida Advanced - Advanced Frida features
 * 
 * Scripts are loaded from .js files in resources/frida-scripts/
 */
public class FridaTemplates {
    
    /**
     * Script entry containing English name, Chinese name and code
     */
    public static class ScriptEntry {
        public final String nameEn;
        public final String nameZh;
        public final String code;
        
        public ScriptEntry(String nameEn, String nameZh, String code) {
            this.nameEn = nameEn;
            this.nameZh = nameZh;
            this.code = code;
        }
        
        /**
         * Get display name based on language setting
         */
        public String getName(boolean isEnglish) {
            return isEnglish ? nameEn : nameZh;
        }
    }
}
