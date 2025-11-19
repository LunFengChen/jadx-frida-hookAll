// Monitor JNI RegisterNatives
function hookRegisterNatives() {
    var symbols = Module.enumerateSymbolsSync('libart.so');
    var RegisterNatives = null;
    
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf('art') >= 0 && 
            symbol.name.indexOf('RegisterNatives') >= 0 && 
            symbol.name.indexOf('CheckJNI') < 0) {
            RegisterNatives = symbol.address;
            console.log('[+] Found RegisterNatives at: ' + RegisterNatives);
            break;
        }
    }
    
    if (RegisterNatives != null) {
        Interceptor.attach(RegisterNatives, {
            onEnter: function(args) {
                console.log('\n========== RegisterNatives ==========');
                var env = args[0];
                var jclass = args[1];
                var methods = args[2];
                var nMethods = parseInt(args[3]);
                
                var className = Java.vm.tryGetEnv().getClassName(jclass);
                console.log('[Class] ' + className);
                console.log('[Methods Count] ' + nMethods);
                
                for (var i = 0; i < nMethods; i++) {
                    var methodInfo = ptr(methods).add(i * Process.pointerSize * 3);
                    var methodName = ptr(methodInfo.readPointer()).readCString();
                    var signature = ptr(methodInfo.add(Process.pointerSize).readPointer()).readCString();
                    var fnPtr = methodInfo.add(Process.pointerSize * 2).readPointer();
                    console.log('  [' + i + '] ' + methodName + signature + ' -> ' + fnPtr);
                }
            }
        });
        console.log('[+] RegisterNatives hook installed');
    } else {
        console.log('[-] RegisterNatives not found');
    }
}

Java.perform(hookRegisterNatives);
