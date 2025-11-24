// Print Map Content
Java.perform(function() {
    var HashMap = Java.use('java.util.HashMap');
    
    // Hook put method
    HashMap.put.implementation = function(key, value) {
        console.log('[Map.put] Key: ' + key + ', Value: ' + value);
        return this.put(key, value);
    };
    
    // Helper function to print entire Map
    function printMap(map) {
        console.log('========== Map Content ==========');
        var entries = map.entrySet();
        var iterator = entries.iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            console.log('  ' + entry.getKey() + ' => ' + entry.getValue());
        }
        console.log('=================================');
    }
    
    // Export function for use
    global.printMap = printMap;
});
