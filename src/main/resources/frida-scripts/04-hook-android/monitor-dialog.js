// Monitor Android Dialog
Java.perform(function() {
    var Dialog = Java.use('android.app.Dialog');
    
    Dialog.show.implementation = function() {
        console.log('========== Dialog.show() ==========');
        console.log('[Dialog] Class: ' + this.getClass().getName());
        
        // Print stack trace to see where dialog is shown
        console.log('[Dialog] Stack trace:');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()
        ));
        
        return this.show();
    };
    
    console.log('[+] Dialog monitor installed');
});
