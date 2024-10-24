// Orginal Source: https://codeshare.frida.re/@fhaag95/bcryptdll-bcryptdecrypt/
//Details on the function available here: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
var bcryptdecrypt = Module.getExportByName("bcrypt.dll", "BCryptDecrypt");
Interceptor.attach(bcryptdecrypt, {
    onEnter: function(args) {
        this.plaintextPointer = args[6];
        this.plaintextSizeVal = args[7];
        if (this.plaintextPointer.isNull()) {
            this.abort = true;
            return;
        }

        try {
            this.plaintextSize = this.plaintextSizeVal.readU64();
        } catch (err) {
            //Enable for Debugging purposes
            //send('Error in onEnter: ' + err);
        }
    },
    onLeave: function(retval) {
        if (this.abort || this.plaintextSize == 0) {
            return;
        }

        try {
            let plaintext = this.plaintextPointer.readCString(this.plaintextSize);
            if (plaintext != null) {
                send('Obtained cleartext is: ' + plaintext);
            }
        } catch (err) {
            //Enable for Debugging purposes
            //send('Error in onLeave: ' + err);
        }
    }
});
