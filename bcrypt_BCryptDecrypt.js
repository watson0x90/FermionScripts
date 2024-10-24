// Orginal Source: https://codeshare.frida.re/@fhaag95/bcryptdll-bcryptdecrypt/
//Details on the function available here: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt
var bcryptdecrypt = Module.getExportByName("bcrypt.dll", "BCryptDecrypt");
Interceptor.attach(bcryptdecrypt, {
    onEnter: function(args) {
        this.plaintextPointer = args[6];
        this.plaintextSizeVal = args[7];

        try {
            if(!this.plaintextPointer.isNull()){
                this.plaintextSize = this.plaintextSizeVal.readU64();
            }else{
                // Used to know if we should attempt to read or not OnLeave
                this.plaintextSize = 0;
            }
        } catch (err) {
            //Enable for Debugging purposes
            //send('Error in onEnter: ' + err);
        }
    },
    onLeave: function(retval) {
        if (this.plaintextSize != 0) {
            try {
                let plaintext = this.plaintextPointer.readCString(this.plaintextSize);
                if (plaintext != null) {
                    send('[##] PlainText: \n\n' + plaintext);
                }
            } catch (err) {
                //Enable for Debugging purposes
                //send('Error in onLeave: ' + err);
            }
        }
    }
});
