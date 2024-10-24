var bcryptdecrypt = Module.getExportByName("bcrypt.dll", "BCryptDecrypt");

Interceptor.attach(bcryptdecrypt, {
    onEnter: function(args) {
        var trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(address => {
                var symbol = DebugSymbol.fromAddress(address);
                return symbol.name 
                    ? `${address} - ${symbol.moduleName}!${symbol.name}` 
                    : `${address} - ${symbol} (unknown)`;
            })
            .join("\n");

        send('[##] (OnEnter) Call Stack for BCryptDecrypt:\n' + trace);
    },
    onLeave: function(retval) {
        // No additional actions needed on leave
    }
});
