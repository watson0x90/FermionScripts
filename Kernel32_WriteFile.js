let pWriteFile = Module.findExportByName("Kernel32.dll", "WriteFile");

Interceptor.attach(pWriteFile, {
    onEnter: function(args) {
        send("[>] Called WriteFile");
        send("    |_ hFile:               " + args[0]);
        send("    |_ lpBuffer:            " + args[1]);
        send("    |_ nNumberOfBytesToWrite: " + args[2].toInt32());
        send("    |_ lpOverlapped:        " + args[4]);
    },
    onLeave: function(retval) {
        send("[<] WriteFile returned: " + retval);
    }
});
