let pWriteProcessMemory = Module.findExportByName("Kernel32.dll", "WriteProcessMemory");

Interceptor.attach(pWriteProcessMemory, {
    onEnter: function(args) {
        send("[>] Called WriteProcessMemory");
        send("    |_ hProcess:            " + args[0]);
        send("    |_ lpBaseAddress:       " + args[1]);
        send("    |_ lpBuffer:            " + args[2]);
        send("    |_ nSize:               " + args[3]);
        send("    |_ lpNumberOfBytesWritten: " + args[4]);

        this.buffPtr = args[2];
    },
    onLeave: function(retval) {
        let writeBuff = new NativePointer(this.buffPtr);
        send(hexdump(writeBuff, {length:0x100}));
    }
});
