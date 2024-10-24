var internetReadFileExA = Module.getExportByName("Wininet.dll", "InternetReadFileExA");

Interceptor.attach(internetReadFileExA, {
    onEnter: function(args) {
        // Capture arguments of InternetReadFileExA
        this.hInternet = args[0]; // HINTERNET handle
        this.lpBuffersOut = args[1]; // LPINTERNET_BUFFERSA structure
        this.dwFlags = args[2]; // Flags

        // Log basic information about the call
        send("[##] (OnEnter) InternetReadFileExA called");
        send("    hInternet: " + this.hInternet);
        send("    lpBuffersOut: " + this.lpBuffersOut);
        send("    dwFlags: " + this.dwFlags);
        
        // Log more details if available
        try {
            if (!this.lpBuffersOut.isNull()) {
                // Assuming lpBuffersOut points to an INTERNET_BUFFERSA structure
                var bufferStruct = this.lpBuffersOut.add(8); // Adjust if structure is different
                var bufferLength = bufferStruct.readUInt();  // Assuming length is at offset 8
                var buffer = this.lpBuffersOut.add(12).readPointer();  // Assuming pointer is at offset 12
                send("    Buffer length: " + bufferLength);
                send("    Buffer address: " + buffer);
            }
        } catch (err) {
            send("    [##] Error reading buffer information: " + err);
        }
    },
    onLeave: function(retval) {
        // Log return value
        send("[##] (OnLeave) InternetReadFileExA returned: " + retval);
    }
});
