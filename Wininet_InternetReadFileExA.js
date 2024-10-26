const internetReadFileExA = Module.getExportByName("Wininet.dll", "InternetReadFileExA");

let wininetListener = Interceptor.attach(internetReadFileExA, {
    onEnter: function(args) {
        // Capture arguments of InternetReadFileExA
        let hInternet = args[0]; // HINTERNET handle
        let lpBuffersOut = args[1]; // LPINTERNET_BUFFERSA structure
        let dwFlags = args[2]; // Flags

        // Log basic information about the call
        send("[##] (OnEnter) InternetReadFileExA called");
        send("    hInternet: " + hInternet);
        send("    lpBuffersOut: " + lpBuffersOut);
        send("    dwFlags: " + dwFlags);
        
        // Log more details if available
        try {
            if (!lpBuffersOut.isNull()) {
                // Assuming lpBuffersOut points to an INTERNET_BUFFERSA structure
                let bufferStruct = lpBuffersOut.add(8); // Adjust if structure is different
                let bufferLength = bufferStruct.readUInt();  // Assuming length is at offset 8
                let buffer = lpBuffersOut.add(12).readPointer();  // Assuming pointer is at offset 12
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
        wininetListener.detach();
    }
});
