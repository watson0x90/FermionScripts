function getASCIIString(buffPtr, buffSize) {
    let asciiString = "";

    for (let i = 0; i < buffSize; i++) {
        try {
            let byte = buffPtr.add(i).readU8();
            if (byte >= 32 && byte <= 126) { // Check if the byte is a printable ASCII character
                asciiString += String.fromCharCode(byte);
            }
        } catch (error) {
            send(`[!] Error reading memory at offset ${i}: ${error.message}`);
            break;
        }
    }

    return asciiString;
}



// Intercepting KernelBase.dll WriteFile function
Interceptor.attach(Module.findExportByName("KernelBase.dll", "WriteFile"), {
    onEnter: function (args) {
        // args[0]: hFile (HANDLE to the file)
        // args[1]: lpBuffer (pointer to buffer containing data to be written)
        // args[2]: nNumberOfBytesToWrite (number of bytes to write)
        // args[3]: lpNumberOfBytesWritten (pointer to variable that receives number of bytes written)

        this.hFile = args[0];  // Store the file handle for later
        this.lpBuffer = args[1];  // Store the buffer pointer
        this.nNumberOfBytesToWrite = args[2].toInt32();  // Store the number of bytes to write

        // Send relevant information
        send("WriteFile called: File Handle: " + this.hFile.toString() + ", Bytes to write: " + this.nNumberOfBytesToWrite);

        // Read the full buffer content
        var bufferContent = this.lpBuffer.readByteArray(this.nNumberOfBytesToWrite);
        var hexContent = hexdump(bufferContent, {
            offset: 0,
            length: this.nNumberOfBytesToWrite,  // Read the full length of the buffer
            header: true,
            ansi: false
        });

        // Send hex content as a string (full content)
        send("Full Buffer content:\n" + hexContent);

        let ascii_str = getASCIIString(this.lpBuffer, this.nNumberOfBytesToWrite);
        send("ASCII: \n" + ascii_str);
    },
    onLeave: function (retval) {
        // Send the result of the WriteFile call
        send("WriteFile returned: " + retval.toString());
    }
});
