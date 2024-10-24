function generateUUID() {
    let uuid = '', i, random;
    for (i = 0; i < 32; i++) {
        random = Math.random() * 16 | 0;

        if (i === 8 || i === 12 || i === 16 || i === 20) {
            uuid += '-';
        }

        uuid += (i === 12 ? 4 : (i === 16 ? (random & 3 | 8) : random)).toString(16);
    }
    return uuid;
}

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

// Intercepting NdrGetBuffer in rpcrt4.dll
Interceptor.attach(Module.findExportByName("rpcrt4.dll", "NdrGetBuffer"), {
    onEnter: function (args) {
        // args[0]: Pointer to the MIDL_STUB_MESSAGE structure
        // args[1]: The requested buffer size
        // args[2]: Pointer to the type format string for the object

        this.stubMessagePointer = args[0];
        this.bufferSize = args[1].toInt32();
        this.typeFormatStringPointer = args[2];

        this.uuid = generateUUID();

        send("\n ====== NdrGetBuffer - " + this.uuid +  " =======\n")

        // Send basic information about the NdrGetBuffer call
        send("[#] NdrGetBuffer called: StubMessage Pointer=" + this.stubMessagePointer.toString() +
             ", Buffer Size=" + this.bufferSize.toString() +
             ", Type Format String Pointer=" + this.typeFormatStringPointer.toString());

        // If the stub message pointer is valid, dump some memory from the structure
        if (!this.stubMessagePointer.isNull()) {
            var stubMessageContent = this.stubMessagePointer.readByteArray(64); // Reading first 64 bytes of MIDL_STUB_MESSAGE
            send("StubMessage Content (first 64 bytes):\n" + hexdump(stubMessageContent, {
                offset: 0,
                length: 64,
                header: true,
                ansi: false
            }));
        }

        // If the type format string pointer is valid, read its memory
        if (!this.typeFormatStringPointer.isNull()) {
            var typeFormatStringContent = this.typeFormatStringPointer.readByteArray(64); // Read 64 bytes of type format string
            send("Type Format String Content (first 64 bytes):\n" + hexdump(typeFormatStringContent, {
                offset: 0,
                length: 64,
                header: true,
                ansi: false
            }));
        }
    },
    onLeave: function (retval) {
        // Send the return value, which is a pointer to the buffer
        send("[#] (ONLEAVE) NdrGetBuffer returned: Buffer Pointer=" + retval.toString());

        // If the buffer pointer is valid and the buffer size is greater than 0, read the buffer content
        if (!retval.isNull() && this.bufferSize > 0) {
            var bufferContent = retval.readByteArray(this.bufferSize);
            send("[#] (ONLEAVE) Buffer Content HEX:\n" + hexdump(bufferContent, {
                offset: 0,
                length: this.bufferSize,
                header: true,
                ansi: false
            }));

            var asciiData = getASCIIString(retval, this.bufferSize);

            send("[#] (ONLEAVE) Buffer Content ASCII:\n" + asciiData);
        }

        send("\n ====== NdrGetBuffer - " + this.uuid +  "   =======\n")

    }
});
