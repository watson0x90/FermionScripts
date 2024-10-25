// Utility function to convert an ArrayBuffer to a hex string and UTF-16LE ASCII string, always returning UTF-16LE content
function arrayBufferToHexAndJsonString(buffer) {
    // Convert buffer to hex string for full representation
    const hexString = Array.prototype.map.call(new Uint8Array(buffer), byte => ('00' + byte.toString(16)).slice(-2)).join(' ');

    // Interpret the buffer as a UTF-16LE string
    const utf16String = String.fromCharCode.apply(null, new Uint16Array(buffer));

    // Locate JSON block if present
    const jsonStartIndex = utf16String.indexOf('{');
    let jsonContent;
    if (jsonStartIndex !== -1) {
        // Extract JSON substring starting at the first '{' character
        jsonContent = utf16String.slice(jsonStartIndex).replace(/\x00/g, ''); // Remove null characters
    } else {
        // If no JSON, print UTF-16LE content directly
        jsonContent = utf16String.replace(/\x00/g, ''); // Remove null characters for display
    }

    return { hex: hexString, ascii: jsonContent };
}


function interceptNdrGetBuffer(printHex) {
    const ndrGetBuffer = Module.findExportByName('rpcrt4.dll', 'NdrGetBuffer');
    if (ndrGetBuffer !== null) {
        Interceptor.attach(ndrGetBuffer, {
            onEnter: function (args) {
                const pStubMsg = args[0];
                const requestedBufferLength = args[1].toInt32();
                const rpcHandle = args[2];

                send(`[## - NdrGetBuffer] Buffer Preparation`);
                send(`Requested Buffer Length: ${requestedBufferLength} bytes`);
                send(`RPC Handle: ${rpcHandle}`);

                // Access RpcMsg and Buffer pointers within MIDL_STUB_MESSAGE
                try {
                    const pRpcMsg = pStubMsg.readPointer();
                    const bufferPointer = pStubMsg.add(0x10).readPointer();
                    const bufferEndPointer = pStubMsg.add(0x18).readPointer();
                    const actualBufferLength = bufferEndPointer.sub(bufferPointer).toInt32();

                    send(`Buffer Pointer: ${bufferPointer}`);
                    send(`Buffer End Pointer: ${bufferEndPointer}`);
                    send(`Actual Buffer Length Calculated: ${actualBufferLength} bytes (Hex: 0x${actualBufferLength.toString(16)})`);
                    
                    const fBufferValid = pStubMsg.add(0x9C).readU8();
                    send(`Buffer Validity Flag (fBufferValid): ${fBufferValid ? 'Set' : 'Not Set'}\n`);

                    // Log the buffer content in both hex and extracted JSON ASCII (interpreted as UTF-16LE)
                    if (!bufferPointer.isNull() && actualBufferLength > 0 && actualBufferLength < 0x10000) {
                        const bufferContent = bufferPointer.readByteArray(actualBufferLength);
                        if (bufferContent) {
                            const { hex, ascii } = arrayBufferToHexAndJsonString(bufferContent);
                            if (printHex) {
                                send(`[## - NdrGetBuffer] Buffer Content (HEX) (${actualBufferLength} bytes):\n${hex}\n`);
                            }
                            send(`[## - NdrGetBuffer] Buffer Content (ASCII as UTF-16LE JSON) (${actualBufferLength} bytes):\n${ascii}\n`);
                        }
                    }
                } catch (error) {
                    send("[!] Error accessing buffer or RpcMsg in MIDL_STUB_MESSAGE: " + error.message);
                }
            }
        });
    } else {
        send("[!] Error: NdrGetBuffer not found in rpcrt4.dll.");
    }
}

/**
 * @param {bool} - print hex chars
 */
interceptNdrGetBuffer(true);
