// Utility function to convert an ArrayBuffer to a hex string and extract JSON block
function arrayBufferToHexAndJsonString(buffer) {
    const hexString = Array.prototype.map.call(new Uint8Array(buffer), byte => ('00' + byte.toString(16)).slice(-2)).join(' ');

    let asciiString = Array.prototype.map.call(new Uint8Array(buffer), byte => {
        return byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ''; // Include printable characters only
    }).join('').replace(/\x00/g, ''); // Remove null bytes

    const jsonStartIndex = asciiString.indexOf('{');
    if (jsonStartIndex !== -1) {
        asciiString = asciiString.slice(jsonStartIndex);
    } else {
        asciiString = "JSON block not found. ASCII content: " + asciiString;
    }

    return { hex: hexString, ascii: asciiString };
}

// Updated function to modify JSON fields, re-encode to UTF-16LE, and update buffer length
function modifyBufferFields(bufferPointer, bufferLength, fieldUpdates, pStubMsg) {
    const bufferContent = bufferPointer.readByteArray(bufferLength);
    if (!bufferContent) return;

    const { ascii: asciiContent } = arrayBufferToHexAndJsonString(bufferContent);

    // Locate JSON block in ASCII content
    const jsonStartIndex = asciiContent.indexOf('{');
    const jsonEndIndex = asciiContent.lastIndexOf('}') + 1;

    if (jsonStartIndex === -1 || jsonEndIndex === -1) {
        send("[!] JSON block not found in buffer content.");
        return;
    }

    const originalJson = asciiContent.slice(jsonStartIndex, jsonEndIndex);
    let modifiedJson = originalJson;

    try {
        const jsonObject = JSON.parse(originalJson);

        let modificationMade = false;
        for (const [fieldName, newValue] of Object.entries(fieldUpdates)) {
            if (fieldName in jsonObject) {
                send(`[## - Pre-Modification] Original field "${fieldName}": ${jsonObject[fieldName]}`);
                jsonObject[fieldName] = newValue;
                modificationMade = true;
            } else {
                send(`[!] Warning: Field "${fieldName}" not found in JSON content.`);
            }
        }

        if (modificationMade) {
            modifiedJson = JSON.stringify(jsonObject);

            // Convert modified JSON to UTF-16LE
            const utf16EncodedBuffer = [];
            for (const char of modifiedJson) {
                utf16EncodedBuffer.push(char.charCodeAt(0) & 0xFF, (char.charCodeAt(0) >> 8) & 0xFF);
            }
            utf16EncodedBuffer.push(0x00, 0x00); // Null terminator for UTF-16LE

            // Write back to buffer
            bufferPointer.writeByteArray(new Uint8Array(utf16EncodedBuffer));

            // Calculate and update the new buffer length in the structure
            const newBufferLength = utf16EncodedBuffer.length;
            pStubMsg.add(0x2C).writeU32(newBufferLength);
            send(`[## - Post-Modification] JSON modified. New Buffer Length set to ${newBufferLength} bytes (Hex: 0x${newBufferLength.toString(16)})`);

            // Verification step
            const verifyContent = bufferPointer.readByteArray(newBufferLength);
            const { hex: verifyHex, ascii: verifyAscii } = arrayBufferToHexAndJsonString(verifyContent);
            send(`[## - Verification] Modified Buffer Content (Hex):\n${verifyHex}`);
            send(`[## - Verification] Modified Buffer Content (ASCII):\n${verifyAscii}`);
        } else {
            send("[##] No modifications were made to the JSON buffer.");
        }
    } catch (error) {
        send(`[!] Error parsing or modifying JSON: ${error.message}`);
    }
}


// Hook the NdrGetBuffer function and modify buffer if conditions match
function interceptAndModifyNdrGetBuffer(fieldUpdates) {
    const ndrGetBuffer = Module.findExportByName('rpcrt4.dll', 'NdrGetBuffer');
    if (ndrGetBuffer !== null) {
        Interceptor.attach(ndrGetBuffer, {
            onEnter: function (args) {
                const pStubMsg = args[0];
                try {
                    const bufferPointer = pStubMsg.add(0x10).readPointer();
                    const bufferEndPointer = pStubMsg.add(0x18).readPointer();
                    const actualBufferLength = bufferEndPointer.sub(bufferPointer).toInt32();

                    send(`Buffer Pointer: ${bufferPointer}`);
                    send(`Buffer End Pointer: ${bufferEndPointer}`);
                    send(`Actual Buffer Length: ${actualBufferLength} bytes`);

                    if (bufferPointer && actualBufferLength > 0) {
                        modifyBufferFields(bufferPointer, actualBufferLength, fieldUpdates, pStubMsg);
                    }
                } catch (error) {
                    send("[!] Error accessing or modifying buffer in NdrGetBuffer: " + error.message);
                }
            }
        });
    } else {
        send("[!] Error: NdrGetBuffer not found in rpcrt4.dll.");
    }
}

// Specify the fields to update as key-value pairs in an object
const fieldUpdates = {
    "loginName": "test1@test-example.com",
    "sessionID": "new-session-id-123",
    "authToken": "new-auth-token-456"
};

// Call interceptAndModifyNdrGetBuffer with the field updates
interceptAndModifyNdrGetBuffer(fieldUpdates);
