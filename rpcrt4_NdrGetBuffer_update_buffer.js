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

// Function to modify multiple JSON fields in the buffer
function modifyBufferFields(bufferPointer, bufferLength, fieldUpdates) {
    const bufferContent = bufferPointer.readByteArray(bufferLength);
    if (!bufferContent) return;

    const { ascii: jsonContent } = arrayBufferToHexAndJsonString(bufferContent);
    try {
        const jsonObject = JSON.parse(jsonContent); // Parse JSON content

        // Loop through each field and update if it exists
        for (const [fieldName, newValue] of Object.entries(fieldUpdates)) {
            if (fieldName in jsonObject) {
                send(`[## - Pre-Modification] Original field "${fieldName}": ${jsonObject[fieldName]}`);
                jsonObject[fieldName] = newValue; // Update the field with the new value
            } else {
                send(`[!] Warning: Field "${fieldName}" not found in JSON content.`);
            }
        }

        // Convert updated JSON object back to a string and to UTF-8 bytes
        const updatedJsonString = JSON.stringify(jsonObject);
        const updatedBuffer = Memory.allocUtf8String(updatedJsonString);

        // Verify if the updated content fits within the original buffer
        const newLength = updatedJsonString.length;
        if (newLength <= bufferLength) {
            bufferPointer.writeByteArray(updatedBuffer.readByteArray(newLength));
            send(`[## - Post-Modification] Updated fields in JSON`);

            // Verification step: Read back the buffer and confirm change
            const verifyContent = bufferPointer.readByteArray(newLength);
            const { ascii: verifyAscii } = arrayBufferToHexAndJsonString(verifyContent);
            send(`[## - Verification] Modified Buffer Content:\n${verifyAscii}`);
        } else {
            send(`[!] Warning: Modified JSON length (${newLength} bytes) exceeds original buffer length (${bufferLength} bytes), modification skipped.`);
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
                        modifyBufferFields(bufferPointer, actualBufferLength, fieldUpdates);
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
