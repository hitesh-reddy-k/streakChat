const crypto = require("crypto");

// Encrypt with recipient's public key (RSA)
function encryptMessage(message, publicKey) {
    try {
        console.log("🔐 Starting message encryption...");
        console.log("📊 Encryption details:", {
            messageLength: message.length,
            publicKeyLength: publicKey.length,
            publicKeyPreview: publicKey.substring(0, 50) + "..."
        });

        if (!message || typeof message !== 'string') {
            throw new Error("Message must be a non-empty string");
        }

        if (!publicKey || typeof publicKey !== 'string') {
            throw new Error("Public key must be a non-empty string");
        }

        // Check if message is too long for RSA encryption
        // RSA 2048 can encrypt up to 245 bytes (2048/8 - 11 for PKCS1 padding)
        const maxMessageLength = 245;
        if (Buffer.from(message, 'utf8').length > maxMessageLength) {
            console.log("⚠️ Message too long for direct RSA encryption, using hybrid encryption");
            
            // For long messages, use AES + RSA hybrid encryption
            const aesKey = crypto.randomBytes(32); // 256-bit key
            const iv = crypto.randomBytes(16); // 128-bit IV
            
            // Encrypt message with AES
            const cipher = crypto.createCipher('aes-256-cbc', aesKey);
            let encryptedMessage = cipher.update(message, 'utf8', 'base64');
            encryptedMessage += cipher.final('base64');
            
            // Encrypt AES key with RSA
            const encryptedAESKey = crypto.publicEncrypt(publicKey, aesKey).toString('base64');
            
            // Combine encrypted AES key and encrypted message
            const result = JSON.stringify({
                type: 'hybrid',
                key: encryptedAESKey,
                iv: iv.toString('base64'),
                data: encryptedMessage
            });
            
            console.log("✅ Hybrid encryption completed");
            return Buffer.from(result).toString('base64');
        }

        // Direct RSA encryption for short messages
        const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message, 'utf8'));
        const result = encrypted.toString("base64");
        
        console.log("✅ Direct RSA encryption completed:", {
            originalLength: message.length,
            encryptedLength: result.length
        });
        
        return result;
        
    } catch (error) {
        console.error("❌ Encryption error:", error);
        throw new Error(`Encryption failed: ${error.message}`);
    }
}

// Decrypt with your private key (RSA)
function decryptMessage(encryptedMessage, privateKey) {
    try {
        console.log("🔓 Starting message decryption...");
        console.log("📊 Decryption details:", {
            encryptedLength: encryptedMessage.length,
            privateKeyLength: privateKey.length,
            privateKeyPreview: privateKey.substring(0, 50) + "..."
        });

        if (!encryptedMessage || typeof encryptedMessage !== 'string') {
            throw new Error("Encrypted message must be a non-empty string");
        }

        if (!privateKey || typeof privateKey !== 'string') {
            throw new Error("Private key must be a non-empty string");
        }

        try {
            // Try to parse as hybrid encryption first
            const hybridData = JSON.parse(Buffer.from(encryptedMessage, 'base64').toString('utf8'));
            
            if (hybridData.type === 'hybrid') {
                console.log("🔄 Detected hybrid encryption, decrypting...");
                
                // Decrypt AES key with RSA
                const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(hybridData.key, 'base64'));
                const iv = Buffer.from(hybridData.iv, 'base64');
                
                // Decrypt message with AES
                const decipher = crypto.createDecipher('aes-256-cbc', aesKey);
                let decrypted = decipher.update(hybridData.data, 'base64', 'utf8');
                decrypted += decipher.final('utf8');
                
                console.log("✅ Hybrid decryption completed");
                return decrypted;
            }
        } catch (parseError) {
            // Not hybrid encryption, continue with direct RSA
            console.log("ℹ️ Not hybrid encryption, trying direct RSA...");
        }

        // Direct RSA decryption
        const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, "base64"));
        const result = decrypted.toString("utf8");
        
        console.log("✅ Direct RSA decryption completed:", {
            decryptedLength: result.length
        });
        
        return result;
        
    } catch (error) {
        console.error("❌ Decryption error:", error);
        throw new Error(`Decryption failed: ${error.message}`);
    }
}

// Test encryption/decryption with a key pair
function testEncryption() {
    try {
        console.log("🧪 Testing encryption/decryption...");
        
        // Generate test key pair
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "pkcs1", format: "pem" },
            privateKeyEncoding: { type: "pkcs1", format: "pem" }
        });

        const testMessage = "Hello, this is a test message for encryption!";
        console.log("📝 Test message:", testMessage);

        // Test encryption
        const encrypted = encryptMessage(testMessage, publicKey);
        console.log("🔐 Encrypted message length:", encrypted.length);

        // Test decryption
        const decrypted = decryptMessage(encrypted, privateKey);
        console.log("🔓 Decrypted message:", decrypted);

        const success = testMessage === decrypted;
        console.log(success ? "✅ Encryption test PASSED" : "❌ Encryption test FAILED");
        
        return success;
        
    } catch (error) {
        console.error("❌ Encryption test error:", error);
        return false;
    }
}

// Validate key format
function validateKeyFormat(key, keyType = 'unknown') {
    try {
        console.log(`🔍 Validating ${keyType} key format...`);
        
        if (!key || typeof key !== 'string') {
            console.log(`❌ ${keyType} key is not a string`);
            return false;
        }

        if (!key.includes('-----BEGIN') || !key.includes('-----END')) {
            console.log(`❌ ${keyType} key missing PEM markers`);
            return false;
        }

        if (keyType === 'private' && !key.includes('PRIVATE KEY')) {
            console.log(`❌ Private key missing PRIVATE KEY marker`);
            return false;
        }

        if (keyType === 'public' && !key.includes('PUBLIC KEY')) {
            console.log(`❌ Public key missing PUBLIC KEY marker`);
            return false;
        }

        console.log(`✅ ${keyType} key format is valid`);
        return true;
        
    } catch (error) {
        console.error(`❌ Key validation error:`, error);
        return false;
    }
}

module.exports = { 
    encryptMessage, 
    decryptMessage, 
    testEncryption, 
    validateKeyFormat 
};