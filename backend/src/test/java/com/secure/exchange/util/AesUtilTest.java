package com.secure.exchange.util;

import com.secure.exchange.util.AesUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;

class AesUtilTest {

    @Test
    void testEncryptionDecryptionCycle() throws Exception {
        // Arrange
        String originalText = "Hello Zero Trust World! 🔒";
        byte[] originalBytes = originalText.getBytes();
        String key = AesUtil.generateKey();

        // Act
        byte[] encrypted = AesUtil.encrypt(originalBytes, key);
        byte[] decrypted = AesUtil.decrypt(encrypted, key);
        String decryptedText = new String(decrypted);

        // Assert
        System.out.println("Original: " + originalText);
        System.out.println("Decrypted: " + decryptedText);

        Assertions.assertEquals(originalText, decryptedText, "Decryption should match original content");
        Assertions.assertNotEquals(new String(encrypted), originalText, "Ciphertext should not resemble plaintext");
    }

    @Test
    void testUniqueIVGeneration() throws Exception {
        // Arrange
        byte[] data = "Sensitive Data".getBytes();
        String key = AesUtil.generateKey();

        // Act
        byte[] enc1 = AesUtil.encrypt(data, key);
        byte[] enc2 = AesUtil.encrypt(data, key);

        // Assert
        Assertions.assertFalse(java.util.Arrays.equals(enc1, enc2),
                "Two encryptions of same data must yield different ciphertexts (IV uniqueness)");
    }

    @Test
    void testTamperDetection() throws Exception {
        // Arrange
        String text = "Do not touch this!";
        String key = AesUtil.generateKey();
        byte[] encrypted = AesUtil.encrypt(text.getBytes(), key);

        // Act - Tamper with the last byte (Payload)
        encrypted[encrypted.length - 1] ^= 1;

        // Assert - GCM should throw AEADBadTagException
        Assertions.assertThrows(javax.crypto.AEADBadTagException.class, () -> {
            AesUtil.decrypt(encrypted, key);
        }, "Modification of ciphertext should fail GCM Tag check");
    }
}
