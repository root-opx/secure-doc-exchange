package com.secure.exchange.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for High-Security Cryptographic Operations using AES-256 GCM.
 * <p>
 * This class handles:
 * <ul>
 * <li>Key Generation (256-bit)</li>
 * <li>Encryption (with random IV)</li>
 * <li>Decryption (extracting IV + Tag)</li>
 * </ul>
 * <p>
 * Zero Trust Principle: The key is never stored by the system, only generated
 * and returned.
 * </p>
 */
public class AesUtil {

    /**
     * Algorithm: Advanced Encryption Standard (AES)
     */
    private static final String ALGORITHM = "AES";

    /**
     * Mode/Padding: Galois/Counter Mode (GCM) without padding.
     * GCM provides both Confidentiality and Integrity (Authenticated Encryption).
     */
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * Key Size: 256 bits (Military Grade).
     */
    private static final int AES_KEY_SIZE = 256;

    /**
     * IV Length: 12 bytes (96 bits) is the recommended standard for GCM efficiency.
     */
    private static final int GCM_IV_LENGTH = 12;

    /**
     * Auth Tag Length: 128 bits (Maximum security tag).
     */
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * Prevents instantiation.
     */
    private AesUtil() {
    }

    /**
     * Generates a secure random 256-bit AES key.
     *
     * @return The key encoded as a Base64 String.
     * @throws Exception If JVM does not support AES-256.
     */
    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        SecretKey key = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Encrypts the provided data using AES-GCM.
     * <p>
     * Warning: A new random IV is generated for *every* encryption operation to
     * prevent
     * key-reuse attacks. The IV is prepended to the ciphertext.
     * </p>
     *
     * @param data      The raw byte array of the file/data to encrypt.
     * @param base64Key The AES-256 key (Base64 encoded string).
     * @return A byte array containing [IV (12 bytes) + CipherText + AuthTag].
     * @throws Exception If encryption fails (invalid key, etc).
     */
    public static byte[] encrypt(byte[] data, String base64Key) throws Exception {
        // 1. Decode the Base64 key
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        SecretKey key = new SecretKeySpec(keyBytes, ALGORITHM);

        // 2. Generate a random IV (Initialization Vector) - Nonce
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // 3. Initialize Cipher in ENCRYPT_MODE
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // 4. Perform Encryption
        byte[] cipherText = cipher.doFinal(data);

        // 5. Concatenate IV + CipherText
        // We must store the IV along with the ciphertext to decrypt it later.
        // It is safe to store the IV in plain text (it is public).
        byte[] encryptedData = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

        return encryptedData;
    }

    /**
     * Decrypts the provided AES-GCM encrypted data.
     *
     * @param encryptedData The byte array containing [IV + CipherText + AuthTag].
     * @param base64Key     The AES-256 key (Base64 encoded string).
     * @return The original decrypted byte array.
     * @throws javax.crypto.AEADBadTagException If the data has been tampered with
     *                                          or key is wrong.
     * @throws Exception                        For other generic crypto failures.
     */
    public static byte[] decrypt(byte[] encryptedData, String base64Key) throws Exception {
        // 1. Decode the Base64 key
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        SecretKey key = new SecretKeySpec(keyBytes, ALGORITHM);

        // 2. Extract IV (First 12 bytes)
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, iv.length);

        // 3. Extract CipherText (Remaining bytes)
        int cipherTextSize = encryptedData.length - GCM_IV_LENGTH;
        byte[] cipherText = new byte[cipherTextSize];
        System.arraycopy(encryptedData, GCM_IV_LENGTH, cipherText, 0, cipherTextSize);

        // 4. Initialize Cipher in DECRYPT_MODE
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        // 5. Perform Decryption (Authentication Tag verification happens here)
        return cipher.doFinal(cipherText);
    }
}
