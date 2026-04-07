package vaultmind.service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class EncryptionService {
    private static final String ALGORITHM = "AES";

    // In a real application, you'd want to use a more secure way to derive or store keys.
    // For this prototype, we'll derive a key from a string or use a fixed one.
    private static SecretKeySpec generateKey(String secret) throws Exception {
        byte[] key = secret.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 32); // Use 256 bits
        return new SecretKeySpec(key, ALGORITHM);
    }

    public static byte[] encrypt(byte[] data, String secret) throws Exception {
        SecretKeySpec keySpec = generateKey(secret);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String secret) throws Exception {
        SecretKeySpec keySpec = generateKey(secret);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
