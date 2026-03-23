import javax.crypto.Cipher;//used for encryption and decryption
import javax.crypto.CipherOutputStream;//special stream that encrypts data on file
import java.io.FileInputStream;//File Handling
import java.io.FileOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.file.Paths;

// Add this to your EncryptionService.java

public class EncryptionService{
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");//generate key using aes algorithm
        keyGen.init(256); // Specifies AES-256
        return keyGen.generateKey();
    }
    public static void encryptFile(String filePath,SecretKey key,byte[] iv) throws Exception{
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec=new GCMParameterSpec(128,iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        try (FileInputStream fis = new FileInputStream(filePath);
             FileOutputStream fos = new FileOutputStream(filePath + ".enc");
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            // Write the IV at the beginning of the file so we can decrypt it later
            fos.write(iv);

            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, read);}}
    }
    public static void decryptFile(String encryptedFilePath,SecretKey key) throws Exception{
        try (FileInputStream fis = new FileInputStream(encryptedFilePath)) {
            byte[] iv = new byte[12];
            int ivRead = fis.read(iv);
            if (ivRead != 12) {
                throw new Exception("Invalid IV length in encrypted file.");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            String outputFilePath = encryptedFilePath.replace(".enc", ".dec");
            try (FileOutputStream fos = new FileOutputStream(outputFilePath);
                 javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(fis, cipher)) {

                byte[] buffer = new byte[8192];
                int read;
                while ((read = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, read);
                }
            }
        }}}