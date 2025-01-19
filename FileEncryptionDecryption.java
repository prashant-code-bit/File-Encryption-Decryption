import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptionDecryption {

    private static final String ALGORITHM = "AES";

    // Method to generate a Secret Key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256, new SecureRandom());
        return keyGenerator.generateKey();
    }

    // Method to encrypt a file
    public static void encryptFile(File inputFile, File encryptedFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            fis.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);
            fos.write(outputBytes);
        }
    }

    // Method to decrypt a file
    public static void decryptFile(File encryptedFile, File decryptedFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(decryptedFile)) {
            byte[] inputBytes = new byte[(int) encryptedFile.length()];
            fis.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);
            fos.write(outputBytes);
        }
    }

    // Save the secret key to a file
    public static void saveKey(SecretKey secretKey, File keyFile) throws IOException {
        byte[] encodedKey = secretKey.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write(encodedKey);
        }
    }

    // Load the secret key from a file
    public static SecretKey loadKey(File keyFile) throws IOException {
        byte[] encodedKey = Files.readAllBytes(keyFile.toPath());
        return new SecretKeySpec(encodedKey, ALGORITHM);
    }

    public static void main(String[] args) {
        try {
            // Example files
            File inputFile = new File("input.txt");
            File encryptedFile = new File("encrypted.dat");
            File decryptedFile = new File("decrypted.txt");
            File keyFile = new File("secret.key");

            // Generate and save the secret key
            SecretKey secretKey = generateKey();
            saveKey(secretKey, keyFile);

            // Encrypt the file
            encryptFile(inputFile, encryptedFile, secretKey);
            System.out.println("File encrypted successfully: " + encryptedFile.getAbsolutePath());

            // Load the key and decrypt the file
            SecretKey loadedKey = loadKey(keyFile);
            decryptFile(encryptedFile, decryptedFile, loadedKey);
            System.out.println("File decrypted successfully: " + decryptedFile.getAbsolutePath());

        } catch (Exception e) {
        }
    }
}
