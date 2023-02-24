import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

public class SessionCipherTest  {
    static String PLAINSTRING = "Time flies like an arrow. Fruit flies like a banana.";
    static Integer KEYLENGTH = 128;
    // Encoded key and IV (Base64-encoding with padding) for decryption with given key/iv and ciphertext
    static String ENCODEDKEY = "r2X8tjnKkFlzugajYIDBCw==";
    static byte[] KEYBYTES =   {(byte) 0xaf, (byte) 0x65, (byte) 0xfc, (byte) 0xb6, (byte) 0x39, (byte) 0xca, (byte) 0x90, (byte) 0x59,
                                (byte) 0x73, (byte) 0xba, (byte) 0x06, (byte) 0xa3, (byte) 0x60, (byte) 0x80, (byte) 0xc1, (byte) 0x0b};
    static String ENCODEDIV = "O737ICi56VMpp2UAm5BwKw==";
    static byte[] IVBYTES =    {(byte) 0x3b, (byte) 0xbd, (byte) 0xfb, (byte) 0x20, (byte) 0x28, (byte) 0xb9, (byte) 0xe9, (byte) 0x53,
                                (byte) 0x29, (byte) 0xa7, (byte) 0x65, (byte) 0x00, (byte) 0x9b, (byte) 0x90, (byte) 0x70, (byte) 0x2b};

    // Ciphertext obtained by encrypting plaintext with AES/CTR/NoPadding cipher and ENCODEDKEY/ENCODEDIV
    static byte[] CIPHERDATA = {(byte) 0x4e, (byte) 0x19, (byte) 0xec, (byte) 0xd1, (byte) 0x29, (byte) 0xb4, (byte) 0x2f, (byte) 0x1e,
                                (byte) 0x67, (byte) 0x1c, (byte) 0x6f, (byte) 0x57, (byte) 0xdb, (byte) 0xe9, (byte) 0xc6, (byte) 0xde,
                                (byte) 0x32, (byte) 0x9c, (byte) 0xdf, (byte) 0xf3, (byte) 0x1c, (byte) 0x73, (byte) 0xef, (byte) 0xf4,
                                (byte) 0xd7, (byte) 0xf3, (byte) 0x26, (byte) 0x9e, (byte) 0x0d, (byte) 0xdd, (byte) 0x94, (byte) 0x0d,
                                (byte) 0xa7, (byte) 0x4b, (byte) 0xe4, (byte) 0xa8, (byte) 0x06, (byte) 0xe4, (byte) 0x01, (byte) 0x49,
                                (byte) 0x14, (byte) 0xc5, (byte) 0x33, (byte) 0xe2, (byte) 0x59, (byte) 0x79, (byte) 0x5c, (byte) 0x6c,
                                (byte) 0x28, (byte) 0x59, (byte) 0xb3, (byte) 0xf2};


    /* Encrypt a byte array plaintext with sessionencrypter and return a byte array ciphertext */

    private byte[] encryptByteArray(byte[] plaintext, SessionCipher sessioncipher) throws Exception {
        try (
             ByteArrayOutputStream cipherByteArrayOutputStream = new ByteArrayOutputStream();
             CipherOutputStream cipherout = sessioncipher.openEncryptedOutputStream(cipherByteArrayOutputStream);
             ) {
            cipherout.write(plaintext);
            return cipherByteArrayOutputStream.toByteArray();
        }
    }

    /* Decrypt a byte array ciphertext with sessiondecrypter and return a byte array plaintext */

    private byte[] decryptByteArray(byte[] ciphertext, SessionCipher sessioncipher) throws Exception {

        // Attach input file to decrypter, and open output file
        try (
             ByteArrayInputStream cipherByteArrayInputStream = new ByteArrayInputStream(ciphertext);
             CipherInputStream cipherin = sessioncipher.openDecryptedInputStream(cipherByteArrayInputStream);
             ) {
            byte[] plainout = cipherin.readAllBytes();
            return plainout;
        }
    }

    /* Test that SessionCiphers are not generated with the same IV */
    @Test
    public void testIVsAreUnique() throws Exception {
        SessionKey key = new SessionKey(KEYLENGTH);
        SessionCipher sessioncipher1 = new SessionCipher(key);
        SessionCipher sessioncipher2 = new SessionCipher(key);

        assertTrue(!Arrays.equals(sessioncipher1.getIVBytes(), sessioncipher2.getIVBytes()),
                    "Different SessionCiphers have different IVs");
    }

    /* Test that encryption followed by decryption gives original plaintext */
    @Test
    public void testEncryptThenDecryptGivesPlaintext() throws Exception {
     // Create cipher instance for a given key length
        SessionKey key = new SessionKey(KEYLENGTH);
        SessionCipher sessioncipher = new SessionCipher(key);
        byte[] plaintext = PLAINSTRING.getBytes();
        byte[] ciphertext = encryptByteArray(plaintext, sessioncipher);
        byte[] decipheredtext = decryptByteArray(ciphertext, sessioncipher);

        assertArrayEquals(decipheredtext, plaintext,
                          "Encryption followed by decryption gives original plaintext");
    }

    /* Test that encryption with derived cipher followed by decryption gives original plaintext */
    @Test
    public void testDerivedEncryptThenDecryptGivesPlaintext() throws Exception {
     // Create cipher instance for a given key length
        SessionKey key = new SessionKey(KEYLENGTH);
        SessionCipher basecipher = new SessionCipher(key);
        SessionCipher sessioncipher = new SessionCipher(basecipher.getSessionKey(),
                                                        basecipher.getIVBytes(), Cipher.ENCRYPT_MODE);
        SessionCipher derivedcipher = new SessionCipher(sessioncipher.getSessionKey(),
                                                           sessioncipher.getIVBytes(), Cipher.ENCRYPT_MODE);
        byte[] plaintext = PLAINSTRING.getBytes();
        byte[] ciphertext = encryptByteArray(plaintext, sessioncipher);
        byte[] decipheredtext = decryptByteArray(ciphertext, derivedcipher);

        assertArrayEquals(decipheredtext, plaintext,
                          "Encryption followed by decryption gives original plaintext");
    }

    /* Test that decryption with given ciphertext, key and IV returns plaintext.
       Key and IV are given as byte arrays.
       Ciphertext was created with AES/CTR/NoPadding cipher.
    */
    @Test
    public void testDecryptedCiphertextGivesPlaintext() throws Exception {

        SessionKey key = new SessionKey(KEYBYTES);
        SessionCipher sessioncipher = new SessionCipher(key, IVBYTES,Cipher.ENCRYPT_MODE);
        byte[] decipheredtext = decryptByteArray(CIPHERDATA, sessioncipher);
        byte[] plaintext = PLAINSTRING.getBytes();

        assertArrayEquals(decipheredtext, plaintext,
                          "Decryption of known ciphertext gives plaintext");
    }

    /*
     * Encrypt content of plaintext file, then decrypt, and write output
     * to another plaintext.
     * Check that files are equals
     */
    @Test
    public void testDecryptedEncryptedFileGivesPlaintextFile() throws Exception {
        String PLAININPUT = "plaininput.txt";
        String PLAINOUTPUT = "plainoutput.txt";
        String CIPHER = "cipher.bin";
        Integer KEYLENGTH = 128;

        // Create cipher instance for a given key length
        SessionKey key = new SessionKey(KEYLENGTH);
        SessionCipher sessioncipher = new SessionCipher(key);

        // Attach output file to cipher, and open input file
        try (
             FileOutputStream outstream = new FileOutputStream(CIPHER);
             CipherOutputStream cryptooutstream = sessioncipher.openEncryptedOutputStream(outstream);
             FileInputStream plaininstream = new FileInputStream(PLAININPUT);
             ) {

            // Copy data from plain input to crypto output via cipher
            cryptooutstream.write(plaininstream.readAllBytes());
        }

        // Now ciphertext is in cipher output file. Decrypt it back to plaintext.

        // Attach input file to cipher, and open output file
        try (
             FileInputStream instream = new FileInputStream(CIPHER);
             CipherInputStream cryptoinstream = sessioncipher.openDecryptedInputStream(instream);
             FileOutputStream plainoutstream = new FileOutputStream(PLAINOUTPUT);
             ) {

            // Copy data from cipher input to plain output via decrypter
            plainoutstream.write(cryptoinstream.readAllBytes());
        }

        // Check that input and output files are the same.

        FileInputStream orig = new FileInputStream(PLAININPUT);
        FileInputStream result = new FileInputStream(PLAINOUTPUT);
        /*System.out.println(orig.readAllBytes());
        System.out.println(result.readAllBytes());*/

        // Files should be small, so just read into memory and compare as byte arrays
        assertArrayEquals(orig.readAllBytes(), result.readAllBytes(),
                          "Encryption and decryption of file gives original plaintext");
    }
}
