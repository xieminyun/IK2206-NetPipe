import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    private SecretKey secretKey;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerate = KeyGenerator.getInstance("AES");
        SecureRandom sRandom = new SecureRandom();
        keyGenerate.init(length, sRandom);
        this.secretKey = keyGenerate.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        this.secretKey = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return secretKey.getEncoded();
    }
}

