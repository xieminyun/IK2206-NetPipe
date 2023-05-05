import org.junit.jupiter.params.provider.EnumSource;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {
    public SessionKey sessionKey;
    public Cipher cipher;
    private byte[] IVByte;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException {
        sessionKey = key;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
        IVByte = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        sessionKey = key;
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IVByte = ivbytes;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IVByte);
        cipher.init(mode, key.getSecretKey(), ivParameterSpec);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionKey;

    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return IVByte;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        return new CipherOutputStream(os, cipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        return new CipherInputStream(inputstream, cipher);
    }
}
