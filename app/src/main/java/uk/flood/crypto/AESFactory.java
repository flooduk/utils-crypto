package uk.flood.crypto;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class AESFactory {

    private static final String AES_CBC_PKCS7PADDING = "AES/CBC/PKCS7Padding";

    private static final String AES_CFB_NOPADDING = "AES/CFB/NoPadding";

    private static final String SHA256 = "SHA-256";

    private static final int KEY_LENGTH = 256;

    public AESKey generateFrom(String value) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(SHA256);
        digest.update(value.getBytes());
        return new AESKey(digest.digest());
    }

    public AESKey generate(int length) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AESKey.KEY_ALGORITHM);
        keyGenerator.init(length);
        return new AESKey(keyGenerator.generateKey().getEncoded());
    }

    public AESKey generateDefault() throws NoSuchAlgorithmException {
        return generate(KEY_LENGTH);
    }

    public Cipher encryptCBCPCKS7Instance(AESKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(AES_CBC_PKCS7PADDING, Cipher.ENCRYPT_MODE, key);
    }

    public Cipher decryptCBCPCKS7Instance(AESKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(AES_CBC_PKCS7PADDING, Cipher.DECRYPT_MODE, key);
    }

    public Cipher encryptCFBNoPaddingInstance(AESKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(AES_CFB_NOPADDING, Cipher.ENCRYPT_MODE, key);
    }

    public Cipher decryptCFBNoPaddingInstance(AESKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(AES_CFB_NOPADDING, Cipher.DECRYPT_MODE, key);
    }

    private Cipher newInstance(String format, int opmode, AESKey key)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(format);
        cipher.init(opmode, key, new IvParameterSpec(AESKey.getInitializationVector()));
        return cipher;
    }

}
