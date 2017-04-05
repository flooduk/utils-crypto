package uk.flood.crypto;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class RSAFactory {

    private static final String RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding";

    private static final String RSA = "RSA";

    public PublicKey makeRSAPublicKey(BigInteger modulus, BigInteger exponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance(RSA).generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    public PrivateKey makeRSAPrivateKey(BigInteger modulus, BigInteger exponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance(RSA)
                .generatePrivate(new RSAPrivateKeySpec(modulus, exponent));
    }

    public Cipher encryptRSACipher(Key key)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(RSA_ECB_PKCS1Padding, Cipher.ENCRYPT_MODE, key);
    }

    public Cipher decryptRSACipher(Key key)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        return newInstance(RSA_ECB_PKCS1Padding, Cipher.DECRYPT_MODE, key);
    }

    private Cipher newInstance(String format, int opmode, Key key)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(format);
        cipher.init(opmode, key);
        return cipher;
    }


}
