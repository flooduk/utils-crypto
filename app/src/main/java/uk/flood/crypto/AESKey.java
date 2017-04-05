package uk.flood.crypto;

import javax.crypto.spec.SecretKeySpec;

public final class AESKey extends SecretKeySpec {

    static final String KEY_ALGORITHM = "AES";

    static byte[] getInitializationVector() {
        return new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    }

    AESKey(byte[] key) {
        super(key, KEY_ALGORITHM);
    }


}
