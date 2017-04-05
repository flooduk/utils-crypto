package uk.flood.crypto;

import org.junit.Test;
import org.junit.runner.RunWith;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import javax.crypto.Cipher;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Instrumentation test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {

    @Test
    public void useAppContext() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("uk.flood.crypto", appContext.getPackageName());

    }

    @Test
    public void AESKey_random1() throws Exception {
        AESFactory aesFactory = new AESFactory();
        AESKey key1 = aesFactory.generateFrom("hello, world!");
        Cipher encryptCipher = aesFactory.encryptCBCPCKS7Instance(key1);

        byte[] data = new byte[256];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)i;
        }

        byte[] encryptedData = encryptCipher.doFinal(data);

        String SHA256 = "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728";
        byte[] sha256 = hexStringToByteArray(SHA256);
        AESKey key2 = new AESKey(sha256);
        Cipher decryptCipher = aesFactory.decryptCBCPCKS7Instance(key2);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        assertArrayEquals(data, decryptedData);

    }

    @Test
    public void AESKey_random2() throws Exception {
        AESFactory aesFactory = new AESFactory();
        AESKey key1 = aesFactory.generateFrom("hello, world!");
        Cipher encryptCipher = aesFactory.encryptCFBNoPaddingInstance(key1);

        byte[] data = new byte[256];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte)i;
        }

        byte[] encryptedData = encryptCipher.doFinal(data);

        String SHA256 = "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728";
        byte[] sha256 = hexStringToByteArray(SHA256);
        AESKey key2 = new AESKey(sha256);
        Cipher decryptCipher = aesFactory.decryptCFBNoPaddingInstance(key2);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        assertArrayEquals(data, decryptedData);

    }



    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


}
