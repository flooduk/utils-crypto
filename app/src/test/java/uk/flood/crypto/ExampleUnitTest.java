package uk.flood.crypto;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    @Test
    public void addition_isCorrect() throws Exception {
        assertEquals(4, 2 + 2);
    }

    @Test
    public void AESKey_from() throws Exception {
        AESFactory aesFactory = new AESFactory();
        AESKey key = aesFactory.generateFrom("hello, world!");
        String SHA256 = "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728";
        byte[] sha256 = hexStringToByteArray(SHA256);
        assertArrayEquals(key.getEncoded(), sha256);
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