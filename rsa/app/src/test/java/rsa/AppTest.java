package rsa;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AppTest {

    @Test
    void testModInverseBasic() {
        assertEquals(27, RSA.modInverse(3, 40));
    }

    @Test
    void testModExpBasic() {
        assertEquals(6, RSA.modExp(2, 5, 13));
    }

    @Test
    void testModExpWithOne() {
        assertEquals(1, RSA.modExp(5, 0, 13));
    }

    @Test
    void testDecryptCRTSimple() {
        long p = 11;
        long q = 17;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 59;
        long d = RSA.modInverse(e, phi);

        long message = 42;
        long encrypted = RSA.modExp(message, e, n);
        long decrypted = RSA.decryptCRT(encrypted, d, p, q);

        assertEquals(message, decrypted);
    }

    @Test
    void testModInverseEdgeCases() {
        assertEquals(0, RSA.modInverse(10, 1));
    }

    @Test
    void testModExpLargeExponent() {
        assertEquals(11, RSA.modExp(7, 128, 19));
    }

    @Test
    void testEncryptDecryptMultipleValues() {
        long p = 61;
        long q = 53;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 17;
        long d = RSA.modInverse(e, phi);

        long[] messages = { 0, 1, 12, 100, 3120 };

        for (long message : messages) {
            long encrypted = RSA.modExp(message, e, n);
            long decrypted = RSA.decryptCRT(encrypted, d, p, q);
            assertEquals(message, decrypted, "Failed for message: " + message);
        }
    }

    @Test
    void testEncryptDecryptLargeNumbers() {
        long p = 101;
        long q = 113;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 3533;
        long d = RSA.modInverse(e, phi);

        long message = 9999;

        long encrypted = RSA.modExp(message, e, n);
        long decrypted = RSA.decryptCRT(encrypted, d, p, q);

        assertEquals(message, decrypted);
    }

    @Test
    void testEdgeValues() {
        long p = 61;
        long q = 53;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 17;
        long d = RSA.modInverse(e, phi);

        long[] messages = { 0, n - 1 };
        for (long message : messages) {
            long encrypted = RSA.modExp(message, e, n);
            long decrypted = RSA.decryptCRT(encrypted, d, p, q);
            assertEquals(message, decrypted, "Failed at edge: " + message);
        }
    }

    @Test
    void testDifferentMessagesProduceDifferentCiphertexts() {
        long p = 11, q = 17;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 59;
        long d = RSA.modInverse(e, phi);

        long m1 = 4, m2 = 5;
        long c1 = RSA.modExp(m1, e, n);
        long c2 = RSA.modExp(m2, e, n);

        assertNotEquals(c1, c2, "Different messages should not encrypt to the same ciphertext");
    }

    @Test
    void testMessageGreaterThanN() {
        long p = 11, q = 17;
        long n = p * q;
        long message = n + 1;

        long e = 59;
        long phi = (p - 1) * (q - 1);
        long d = RSA.modInverse(e, phi);

        long encrypted = RSA.modExp(message % n, e, n);
        long decrypted = RSA.decryptCRT(encrypted, d, p, q);

        assertEquals(message % n, decrypted);
    }
}
