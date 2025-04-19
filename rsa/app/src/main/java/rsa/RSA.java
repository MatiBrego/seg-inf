package rsa;

public class RSA {

    // Algoritmo extendido de Euclides para encontrar la inversa multiplicativa
    public static long modInverse(long a, long m) {
        long m0 = m, t, q;
        long x0 = 0, x1 = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            q = a / m;
            t = m;

            m = a % m;
            a = t;
            t = x0;

            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }

    // Exponenciación rápida (a^b mod n)
    public static long modExp(long base, long exp, long mod) {
        long result = 1;
        base = base % mod;
        while (exp > 0) {
            if ((exp & 1) == 1)
                result = (result * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }

    // Descifrado usando el Teorema de los Restos Chinos
    public static long decryptCRT(long x, long d, long p, long q) {
        long dp = d % (p - 1);
        long dq = d % (q - 1);

        long qInv = modInverse(q, p);

        long m1 = modExp(x, dp, p);
        long m2 = modExp(x, dq, q);

        long h = (qInv * ((m1 - m2 + p) % p)) % p;

        return ((m2 + h * q) % (p * q) + (p * q)) % (p * q);
    }


}
