package rsa;

import static rsa.RSA.*;

public class App {

    public static void main(String[] args) {
        System.out.println("Generando claves...");
        long p = 11;
        long q = 17;
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long e = 59;
        long d = modInverse(e, phi);

        System.out.println("Clave pública: (" + n + ", " + e + ")");
        System.out.println("Clave privada: " + d);

        System.out.println("-------------------------------------");

        System.out.println("Cifrado y Descifrado...");
        long mensaje = 185; // debe cumplir m ∈ [0, n - 1]

        long cifrado = modExp(mensaje, e, n);
        System.out.println("Mensaje cifrado: " + cifrado);

        long descifrado = decryptCRT(cifrado, d, p, q);
        System.out.println("Mensaje descifrado: " + descifrado);
    }
}
