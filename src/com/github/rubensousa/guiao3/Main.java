package com.github.rubensousa.guiao3;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {

    /**
     *
     * mac_then_encrypt
     * Mensagem e o seu MAC -> encrypt -> Criptograma
     *
     *
     * encrypt_then_mac (Melhor)
     * Mensagem -> encrypt -> IV + Criptograma e seu MAC -> Mensagem final
     *
     */

    /**
     * Cifra a ser usada
     */
    public static final String CIPHER = "AES";


    public static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";

    /**
     * Algoritmo MAC a ser usado
     */
    public static final String MAC_ALGORITHM = "HmacSHA256";

    public static final String KEY_ALIAS = "passphrase";

    public static final String SECRET_KEY_ALIAS = "alias";

    public static final String MAC_KEY_ALIAS = "macalias";

    public static final String KEYSTORE_TYPE = "JCEKS";

    public static final byte[] IV = new byte[]{127, 45, 110, 46, 16, 108, 116, 7, 38, 48, 30, 122, 17, 35, 59, 47};

    public static final int IV_LENGTH = 16;

    /**
     * Tamanho da chave em bits
     */
    public static final int KEY_LENGTH = 128;

    public static void main(String[] args) {

        if (args.length == 1) {
            if (args[0].equals("-genkey")) {

                CipherUtils cipherUtils;
                try {
                    cipherUtils = new CipherUtils();
                    cipherUtils.generateKey();
                    System.exit(0);
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
                System.exit(-1);
            }
        } else {
            if (args.length == 3) {

                if (args[0].equals("-enc")) {
                    try {
                        CipherUtils cipherUtils = new CipherUtils(Cipher.ENCRYPT_MODE, args[1], args[2]);
                        cipherUtils.startMode();
                        System.exit(0);
                    } catch (KeyStoreException e) {
                        e.printStackTrace();
                    }
                    System.exit(-1);
                }

                if (args[0].equals("-dec")) {
                    try {
                        CipherUtils cipherUtils = new CipherUtils(Cipher.DECRYPT_MODE, args[1], args[2]);
                        cipherUtils.startMode();
                        System.exit(0);
                    } catch (KeyStoreException e) {
                        e.printStackTrace();
                    }
                    System.exit(-1);
                }

                howToUse();
            } else {
                howToUse();
            }
        }
    }

    private static void howToUse() {
        System.out.println("How to use:");
        System.out.println("prog -genkey");
        System.out.println("prog -enc <infile> <outfile>");
        System.out.println("prog -dec <infile> <outfile>");
        System.exit(-1);
    }

}
