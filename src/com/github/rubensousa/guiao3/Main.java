package com.github.rubensousa.guiao3;

import javax.crypto.*;
import java.security.*;

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
