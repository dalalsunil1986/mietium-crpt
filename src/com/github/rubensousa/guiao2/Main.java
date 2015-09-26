package com.github.rubensousa.guiao2;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {

    /**
     * Cifra a ser usada
     */
    public static final String CIPHER = "RC4";

    /**
     * Tamanho da chave em bits
     */
    public static final int KEY_LENGTH = 128;

    public static void main(String[] args) {

        if (args.length == 2) {
            if (args[0].equals("-genkey")) {
                generateKey(args[1]);
                System.exit(0);
            } else {
                howToUse();
            }
        } else {
            if (args.length == 4) {
                if (args[0].equals("-enc")) {
                    encryptFile(args[1], args[2], args[3]);
                    System.exit(0);
                }

                if (args[0].equals("-dec")) {
                    decryptFile(args[1], args[2], args[3]);
                    System.exit(0);
                }
                howToUse();
            } else {
                howToUse();
            }
        }
    }

    private static void howToUse() {
        System.out.println("How to use:");
        System.out.println("prog -genkey <keyfile>");
        System.out.println("prog -enc <keyfile> <infile> <outfile>");
        System.out.println("prog -dec <keyfile> <infile> <outfile>");
        System.exit(-1);
    }

    private static void generateKey(String filePath) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER);
            File file = new File(filePath);
            file.createNewFile();

            keyGenerator.init(KEY_LENGTH);

            SecretKey secretKey = keyGenerator.generateKey();

            byte[] key = secretKey.getEncoded();

            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(key);
            fileOutputStream.flush();
            System.exit(0);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        System.exit(-1);
    }

    private static byte[] readKey(String keyPath) {
        FileInputStream fileInputStream;
        try {
            fileInputStream = new FileInputStream(new File(keyPath));
            byte[] key = new byte[KEY_LENGTH / 8];

            if (fileInputStream.read(key) != key.length) {
                return null;
            }

            return key;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static void encryptFile(String keyPath, String inputPath, String outputPath) {
        try {
            byte[] key = readKey(keyPath);
            if (key == null) {
                System.exit(-1);
            }

            // Criar instância da cifra
            Cipher cipher = Cipher.getInstance(CIPHER);
            SecretKey secretKey = new SecretKeySpec(key, CIPHER);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            File input = new File(inputPath);
            File output = new File(outputPath);
            FileInputStream fileInputStream = new FileInputStream(input);
            CipherOutputStream fileOutputStream = new CipherOutputStream(new FileOutputStream(output), cipher);

            byte[] data = new byte[1024 * 10];
            int bytes;

            while ((bytes = fileInputStream.read(data)) != -1) {
                fileOutputStream.write(data, 0, bytes);
                fileOutputStream.flush();
            }

            System.exit(0);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        System.exit(-1);
    }

    private static void decryptFile(String keyPath, String inputPath, String outputPath) {
        try {
            byte[] key = readKey(keyPath);
            if (key == null) {
                System.exit(-1);
            }

            // Criar instância da cifra
            Cipher cipher = Cipher.getInstance(CIPHER);
            SecretKey secretKey = new SecretKeySpec(key, CIPHER);

            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            File input = new File(inputPath);
            File output = new File(outputPath);
            CipherInputStream fileInputStream = new CipherInputStream(new FileInputStream(input), cipher);
            FileOutputStream fileOutputStream = new FileOutputStream(output);

            byte[] data = new byte[1024 * 10];
            int bytes;

            while ((bytes = fileInputStream.read(data)) != -1) {
                fileOutputStream.write(data, 0, bytes);
                fileOutputStream.flush();
            }

            System.exit(0);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        System.exit(-1);

    }

}
