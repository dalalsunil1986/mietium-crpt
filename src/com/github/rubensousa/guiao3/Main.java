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

    public static final String KEYSTORE_TYPE = "JCEKS";

    public static final byte[] IV = new byte[]{127, 45, 110, 46, 16, 108, 116, 7, 38, 48, 30, 122, 17, 35, 59, 47};

    /**
     * Tamanho da chave em bits
     */
    public static final int KEY_LENGTH = 128;

    public static void main(String[] args) {

        if (args.length == 1) {
            if (args[0].equals("-genkey")) {
                try {
                    generateKey();
                } catch (IOException e) {
                    e.printStackTrace();
                    System.exit(-1);
                }
                System.exit(0);
            }

            if (args[0].equals("-load")) {
                loadKey();
                System.exit(0);
            } else {
                howToUse();
            }
        } else {
            if (args.length == 3) {

                if (args[0].equals("-enc")) {
                    encryptFile(args[1], args[2]);
                    System.exit(0);
                }

                if (args[0].equals("-dec")) {
                    decryptFile(args[1], args[2]);
                    System.exit(0);
                }
                howToUse();
            } else {
                System.out.println("test");
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

    /**
     * Carregar a SecretKey guardada na KeyStore
     *
     * @return SecretKey guardada ou null se não foi encontrada
     */
    private static SecretKey loadKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

            System.out.println("Introduza a senha da KeyStore:");
            char[] password = System.console().readPassword();

            KeyStore.ProtectionParameter protParam =
                    new KeyStore.PasswordProtection(password);

            FileInputStream fileInputStream = new FileInputStream(KEY_ALIAS);
            keyStore.load(fileInputStream, password);

            KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry)
                    keyStore.getEntry(SECRET_KEY_ALIAS, protParam);

            return skEntry.getSecretKey();
        } catch (KeyStoreException | UnrecoverableEntryException |
                CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static void saveKey(FileInputStream fis, char[] password, KeyStore keyStore, SecretKey secretKey) throws IOException {

        FileOutputStream fos = null;

        try {
            keyStore.load(fis, password);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
            keyStore.setEntry(SECRET_KEY_ALIAS, skEntry, protParam);

            fos = new FileOutputStream(KEY_ALIAS);
            keyStore.store(fos, password);
            System.exit(0);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                fis.close();
            }

            if (fos != null) {
                fos.close();
            }
        }
        System.exit(-1);
    }

    private static void generateKey() throws IOException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER);
            keyGenerator.init(KEY_LENGTH);
            SecretKey secretKey = keyGenerator.generateKey();

            System.out.println("Introduza uma senha para guardar a chave:");
            char[] password = System.console().readPassword();

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

            FileInputStream fileInputStream = null;
            try {
                fileInputStream = new FileInputStream(KEY_ALIAS);
                saveKey(fileInputStream, password, keyStore, secretKey);
            } catch (FileNotFoundException e) {
                try {
                    keyStore.load(null, password);
                    saveKey(fileInputStream, password, keyStore, secretKey);
                } catch (CertificateException e1) {
                    e1.printStackTrace();
                }
            } finally {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            }

            System.exit(0);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }
        System.exit(-1);
    }

    private static void encryptFile(String inputPath, String outputPath) {
        CipherOutputStream cipherOutputStream = null;
        FileInputStream fileInputStream = null;

        try {
            SecretKey sKey = loadKey();
            if (sKey == null) {
                System.exit(-1);
            }

            byte[] key = sKey.getEncoded();
            // Criar instância da cifra
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            SecretKey secretKey = new SecretKeySpec(key, CIPHER);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
            File input = new File(inputPath);
            File output = new File(outputPath);
            fileInputStream = new FileInputStream(input);
            cipherOutputStream = new CipherOutputStream(new FileOutputStream(output), cipher);

            byte[] data = new byte[1024 * 10];
            int bytes;

            while ((bytes = fileInputStream.read(data)) != -1) {
                cipherOutputStream.write(data, 0, bytes);
                cipherOutputStream.flush();
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.exit(-1);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (cipherOutputStream != null) {
                try {
                    cipherOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        System.exit(0);
    }

    private static void decryptFile(String inputPath, String outputPath) {
        CipherInputStream cipherInputStream = null;
        FileOutputStream fileOutputStream = null;

        try {
            SecretKey sKey = loadKey();
            if (sKey == null) {
                System.exit(-1);
            }

            byte[] key = sKey.getEncoded();

            // Criar instância da cifra
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            SecretKey secretKey = new SecretKeySpec(key, CIPHER);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

            File input = new File(inputPath);
            File output = new File(outputPath);
            cipherInputStream = new CipherInputStream(new FileInputStream(input), cipher);
            fileOutputStream = new FileOutputStream(output);

            byte[] data = new byte[1024 * 10];
            int bytes;

            while ((bytes = cipherInputStream.read(data)) != -1) {
                fileOutputStream.write(data, 0, bytes);
                fileOutputStream.flush();
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.exit(-1);
        } finally {
            if (cipherInputStream != null) {
                try {
                    cipherInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        System.exit(0);
    }

}
