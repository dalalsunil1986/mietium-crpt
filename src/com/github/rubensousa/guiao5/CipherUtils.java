package com.github.rubensousa.guiao5;


import com.github.rubensousa.guiao4.KeyStoreManager;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class CipherUtils {

    /**
     * Tamanho da chave em bits
     */
    public static final int KEY_LENGTH = 128;

    /**
     *
     */
    public static final int BUFFER_SIZE = 1024 * 1024 * 10;

    /**
     * Cifra a ser usada
     */
    public static final String CIPHER = "AES";

    /**
     * Tipo de instância da cifra
     */
    public static final String CIPHER_INSTANCE = "AES/CTR/NoPadding";

    /**
     * Nome da SecretKey da cifra a ser usada
     */
    public static final String CIPHER_SECRETKEY_ALIAS = "cipheralias";


    /**
     * Algoritmo MAC a ser usado
     */
    public static final String MAC_ALGORITHM = "HmacSHA256";

    /**
     * Tamanho do MAC em bytes
     */
    public static final int MAC_SIZE = 32;

    /**
     * Nome da SecretKey para o MAC
     */
    public static final String MAC_SECRETKEY_ALIAS = "macalias";


    /**
     * Modo da cifra
     */
    private int mCipherMode;

    private Cipher mCipher;

    private SecretKey mSecretKeyCipher;

    private KeyStoreManager mKeyStoreManager;

    private ObjectInputStream mInputStream;

    private ObjectOutputStream mOutputStream;

    private File mInputFile;

    public CipherUtils() throws KeyStoreException {
        mKeyStoreManager = new KeyStoreManager();
    }

    public static SecretKey generateKey() throws KeyStoreException, NoSuchAlgorithmException,
            IOException, CertificateException {
        KeyStoreManager km = new KeyStoreManager();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER);
        keyGenerator.init(KEY_LENGTH);
        SecretKey secretKey = keyGenerator.generateKey();
        km.saveKey(secretKey, CIPHER_SECRETKEY_ALIAS);
        return secretKey;
    }


    public CipherUtils(ObjectInputStream inputStream, ObjectOutputStream outputStream, BigInteger key)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException,
            IOException, NoSuchPaddingException {

        if (inputStream == null || outputStream == null) {
            throw new IllegalArgumentException("inputstream and outputstream can't be null");
        }

        mInputStream = inputStream;
        mOutputStream = outputStream;
        mCipherMode = Cipher.ENCRYPT_MODE;
        mKeyStoreManager = new KeyStoreManager();
        SecretKey secretKey = new SecretKeySpec(key.toByteArray(), 0, 16, CIPHER);

        byte[] keyEncoded = secretKey.getEncoded();

        // Criar instância da cifra
        mCipher = Cipher.getInstance(CIPHER_INSTANCE);

        mSecretKeyCipher = new SecretKeySpec(keyEncoded, CIPHER);
    }

    public CipherUtils(File inputFile, OutputStream outputStream) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableEntryException, IOException, NoSuchPaddingException {
        if (inputFile == null || outputStream == null) {
            throw new IllegalArgumentException("file and outputstream can't be null");
        }

        mCipherMode = Cipher.ENCRYPT_MODE;
        mKeyStoreManager = new KeyStoreManager();
        mInputFile = inputFile;
        SecretKey secretKey = mKeyStoreManager.loadKey(CIPHER_SECRETKEY_ALIAS);

        byte[] keyEncoded = secretKey.getEncoded();

        // Criar instância da cifra
        mCipher = Cipher.getInstance(CIPHER_INSTANCE);
        mSecretKeyCipher = new SecretKeySpec(keyEncoded, CIPHER);
    }

    public void encrypt(String text) throws InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException,
            IOException, BadPaddingException, IllegalBlockSizeException {

        byte[] iv = new byte[mCipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);

        mCipher.init(Cipher.ENCRYPT_MODE, mSecretKeyCipher, new IvParameterSpec(iv));

        // Inicializar MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHM);
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Gerar chave para o MAC
        SecretKey macSecretKey = mSecretKeyCipher;
        mac.init(macSecretKey);

        // Guardar chave do MAC
        mKeyStoreManager.saveKey(macSecretKey, MAC_SECRETKEY_ALIAS);

        byte[] data = text.getBytes();

        //Escrever vetor de inicialização
        mOutputStream.writeObject(iv);
        mOutputStream.flush();

        // Atualizar MAC com o vetor de inicialização
        mac.update(iv);

        // Cifrar a string e enviar
        byte[] ciphered = mCipher.doFinal(data);
        mOutputStream.writeObject(ciphered);
        mOutputStream.flush();

        // Finalizar cálculo do MAC e enviar
        byte[] macData = mac.doFinal(ciphered);

        mOutputStream.writeObject(macData);
        mOutputStream.flush();
    }

    public String readAndDecrypt() throws InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException,
            IOException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        byte[] iv = (byte[]) mInputStream.readObject();

        mCipher.init(Cipher.ENCRYPT_MODE, mSecretKeyCipher, new IvParameterSpec(iv));

        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(mSecretKeyCipher);
        mac.update(iv);

        byte[] data = (byte[]) mInputStream.readObject();
        byte[] macData = (byte[]) mInputStream.readObject();

        byte[] macCalc = mac.doFinal(data);

        if (!Arrays.equals(macData, macCalc)) {
            throw new IOException("macs não coincidem");
        }

        data = mCipher.doFinal(data);
        return new String(data, "UTF-8");
    }

    private void encrypt(Cipher cipher, SecretKey secretKeyCipher)
            throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, KeyStoreException, IOException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {

        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeyCipher, new IvParameterSpec(iv));


        // Inicializar MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHM);
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Gerar chave para o MAC
        SecretKey macSecretKey = keyGenerator.generateKey();
        mac.init(macSecretKey);

        // Guardar chave do MAC
        mKeyStoreManager.saveKey(macSecretKey, MAC_SECRETKEY_ALIAS);
        mKeyStoreManager.closeKeyStore();

        byte[] data = new byte[BUFFER_SIZE];
        int bytes;

        //Escrever vetor de inicialização no ficheiro
        mOutputStream.write(iv);
        mOutputStream.flush();

        // Atualizar MAC com o vetor de inicialização
        mac.update(iv);

        // Ler do ficheiro, ir cifrando e guardando o resultado no ficheiro, enquanto atualiza o MAC
        while ((bytes = mInputStream.read(data)) != -1) {
            byte[] ciphered = cipher.update(data, 0, bytes);
            mac.update(ciphered, 0, ciphered.length);
            mOutputStream.write(ciphered, 0, ciphered.length);
            mOutputStream.flush();
        }

        // Finalizar a cifra
        data = cipher.doFinal();
        mOutputStream.write(data, 0, data.length);
        mOutputStream.flush();

        // Finalizar cálculo do MAC e escrever no final do ficheiro
        mac.update(data, 0, data.length);
        data = mac.doFinal();
        mOutputStream.write(data, 0, data.length);
        mOutputStream.flush();
    }

    private void decrypt(Cipher cipher, SecretKey secretKeyCipher)
            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
            UnrecoverableEntryException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        byte[] iv = new byte[cipher.getBlockSize()];

        RandomAccessFile randomAccessFile = new RandomAccessFile(mInputFile, "r");


        // Ler vetor de inicialização
        if (randomAccessFile.read(iv) != cipher.getBlockSize()) {
            throw new IOException("IV não encontrado");
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKeyCipher, new IvParameterSpec(iv));
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Carregar chave do MAC
        SecretKey macSecretKey = mKeyStoreManager.loadKey(MAC_SECRETKEY_ALIAS);
        mKeyStoreManager.closeKeyStore();
        mac.init(macSecretKey);

        // Calcular MAC do vetor de inicialização
        mac.update(iv);

        byte[] data = new byte[BUFFER_SIZE];
        int bytes;
        int totalBytes;

        randomAccessFile.seek(0);
        // Verificar se o tamanho do ficheiro bate certo, saltando bytes até à posição do MAC
        if (randomAccessFile.skipBytes((int) mInputFile.length() - MAC_SIZE) != mInputFile.length() - MAC_SIZE) {
            throw new IOException("MAC não encontrado");
        }

        byte[] macOriginal = new byte[MAC_SIZE];

        // Ler MAC do ficheiro
        if (randomAccessFile.read(macOriginal) != MAC_SIZE) {
            throw new IOException("MAC danificado");
        }

        // Colocar apontador no primeiro byte do criptograma
        randomAccessFile.seek(iv.length);
        totalBytes = iv.length;

        // Calcular o MAC a partir do criptograma atual
        while ((bytes = randomAccessFile.read(data)) != -1) {
            totalBytes += bytes;
            if (totalBytes >= mInputFile.length() - MAC_SIZE) {
                mac.update(data, 0, bytes - MAC_SIZE);
            } else {
                mac.update(data, 0, bytes);
            }
        }

        byte[] macCalculated = mac.doFinal();

        // Se os dois MAC baterem certo, desencriptar o ficheiro
        if (checkMac(macOriginal, macCalculated)) {

            totalBytes = iv.length;
            randomAccessFile.seek(totalBytes);

            while ((bytes = randomAccessFile.read(data)) != -1) {
                totalBytes += bytes;

                if (totalBytes >= mInputFile.length() - MAC_SIZE) {
                    mOutputStream.write(cipher.update(data, 0, bytes - MAC_SIZE));
                } else {
                    mOutputStream.write(cipher.update(data, 0, bytes));
                }

                mOutputStream.flush();
            }
            mOutputStream.write(cipher.doFinal());
            mOutputStream.flush();
        } else {
            System.out.println("O ficheiro foi modificado e não pode ser desencriptado");
            System.exit(-1);
        }
    }

    private boolean checkMac(byte[] original, byte[] generated) {
        if (original.length != generated.length) {
            return false;
        }

        for (int i = 0; i < MAC_SIZE; i++) {
            if (original[i] != generated[i]) {
                return false;
            }
        }

        return true;
    }

}
