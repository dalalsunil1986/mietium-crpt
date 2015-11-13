package com.github.rubensousa.guiao6;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class CipherUtils {


    /**
     * Cifra a ser usada
     */
    public static final String CIPHER = "AES";

    /**
     * Tipo de instância da cifra
     */
    public static final String CIPHER_INSTANCE = "AES/CTR/NoPadding";

    /**
     * Algoritmo de hash a ser usado
     */
    public static final String HASH_ALGORITHM = "SHA-256";

    /**
     * Algoritmo MAC a ser usado
     */
    public static final String MAC_ALGORITHM = "HmacSHA256";

    /**
     * Tamanho do MAC em bytes
     */
    public static final int MAC_SIZE = 32;

    private Cipher mCipher;

    private SecretKey mSecretKeyCipher;


    private ObjectInputStream mInputStream;

    private ObjectOutputStream mOutputStream;

    private Mac mMac;

    public CipherUtils(ObjectInputStream inputStream, ObjectOutputStream outputStream, byte[] key)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException,
            IOException, NoSuchPaddingException, InvalidKeyException {

        if (inputStream == null || outputStream == null) {
            throw new IllegalArgumentException("inputstream and outputstream can't be null");
        }

        mInputStream = inputStream;
        mOutputStream = outputStream;

        // Criar hash da chave privada
        MessageDigest sha256 = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] secretHash = sha256.digest(key);
        SecretKey secretKey = new SecretKeySpec(secretHash, 0, 16, CIPHER);

        // Inicializar Mac
        mMac = Mac.getInstance(MAC_ALGORITHM);
        mMac.init(new SecretKeySpec(secretHash, 16, 16, MAC_ALGORITHM));

        // Criar instância da cifra
        mCipher = Cipher.getInstance(CIPHER_INSTANCE);

        mSecretKeyCipher = new SecretKeySpec(secretKey.getEncoded(), CIPHER);
    }

    public void encrypt(String text) throws InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException,
            IOException, BadPaddingException, IllegalBlockSizeException, CloneNotSupportedException {

        byte[] iv = new byte[mCipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);

        mCipher.init(Cipher.ENCRYPT_MODE, mSecretKeyCipher, new IvParameterSpec(iv));

        byte[] data = text.getBytes();

        //Escrever vetor de inicialização
        mOutputStream.writeObject(iv);
        mOutputStream.flush();

        // Atualizar MAC com o vetor de inicialização
        mMac.update(iv);

        // Cifrar a string e enviar
        byte[] ciphered = mCipher.doFinal(data);
        mOutputStream.writeObject(ciphered);
        mOutputStream.flush();

        // Finalizar cálculo do MAC e enviar
        byte[] macData = mMac.doFinal(ciphered);

        // Reutilizar instância do Mac
        mMac = (Mac) mMac.clone();
        mOutputStream.writeObject(macData);
        mOutputStream.flush();
    }

    public String readAndDecrypt() throws InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException,
            IOException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        byte[] iv = (byte[]) mInputStream.readObject();

        mCipher.init(Cipher.ENCRYPT_MODE, mSecretKeyCipher, new IvParameterSpec(iv));

        mMac.update(iv);

        byte[] data = (byte[]) mInputStream.readObject();
        byte[] macData = (byte[]) mInputStream.readObject();

        byte[] macCalc = mMac.doFinal(data);

        if (!Arrays.equals(macData, macCalc)) {
            throw new IOException("macs não coincidem");
        }

        data = mCipher.doFinal(data);
        return new String(data, "UTF-8");
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
