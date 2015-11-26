package com.github.rubensousa.guiao7;


import javax.crypto.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class CipherUtils {

    /**
     * Tipo de instância da cifra
     */
    public static final String CIPHER_INSTANCE = "RSA";

    private Cipher mCipher;

    private ObjectInputStream mInputStream;

    private ObjectOutputStream mOutputStream;


    public CipherUtils(ObjectInputStream inputStream, ObjectOutputStream outputStream) throws NoSuchPaddingException,
            NoSuchAlgorithmException {

        if (inputStream == null || outputStream == null) {
            throw new IllegalArgumentException("inputstream and outputstream can't be null");
        }

        mInputStream = inputStream;
        mOutputStream = outputStream;

        // Criar instância da cifra
        mCipher = Cipher.getInstance(CIPHER_INSTANCE);
    }

    public void encryptAndSend(String text, RSAPublicKey publicKey, Signature signature) throws InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, IOException, SignatureException, CloneNotSupportedException {

        mCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] stringBytes = text.getBytes();
        byte[] output = mCipher.doFinal(stringBytes);

        mOutputStream.writeObject(output);
        mOutputStream.flush();

        signature.update(output);
        byte[] sign = signature.sign();

        mOutputStream.writeObject(sign);
        mOutputStream.flush();
    }

    public String readAndDecrypt(RSAPrivateKey privateKey, Signature signature) throws InvalidKeyException, IOException,
            ClassNotFoundException, SignatureException, BadPaddingException, IllegalBlockSizeException {

        mCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] data = (byte[]) mInputStream.readObject();
        byte[] sign = (byte[]) mInputStream.readObject();

        signature.update(data);

        if (signature.verify(sign)) {
            byte[] output = mCipher.doFinal(data);
            return new String(output);
        } else {
            System.out.println("Assinatura inválida");
            return "";
        }
    }

}
