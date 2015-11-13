package com.github.rubensousa.guiao6;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;


public class AliceThread extends Thread {

    private int ct;
    private Socket mSocket;
    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgreement;


    public AliceThread(Socket socket, int ct, DHParameterSpec dhParameterSpec) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        mSocket = socket;
        this.ct = ct;

        // Criar gerador de par de chaves
        KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DH");
        aliceKeyPairGen.initialize(dhParameterSpec);

        // Gerar par de chaves pública e privada
        mKeyPair = aliceKeyPairGen.generateKeyPair();

        // Criar e inicializar acordo de chaves
        mKeyAgreement = KeyAgreement.getInstance("DH");
        mKeyAgreement.init(mKeyPair.getPrivate());
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;

        try {
            ois = new ObjectInputStream(mSocket.getInputStream());
            oos = new ObjectOutputStream(mSocket.getOutputStream());

            // Enviar a chave pública ao Bob
            oos.writeObject(mKeyPair.getPublic());
            oos.flush();

            // Recever a chave pública do Bob
            PublicKey bobPublicKey = (PublicKey) ois.readObject();

            // Gerar chave privada
            mKeyAgreement.doPhase(bobPublicKey, true);
            byte[] secret = mKeyAgreement.generateSecret();


            CipherUtils cipherUtils = new CipherUtils(ois, oos, secret);

            while (true) {
                System.out.println(ct + " : " + cipherUtils.readAndDecrypt());
            }

        } catch (EOFException e) {
            System.out.println("[" + ct + "]");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {

            if (ois != null) {
                try {
                    ois.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
