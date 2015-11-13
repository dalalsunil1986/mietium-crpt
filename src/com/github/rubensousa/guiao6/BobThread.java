package com.github.rubensousa.guiao6;


import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

public class BobThread extends Thread {


    private Socket mSocket;
    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgreement;
    private DHParameterSpec mDhParameterSpec;

    public BobThread(Socket socket) {
        mSocket = socket;
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(mSocket.getOutputStream());
            ois = new ObjectInputStream(mSocket.getInputStream());

            // Receber chave pública da Alice
            PublicKey alicePublicKey = (PublicKey) ois.readObject();

            // Criar parâmetros do DH a partir da chave da Alice
            mDhParameterSpec = ((DHPublicKey) alicePublicKey).getParams();

            // Criar gerador de par de chaves
            KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DH");
            bobKeyPairGen.initialize(mDhParameterSpec);

            // Gerar par de chaves pública e privada
            mKeyPair = bobKeyPairGen.generateKeyPair();

            // Criar e inicializar acordo de chaves
            mKeyAgreement = KeyAgreement.getInstance("DH");
            mKeyAgreement.init(mKeyPair.getPrivate());


            // Enviar a chave pública do Bob
            oos.writeObject(mKeyPair.getPublic());

            // Gerar chave privada
            mKeyAgreement.doPhase(alicePublicKey, true);
            byte[] secret = mKeyAgreement.generateSecret();

            CipherUtils cipherUtils = new CipherUtils(ois, oos, secret);
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

            while ((test = stdIn.readLine()) != null) {
                cipherUtils.encrypt(test);
            }

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
