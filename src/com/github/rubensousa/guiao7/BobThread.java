package com.github.rubensousa.guiao7;


import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class BobThread extends Thread {


    private Socket mSocket;
    private RSAPrivateKey mRSAPrivateKey;

    public BobThread(Socket socket) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        mSocket = socket;

        File privateKeyFile = new File(KeyGen.PRIVATE_KEY);
        FileInputStream fileInputStream = new FileInputStream(privateKeyFile);
        DataInputStream dis = new DataInputStream(fileInputStream);

        byte[] privateKey = new byte[(int) privateKeyFile.length()];
        dis.readFully(privateKey);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        mRSAPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(mSocket.getOutputStream());
            ois = new ObjectInputStream(mSocket.getInputStream());

            // Receber chave pública da Alice
            RSAPublicKey alicePublicKey = (RSAPublicKey) ois.readObject();

            // Enviar chave privada
            oos.writeObject(mRSAPrivateKey);

            CipherUtils cipherUtils = new CipherUtils(ois, oos);
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

            while ((test = stdIn.readLine()) != null) {

                // Inicializar assinatura
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(mRSAPrivateKey);
                cipherUtils.encryptAndSend(test, alicePublicKey, signature);
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
