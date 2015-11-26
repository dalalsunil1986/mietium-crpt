package com.github.rubensousa.guiao7;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class AliceThread extends Thread {

    private int ct;
    private Socket mSocket;
    private RSAPublicKey mRSAPublicKey;

    public AliceThread(Socket socket, int ct) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        mSocket = socket;
        this.ct = ct;

        File publicKeyFile = new File(KeyGen.PUBLIC_KEY);
        FileInputStream fileInputStream = new FileInputStream(publicKeyFile);
        DataInputStream dis = new DataInputStream(fileInputStream);

        byte[] publicKey = new byte[(int) publicKeyFile.length()];
        dis.readFully(publicKey);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        mRSAPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;

        try {
            ois = new ObjectInputStream(mSocket.getInputStream());
            oos = new ObjectOutputStream(mSocket.getOutputStream());

            // Enviar a chave pública ao Bob
            oos.writeObject(mRSAPublicKey);
            oos.flush();

            // Recever a chave privada do Bob
            RSAPrivateKey bobPrivateKey = (RSAPrivateKey) ois.readObject();

            // Inicializar assinatura
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(mRSAPublicKey);

            CipherUtils cipherUtils = new CipherUtils(ois, oos);

            while (true) {
                System.out.println(ct + " : " + cipherUtils.readAndDecrypt(bobPrivateKey, signature));
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
