package com.github.rubensousa.guiao5;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;


public class AliceThread extends Thread {

    /* Alice → Bob : gx
 Bob → Alice : gy
 Alice, Bob : K = g(x*y)*/
    private int ct;
    private Socket mSocket;
    private BigInteger mGpowModP;
    private BigInteger mPrime;
    private BigInteger mPrivateKey;
    private BigInteger mKey;

    public AliceThread(Socket socket, int ct, BigInteger prime, BigInteger gPowModP, BigInteger privateKey) {
        mSocket = socket;
        this.ct = ct;
        mPrime = prime;
        mGpowModP = gPowModP;
        mPrivateKey = privateKey;
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;

        try {
            ois = new ObjectInputStream(mSocket.getInputStream());
            oos = new ObjectOutputStream(mSocket.getOutputStream());

            // Receber o g^y do Bob
            BigInteger gY = new BigInteger(ois.readUTF());

            // Enviar o nosso g^x
            oos.writeUTF(mPrivateKey.toString());
            oos.flush();

            // Calcular a chave
            mKey = mGpowModP.modPow(gY, mPrime);

            CipherUtils cipherUtils = new CipherUtils(ois, oos, mKey);

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
