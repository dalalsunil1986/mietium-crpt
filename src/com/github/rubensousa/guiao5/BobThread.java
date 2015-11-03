package com.github.rubensousa.guiao5;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;

public class BobThread extends Thread {

   /* Alice → Bob : gx
    Bob → Alice : gy
    Alice, Bob : K = g(x*y)*/

    private Socket mSocket;
    private BigInteger mGpowModP;
    private BigInteger mPrime;
    private BigInteger mPrivateKey;
    private BigInteger mKey;

    public BobThread(Socket socket, BigInteger prime, BigInteger gPowModP, BigInteger privateKey) {
        mSocket = socket;
        mPrime = prime;
        mGpowModP = gPowModP;
        mPrivateKey = privateKey;
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(mSocket.getOutputStream());
            ois = new ObjectInputStream(mSocket.getInputStream());

            // Enviar o nosso g^Y
            oos.writeUTF(mPrivateKey.toString());
            oos.flush();

            // Receber o g^X da Alice
            BigInteger gX = new BigInteger(ois.readUTF());

            // Calcular a chave
            mKey = mGpowModP.modPow(gX, mPrime);

            CipherUtils cipherUtils = new CipherUtils(ois, oos, mKey);
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
