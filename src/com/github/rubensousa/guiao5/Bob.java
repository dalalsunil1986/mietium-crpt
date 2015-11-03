package com.github.rubensousa.guiao5;


import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

public class Bob {

    public static void main(String[] args) {

        BigInteger y = new BigInteger(Alice.p.bitLength(), new SecureRandom());
        BigInteger gPowYModp = Alice.g.modPow(y, Alice.p);

        try {
            Socket s = new Socket("localhost", Alice.PORT);
            BobThread bobThread = new BobThread(s, Alice.p, gPowYModp, y);
            bobThread.start();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
