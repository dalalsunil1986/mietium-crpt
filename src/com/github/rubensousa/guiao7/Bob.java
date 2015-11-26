package com.github.rubensousa.guiao7;


import java.net.Socket;

public class Bob {

    public static void main(String[] args) {

        try {
            Socket s = new Socket("localhost", Alice.PORT);
            BobThread bobThread = new BobThread(s);
            bobThread.start();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
