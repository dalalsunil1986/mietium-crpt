package com.github.rubensousa.guiao4;

import java.net.*;

public class Servidor {

    public static int PORT = 4568;
    static private int tcount;

    static public void main(String[] args) {
        tcount = 0;
        try {
            ServerSocket ss = new ServerSocket(PORT);

            while (true) {
                Socket s = ss.accept();
                tcount++;
                TServidor ts = new TServidor(s, tcount);
                ts.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
