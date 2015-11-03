package com.github.rubensousa.guiao4;

import java.net.*;
import java.io.*;

public class TServidor extends Thread {
    private int ct;
    protected Socket s;

    public TServidor(Socket s, int c) {
        ct = c;
        this.s = s;
    }

    public void run() {
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            CipherUtils cipherUtils = new CipherUtils(ois, oos);
            try {
                while (true) {
                    System.out.println(ct + " : " + cipherUtils.readAndDecrypt());
                }
            } catch (EOFException e) {
                System.out.println("[" + ct + "]");
            } catch (IOException e) {
                System.out.println(e.getMessage());
            } finally {
                ois.close();
                oos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
