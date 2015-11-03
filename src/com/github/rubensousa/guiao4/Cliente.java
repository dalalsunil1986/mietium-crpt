package com.github.rubensousa.guiao4;

import java.net.*;
import java.io.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Cliente {

    public static void main(String[] args) {

        if (args.length == 1) {
            if (args[0].equals("-genkey")) {
                try {
                    CipherUtils.generateKey();
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
                        | IOException e) {
                    e.printStackTrace();
                }
                System.exit(0);
            } else {
                System.exit(-1);
            }
        }

        try {
            Socket s = new Socket("localhost", Servidor.PORT);

            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            CipherUtils cipherUtils = new CipherUtils(ois, oos);
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            while ((test = stdIn.readLine()) != null) {
                cipherUtils.encrypt(test);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
