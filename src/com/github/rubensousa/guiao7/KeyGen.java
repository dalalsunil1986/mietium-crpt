package com.github.rubensousa.guiao7;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class KeyGen {

    public static final String PUBLIC_KEY = "public.key";
    public static final String PRIVATE_KEY = "private.key";

    public static void main(String args[]) {

        File publicKeyFile = new File(PUBLIC_KEY);
        File privateKeyFile = new File(PRIVATE_KEY);

        KeyPairGenerator kpg;
        FileOutputStream fileOutputStream = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            kpg.initialize(2048, random);
            KeyPair keyPair = kpg.genKeyPair();

            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            fileOutputStream = new FileOutputStream(publicKeyFile);
            fileOutputStream.write(publicKey);
            fileOutputStream.flush();
            fileOutputStream.close();

            fileOutputStream = new FileOutputStream(privateKeyFile);
            fileOutputStream.write(privateKey);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


    }
}
