package com.github.rubensousa.guiao8;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;


public class Alice {

    public static int PORT = 6558;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidParameterSpecException {

        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParamSpec = params.getParameterSpec(DHParameterSpec.class);
        int tcount = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                AliceThread aliceThread = new AliceThread(socket, tcount, dhParamSpec);
                aliceThread.start();

                tcount++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
