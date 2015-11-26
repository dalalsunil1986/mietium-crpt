package com.github.rubensousa.guiao7;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;


public class Alice {

    public static int PORT = 6558;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidParameterSpecException {

        int tcount = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                AliceThread aliceThread = new AliceThread(socket, tcount);
                aliceThread.start();

                tcount++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }
}
