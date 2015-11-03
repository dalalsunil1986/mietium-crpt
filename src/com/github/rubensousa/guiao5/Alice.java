package com.github.rubensousa.guiao5;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;


public class Alice {

    public static int PORT = 6558;
    public static final BigInteger p = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    public static final BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");

    public static void main(String[] args) {

        BigInteger x = new BigInteger(p.bitLength(), new SecureRandom());
        BigInteger gPowXModp = g.modPow(x, p);
        int tcount = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                AliceThread aliceThread = new AliceThread(socket, tcount, p, gPowXModp, x);
                aliceThread.start();
                tcount++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
