package com.github.rubensousa.guiao8;


import sun.security.x509.X500Name;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;

public class BobThread extends Thread {


    private Socket mSocket;
    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgreement;
    private PrivateKey mCertPrivateKey;
    private Certificate mCertificateCA;
    private CertPath mCertificate;
    private DHParameterSpec mDhParameterSpec;

    public BobThread(Socket socket) throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException {
        mSocket = socket;

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("Cliente.p12"), "1234".toCharArray());
        mCertPrivateKey = (PrivateKey) keyStore.getKey("Cliente1", "1234".toCharArray());

        Certificate[] certArray = keyStore.getCertificateChain("Cliente1");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        mCertificate = certFactory.generateCertPath(Arrays.asList(certArray));
        mCertificateCA = certFactory.generateCertificate(new FileInputStream("CA.cer"));
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(mSocket.getOutputStream());
            ois = new ObjectInputStream(mSocket.getInputStream());

            // Receber chave pública da Alice
            PublicKey alicePublicKey = (PublicKey) ois.readObject();

            // Criar parâmetros do DH a partir da chave da Alice
            mDhParameterSpec = ((DHPublicKey) alicePublicKey).getParams();

            // Criar gerador de par de chaves
            KeyPairGenerator bobKeyPairGen = KeyPairGenerator.getInstance("DH");
            bobKeyPairGen.initialize(mDhParameterSpec);

            // Gerar par de chaves pública e privada
            mKeyPair = bobKeyPairGen.generateKeyPair();

            // Criar e inicializar acordo de chaves
            mKeyAgreement = KeyAgreement.getInstance("DH");
            mKeyAgreement.init(mKeyPair.getPrivate());

            // Enviar a chave pública do Bob
            oos.writeObject(mKeyPair.getPublic());
            oos.flush();

            // Gerar chave privada
            mKeyAgreement.doPhase(alicePublicKey, true);
            byte[] secret = mKeyAgreement.generateSecret();

            // Enviar assinatura do segredo
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(mCertPrivateKey);
            signature.update(alicePublicKey.getEncoded());
            signature.update(mKeyPair.getPublic().getEncoded());
            oos.writeObject(signature.sign());
            oos.flush();

            // Enviar certificado
            oos.writeObject(mCertificate);
            oos.flush();

            // Receber assinatura da Alice
            byte[] sign = (byte[]) ois.readObject();

            // Receber certificado da Alice
            CertPath aliceCert = (CertPath) ois.readObject();

            // Validar certificado da Alice
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor anchor = new TrustAnchor((X509Certificate) mCertificateCA, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            try {
                cpv.validate(aliceCert, params);
            } catch (InvalidAlgorithmParameterException iape) {
                System.err.println("Erro de validação: " + iape);
                System.exit(1);
            } catch (CertPathValidatorException cpve) {
                System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
                System.err.println("Posição do certificado causador do erro: "
                        + cpve.getIndex());
                System.exit(1);
            }

            // Verificar assinatura da Alice
            X509Certificate certificate = (X509Certificate) aliceCert.getCertificates().get(0);
            X500Name x500Name = new X500Name(certificate.getSubjectX500Principal().getName());

            if (!x500Name.getCommonName().equals("Servidor")) {
                System.out.println("Entidade não confiável");
            }

            signature.initVerify(certificate.getPublicKey());
            signature.update(alicePublicKey.getEncoded());
            signature.update(mKeyPair.getPublic().getEncoded());

            if (!signature.verify(sign)) {
                System.exit(1);
            }

            CipherUtils cipherUtils = new CipherUtils(ois, oos, secret);
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
