package com.github.rubensousa.guiao8;


import sun.security.x509.X500Name;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;


public class AliceThread extends Thread {

    private int ct;
    private Socket mSocket;
    private PrivateKey mCertPrivateKey;
    private Certificate mCertificateCA;
    private CertPath mCertificate;
    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgreement;

    public AliceThread(Socket socket, int ct, DHParameterSpec dhParameterSpec) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            KeyStoreException, UnrecoverableKeyException, InvalidAlgorithmParameterException,
            InvalidKeyException, CertificateException {
        mSocket = socket;
        this.ct = ct;

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("Servidor.p12"), "1234".toCharArray());
        mCertPrivateKey = (PrivateKey) keyStore.getKey("Servidor", "1234".toCharArray());

        // Criar gerador de par de chaves
        KeyPairGenerator aliceKeyPairGen = KeyPairGenerator.getInstance("DH");
        aliceKeyPairGen.initialize(dhParameterSpec);

        // Gerar par de chaves pública e privada
        mKeyPair = aliceKeyPairGen.generateKeyPair();

        // Criar e inicializar acordo de chaves
        mKeyAgreement = KeyAgreement.getInstance("DH");
        mKeyAgreement.init(mKeyPair.getPrivate());

        Certificate[] certArray = keyStore.getCertificateChain("Servidor");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        mCertificate = certFactory.generateCertPath(Arrays.asList(certArray));
        mCertificateCA = certFactory.generateCertificate(new FileInputStream("CA.cer"));
    }

    @Override
    public void run() {
        ObjectInputStream ois = null;
        ObjectOutputStream oos = null;

        try {
            ois = new ObjectInputStream(mSocket.getInputStream());
            oos = new ObjectOutputStream(mSocket.getOutputStream());

            // Enviar a chave pública ao Bob
            oos.writeObject(mKeyPair.getPublic());
            oos.flush();

            // Recever a chave pública do Bob
            PublicKey bobPublicKey = (PublicKey) ois.readObject();

            // Gerar chave privada
            mKeyAgreement.doPhase(bobPublicKey, true);
            byte[] secret = mKeyAgreement.generateSecret();

            // Receber assinatura do Bob
            byte[] sign = (byte[]) ois.readObject();

            // Receber certificado do Bob
            CertPath bobCert = (CertPath) ois.readObject();

            // Validar certificado do Bob
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            TrustAnchor anchor = new TrustAnchor((X509Certificate) mCertificateCA, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            try {
                cpv.validate(bobCert, params);
            } catch (InvalidAlgorithmParameterException iape) {
                System.err.println("Erro de validação: " + iape);
                System.exit(1);
            } catch (CertPathValidatorException cpve) {
                System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
                System.err.println("Posição do certificado causador do erro: "
                        + cpve.getIndex());
                System.exit(1);
            }

            // Verificar assinatura do Bob
            Signature signature = Signature.getInstance("SHA256withRSA");
            X509Certificate certificate = (X509Certificate) bobCert.getCertificates().get(0);
            X500Name x500Name = new X500Name(certificate.getSubjectX500Principal().getName());

            signature.initVerify(certificate.getPublicKey());
            signature.update(mKeyPair.getPublic().getEncoded());
            signature.update(bobPublicKey.getEncoded());

            if (!signature.verify(sign)) {
                System.out.println("Assinatura inválida");
                System.exit(1);
            }

            // Certificado válido, enviar assinatura
            signature.initSign(mCertPrivateKey);
            signature.update(mKeyPair.getPublic().getEncoded());
            signature.update(bobPublicKey.getEncoded());
            oos.writeObject(signature.sign());
            oos.flush();

            // Enviar certificado
            oos.writeObject(mCertificate);
            oos.flush();

            CipherUtils cipherUtils = new CipherUtils(ois, oos, secret);

            while (true) {
                System.out.println(ct + " : " + cipherUtils.readAndDecrypt());
            }

        } catch (EOFException e) {
            System.out.println("[" + ct + "]");
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
