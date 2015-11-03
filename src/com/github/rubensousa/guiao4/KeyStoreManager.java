package com.github.rubensousa.guiao4;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class KeyStoreManager {

    /**
     * Tipo de KeyStore a ser usada
     */
    public static final String KEYSTORE_TYPE = "JCEKS";

    /**
     * Nome da KeyStore
     */
    public static final String KEYSTORE_ALIAS = "passphrase";


    private KeyStore mKeyStore;

    private FileInputStream mKeyStoreInputStream;

    private char[] mPassword;


    public KeyStoreManager() throws KeyStoreException {
        mKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
    }

    private char[] loadKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException {
        System.out.println("Introduza a senha de acesso à KeyStore:");
        char[] password = System.console().readPassword();

        try {
            mKeyStoreInputStream = new FileInputStream(KEYSTORE_ALIAS);
            mKeyStore.load(mKeyStoreInputStream, password);
        } catch (FileNotFoundException e) {
            mKeyStore.load(null, password);
            mKeyStore.load(mKeyStoreInputStream, password);
        }

        return password;
    }

    public void saveKey(SecretKey secretKey, String alias) throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException {

        if (mKeyStoreInputStream == null) {
            mPassword = loadKeyStore();
        }

        FileOutputStream keyStoreOutputStream = new FileOutputStream(KEYSTORE_ALIAS);
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(mPassword);

        // Criar entrada da chave
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        mKeyStore.setEntry(alias, skEntry, protParam);

        // Gravar chave
        mKeyStore.store(keyStoreOutputStream, mPassword);
    }

    public void closeKeyStore() throws IOException {
        mKeyStoreInputStream.close();
        mPassword = null;
    }

    /**
     * Carregar uma SecretKey guardada na KeyStore
     *
     * @return SecretKey guardada ou null se não foi encontrada
     */
    public SecretKey loadKey(String alias) throws IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {


        if (mKeyStoreInputStream == null) {
            mPassword = loadKeyStore();
        }

        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(mPassword);

        // Carregar entrada da chave
        KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry)
                mKeyStore.getEntry(alias, protParam);


        return skEntry == null ? null : skEntry.getSecretKey();
    }

}
