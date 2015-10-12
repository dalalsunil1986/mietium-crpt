package com.github.rubensousa.guiao3;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class CipherUtils {

    /**
     * Tamanho da chave em bits
     */
    public static final int KEY_LENGTH = 128;

    /**
     *
     */
    public static final int BUFFER_SIZE = 1024 * 1024 * 10;

    /**
     * Cifra a ser usada
     */
    public static final String CIPHER = "AES";

    /**
     * Tipo de instância da cifra
     */
    public static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";

    /**
     * Nome da SecretKey da cifra a ser usada
     */
    public static final String CIPHER_SECRETKEY_ALIAS = "cipheralias";


    /**
     * Algoritmo MAC a ser usado
     */
    public static final String MAC_ALGORITHM = "HmacSHA256";

    /**
     * Tamanho do MAC em bytes
     */
    public static final int MAC_SIZE = 32;

    /**
     * Nome da SecretKey para o MAC
     */
    public static final String MAC_SECRETKEY_ALIAS = "macalias";


    /**
     * Modo da cifra
     */
    private int mCipherMode;

    private KeyStoreManager mKeyStoreManager;

    private File mInputFile;

    private File mOutputFile;

    public CipherUtils() throws KeyStoreException {
        mKeyStoreManager = new KeyStoreManager();
    }

    public CipherUtils(int cipherMode, String inputPath, String outputPath) throws KeyStoreException {

        if (cipherMode != Cipher.DECRYPT_MODE && cipherMode != Cipher.ENCRYPT_MODE) {
            throw new IllegalArgumentException("cipher mode must be Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE");
        }

        mCipherMode = cipherMode;
        mKeyStoreManager = new KeyStoreManager();
        mInputFile = new File(inputPath);
        mOutputFile = new File(outputPath);
    }

    public void generateKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER);
            keyGenerator.init(KEY_LENGTH);
            SecretKey secretKey = keyGenerator.generateKey();
            mKeyStoreManager.saveKey(secretKey, CIPHER_SECRETKEY_ALIAS);
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException e) {
            e.printStackTrace();
            System.exit(-1);
        }

    }

    public void startMode() throws KeyStoreException {

        FileOutputStream fileOutputStream = null;
        FileInputStream fileInputStream = null;

        try {
            fileInputStream = new FileInputStream(mInputFile);
            fileOutputStream = new FileOutputStream(mOutputFile);
            SecretKey secretKey = mKeyStoreManager.loadKey(CIPHER_SECRETKEY_ALIAS);

            byte[] keyEncoded = secretKey.getEncoded();

            // Criar instância da cifra
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            SecretKey secretKeyCipher = new SecretKeySpec(keyEncoded, CIPHER);

            // Inicia o modo de encriptar ou desencriptar
            if (mCipherMode == Cipher.ENCRYPT_MODE) {
                encrypt(cipher, secretKeyCipher, fileInputStream, fileOutputStream);
            } else {
                decrypt(cipher, secretKeyCipher, fileInputStream, fileOutputStream);
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | CertificateException | UnrecoverableEntryException
                | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            System.exit(-1);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        System.exit(0);
    }

    private void encrypt(Cipher cipher, SecretKey secretKeyCipher, FileInputStream fis, FileOutputStream fos)
            throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, KeyStoreException, IOException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {

        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeyCipher, new IvParameterSpec(iv));

        // Inicializar MAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance(MAC_ALGORITHM);
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Gerar chave para o MAC
        SecretKey macSecretKey = keyGenerator.generateKey();
        mac.init(macSecretKey);

        // Guardar chave do MAC
        mKeyStoreManager.saveKey(macSecretKey, MAC_SECRETKEY_ALIAS);
        mKeyStoreManager.closeKeyStore();

        byte[] data = new byte[BUFFER_SIZE];
        int bytes;

        //Escrever vetor de inicialização no ficheiro
        fos.write(iv);
        fos.flush();

        // Atualizar MAC com o vetor de inicialização
        mac.update(iv);

        // Ler do ficheiro, ir cifrando e guardando o resultado no ficheiro, enquanto atualiza o MAC
        while ((bytes = fis.read(data)) != -1) {
            byte[] ciphered = cipher.update(data, 0, bytes);
            mac.update(ciphered, 0, ciphered.length);
            fos.write(ciphered, 0, ciphered.length);
            fos.flush();
        }

        // Finalizar a cifra
        data = cipher.doFinal();
        fos.write(data, 0, data.length);
        fos.flush();

        // Finalizar cálculo do MAC e escrever no final do ficheiro
        mac.update(data, 0, data.length);
        data = mac.doFinal();
        fos.write(data, 0, data.length);
        fos.flush();
    }

    private void decrypt(Cipher cipher, SecretKey secretKeyCipher, FileInputStream fis, FileOutputStream fos)
            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
            UnrecoverableEntryException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        byte[] iv = new byte[cipher.getBlockSize()];

        // Ler vetor de inicialização
        if (fis.read(iv) != cipher.getBlockSize()) {
            throw new IOException("IV não encontrado");
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKeyCipher, new IvParameterSpec(iv));
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Carregar chave do MAC
        SecretKey macSecretKey = mKeyStoreManager.loadKey(MAC_SECRETKEY_ALIAS);
        mKeyStoreManager.closeKeyStore();
        mac.init(macSecretKey);

        // Calcular MAC do vetor de inicialização
        mac.update(iv);

        byte[] data = new byte[BUFFER_SIZE];
        int bytes;
        int totalBytes;

        RandomAccessFile randomAccessFile = new RandomAccessFile(mInputFile, "r");

        // Verificar se o tamanho do ficheiro bate certo, saltando bytes até à posição do MAC
        if (randomAccessFile.skipBytes((int) mInputFile.length() - MAC_SIZE) != mInputFile.length() - MAC_SIZE) {
            throw new IOException("MAC não encontrado");
        }

        byte[] macOriginal = new byte[MAC_SIZE];

        // Ler MAC do ficheiro
        if (randomAccessFile.read(macOriginal) != MAC_SIZE) {
            throw new IOException("MAC danificado");
        }

        // Colocar apontador no primeiro byte do criptograma
        randomAccessFile.seek(iv.length);
        totalBytes = iv.length;

        // Calcular o MAC a partir do criptograma atual
        while ((bytes = randomAccessFile.read(data)) != -1) {
            totalBytes += bytes;
            if (totalBytes >= mInputFile.length() - MAC_SIZE) {
                mac.update(data, 0, bytes - MAC_SIZE);
            } else {
                mac.update(data, 0, bytes);
            }
        }

        byte[] macCalculated = mac.doFinal();

        // Se os dois MAC baterem certo, desencriptar o ficheiro
        if (checkMac(macOriginal, macCalculated)) {

            totalBytes = iv.length;

            while ((bytes = fis.read(data)) != -1) {
                totalBytes += bytes;

                if (totalBytes >= mInputFile.length() - MAC_SIZE) {
                    fos.write(cipher.update(data, 0, bytes - MAC_SIZE));
                } else {
                    fos.write(cipher.update(data, 0, bytes));
                }

                fos.flush();
            }
            fos.write(cipher.doFinal());
            fos.flush();
        } else {
            System.out.println("O ficheiro foi modificado e não pode ser desencriptado");
            System.exit(-1);
        }
    }

    private boolean checkMac(byte[] original, byte[] generated) {
        if (original.length != generated.length) {
            return false;
        }

        for (int i = 0; i < MAC_SIZE; i++) {
            if (original[i] != generated[i]) {
                return false;
            }
        }

        return true;
    }

}
