package com.stylingandroid.identity.key;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.ArrayMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Collections;
import java.util.Map;

public final class KeyTools {

    private static final String PROVIDER_NAME = "AndroidKeyStore";
    private static final String USER_AUTH_KEY_NAME = "com.stylingandroid.fingerprint.USER_AUTH_KEY";

    private static final String ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC;
    private static final String PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7;
    private static final String TRANSFORMATION = ALGORITHM + "/" + BLOCK_MODE + "/" + PADDING;

    private final KeyStore keyStore;
    private final Map<String, KeySpecGenerator> generators;

    public static KeyTools newInstance() throws KeyToolsException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(PROVIDER_NAME);
            keyStore.load(null);
        } catch (Exception e) {
            throw new KeyToolsException("Error initializing keystore: ", e);
        }
        Map<String, KeySpecGenerator> generators = new ArrayMap<>();
        generators.put(USER_AUTH_KEY_NAME, new UserAuthKeySpecGenerator(BLOCK_MODE, PADDING));
        return new KeyTools(keyStore, Collections.unmodifiableMap(generators));
    }

    private KeyTools(KeyStore keyStore, Map<String, KeySpecGenerator> generators) {
        this.keyStore = keyStore;
        this.generators = generators;
    }

    public Cipher getUserAuthCipher() throws KeyToolsException {
        try {
            return getCipher(USER_AUTH_KEY_NAME);
        } catch (KeyPermanentlyInvalidatedException e) {
            /*
             * The invalid key has been removed from the keystore, so let's try and
             * generate a new one.
             */
            try {
                return getCipher(USER_AUTH_KEY_NAME);
            } catch (Exception e1) {
                throw new KeyToolsException("Error creating user authentication cipher", e1);
            }
        } catch (Exception e) {
            throw new KeyToolsException("Error creating user authentication cipher", e);
        }
    }

    private Cipher getCipher(String keyName) throws NoSuchPaddingException, KeyToolsException, NoSuchAlgorithmException,
            KeyStoreException, UnrecoverableKeyException, InvalidKeyException {
        SecretKey secretKey = getKey(keyName);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (KeyPermanentlyInvalidatedException e) {
            recreateKey(keyName);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        return cipher;
    }

    private SecretKey getKey(String keyName) throws KeyStoreException, KeyToolsException, UnrecoverableKeyException, NoSuchAlgorithmException {
        if (!keyStore.isKeyEntry(keyName)) {
            createKey(keyName);
        }
       return (SecretKey) keyStore.getKey(keyName, null);
    }

    private SecretKey recreateKey(String keyName) throws KeyStoreException, KeyToolsException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keyStore.isKeyEntry(keyName)) {
            keyStore.deleteEntry(keyName);
        }
        return getKey(keyName);
    }

    private void createKey(String keyName) throws KeyToolsException, IllegalStateException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER_NAME);
            KeyGenParameterSpec spec = getKeyGenParameterSpec(keyName);
            keyGenerator.init(spec);
            keyGenerator.generateKey();
        } catch (InvalidAlgorithmParameterException e) {
            if (e.getCause() instanceof IllegalStateException) {
                throw (IllegalStateException) e.getCause();
            }
            throw new KeyToolsException("Error creating key for " + keyName, e);
        } catch (Exception e) {
            throw new KeyToolsException("Error creating key for " + keyName, e);
        }
    }

    private KeyGenParameterSpec getKeyGenParameterSpec(String keyName) {
        return generators.get(keyName).generate(keyName);
    }

    public static class KeyToolsException extends Exception {
        public KeyToolsException(String detailMessage, Throwable throwable) {
            super(detailMessage, throwable);
        }
    }
}
