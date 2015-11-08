package com.stylingandroid.authentication.key;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.ArrayMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
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
        } catch (Exception e) {
            throw new KeyToolsException("Error creating user authentication cipher", e);
        }
    }

    private Cipher getCipher(String keyName) throws KeyToolsException, KeyPermanentlyInvalidatedException, UserNotAuthenticatedException,
            IllegalStateException {
        try {
            if (!keyStore.isKeyEntry(keyName)) {
                createKey(keyName);
            }
            SecretKey secretKey = (SecretKey) keyStore.getKey(keyName, null);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;
        } catch (KeyPermanentlyInvalidatedException | UserNotAuthenticatedException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyToolsException("Error creating cipher for " + keyName, e);
        }
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
