package com.stylingandroid.identity.key;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

class UserAuthKeySpecGenerator implements KeySpecGenerator {
    private final String blockMode;
    private final String padding;

    UserAuthKeySpecGenerator(String blockMode, String padding) {
        this.blockMode = blockMode;
        this.padding = padding;
    }

    @Override
    public KeyGenParameterSpec generate(String keyName) {
        return new KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setUserAuthenticationRequired(true)
                .build();
    }
}
