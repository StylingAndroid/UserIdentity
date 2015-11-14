package com.stylingandroid.identity.key;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

class TimedUserAuthKeySpecGenerator implements KeySpecGenerator {
    private final String blockMode;
    private final String padding;
    private final int timeout;

    TimedUserAuthKeySpecGenerator(String blockMode, String padding, int timeout) {
        this.blockMode = blockMode;
        this.padding = padding;
        this.timeout = timeout;
    }

    @Override
    public KeyGenParameterSpec generate(String keyName) {
        return new KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(timeout)
                .build();
    }
}
