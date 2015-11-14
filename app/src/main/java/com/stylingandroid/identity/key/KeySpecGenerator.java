package com.stylingandroid.identity.key;

import android.security.keystore.KeyGenParameterSpec;

interface KeySpecGenerator {
    KeyGenParameterSpec generate(String keyName);
}
