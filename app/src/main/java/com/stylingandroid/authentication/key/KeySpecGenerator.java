package com.stylingandroid.authentication.key;

import android.security.keystore.KeyGenParameterSpec;

interface KeySpecGenerator {
    KeyGenParameterSpec generate(String keyName);
}
