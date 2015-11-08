package com.stylingandroid.authentication;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.content.ContextCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat.CryptoObject;
import android.support.v4.os.CancellationSignal;

import com.stylingandroid.authentication.key.KeyTools.KeyToolsException;

import javax.crypto.Cipher;

public class FingerprintActivity extends BaseActivity {
    private static final int USE_FINGERPRINT_REQUEST_CODE = 0;

    private FingerprintManagerCompat fingerprintManager;
    private AuthenticationCallback authenticationCallback = new AuthenticationCallback();

    private CancellationSignal cancellationSignal = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fingerprintManager = FingerprintManagerCompat.from(this);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (!fingerprintManager.isHardwareDetected()) {
            showError(R.string.no_fingerprint_hardware);
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
            showError(R.string.no_fingerprints_enrolled);
        } else if (ContextCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            showError("Permission not granted");
        } else {
            authenticate();
        }
    }

    @Override
    protected void onPause() {
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
        }
        super.onPause();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == USE_FINGERPRINT_REQUEST_CODE && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            authenticate();
        }
    }

    private void authenticate() {
        Cipher cipher;
        try {
            cipher = getUserAuthCipher();
        } catch (KeyToolsException e) {
            showError(e.getMessage());
            return;
        }
        CryptoObject crypto = new CryptoObject(cipher);
        cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(crypto, 0, cancellationSignal, authenticationCallback, null);
    }

    private void validate(Cipher cipher) {
        if (tryEncrypt(cipher)) {
            startActivity(new Intent(this, SecureActivity.class));
        } else {
            showError(R.string.validation_error);
        }
    }

    private boolean tryEncrypt(Cipher cipher) {
        try {
            cipher.doFinal(SECRET_BYTES);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private class AuthenticationCallback extends FingerprintManagerCompat.AuthenticationCallback {
        @Override
        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
            validate(result.getCryptoObject().getCipher());
        }

        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            showError(errString);
        }

        @Override
        public void onAuthenticationFailed() {
            showError(R.string.authenication_failed);
        }
    }
}
