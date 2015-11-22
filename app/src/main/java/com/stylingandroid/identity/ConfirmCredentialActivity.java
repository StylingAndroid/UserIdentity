package com.stylingandroid.identity;

import android.app.KeyguardManager;
import android.content.Intent;
import android.os.Bundle;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;

import javax.crypto.Cipher;

public class ConfirmCredentialActivity extends BaseActivity {

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private KeyguardManager keyguardManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
    }

    @Override
    protected void onResume() {
        replaceContent(R.layout.activity_credential);
        super.onResume();

        try {
            Cipher cipher = getTimedUserAuthCipher();
            cipher.doFinal(SECRET_BYTES);
        } catch (UserNotAuthenticatedException e) {
            showAuthenticationScreen();
            return;
        } catch (KeyPermanentlyInvalidatedException e) {
            showError(R.string.key_permantently_invalid);
            return;
        } catch (IllegalStateException e) {
            showError(R.string.no_lockscreen);
            return;
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        replaceContent(R.layout.activity_user_identified);
    }

    private void showAuthenticationScreen() {
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }
}
