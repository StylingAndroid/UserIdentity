package com.stylingandroid.authentication;

import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.StringRes;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import com.stylingandroid.authentication.key.KeyTools;
import com.stylingandroid.authentication.key.KeyTools.KeyToolsException;

import javax.crypto.Cipher;

public class BaseActivity extends AppCompatActivity {

    static final byte[] SECRET_BYTES = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    private View errorPanel;
    private TextView errorText;

    private KeyTools keyTools;

    @Override
    protected void onResume() {
        super.onResume();
        errorPanel = findViewById(R.id.error_panel);
        errorText = (TextView) findViewById(R.id.error_text);

        hideError();

        try {
            keyTools = KeyTools.newInstance();
        } catch (KeyToolsException e) {
            e.printStackTrace();
            showError(e.getMessage());
        }
    }

    protected void showError(@StringRes int stringId) {
        showError(getString(stringId));
    }

    protected void showError(CharSequence error) {
        errorText.setText(error);
        errorPanel.setVisibility(View.VISIBLE);
    }

    protected void hideError() {
        errorPanel.setVisibility(View.GONE);
    }

    public Cipher getUserAuthCipher() throws KeyToolsException {
        return keyTools.getUserAuthCipher();
    }

    public Cipher getTimedUserAuthCipher() throws KeyToolsException, UserNotAuthenticatedException, KeyPermanentlyInvalidatedException {
        return keyTools.getTimedUserAuthCipher();
    }
}
