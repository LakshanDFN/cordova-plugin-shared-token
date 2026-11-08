package com.directfn.sharedtoken;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class SharedTokenStorage {

    private static final String PREFS_NAME =
        "shared_token_storage";

    private static final String KEY_ALIAS =
        "DFN_SHARED_TOKEN_KEY";

    private static final String TOKEN_KEY =
        "encrypted_token";

    private static final String IV_KEY =
        "token_iv";

    private static final String ANDROID_KEYSTORE =
        "AndroidKeyStore";

    private SharedTokenStorage() {
    }

    private static SecretKey getOrCreateKey() throws Exception {

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        }

        KeyGenerator generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        );

        generator.init(
            new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT |
                KeyProperties.PURPOSE_DECRYPT
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(
                KeyProperties.ENCRYPTION_PADDING_NONE
            )
            .setRandomizedEncryptionRequired(true)
            .build()
        );

        return generator.generateKey();
    }

    public static synchronized void store(
        Context context,
        String token
    ) throws Exception {

        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException(
                "AMToken cannot be empty"
            );
        }

        SecretKey key = getOrCreateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal(
            token.getBytes(StandardCharsets.UTF_8)
        );

        SharedPreferences preferences =
            context.getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            );

        preferences.edit()
            .putString(
                TOKEN_KEY,
                Base64.encodeToString(encrypted, Base64.NO_WRAP)
            )
            .putString(
                IV_KEY,
                Base64.encodeToString(
                    cipher.getIV(),
                    Base64.NO_WRAP
                )
            )
            .apply();
    }

    public static synchronized String get(
        Context context
    ) throws Exception {

        SharedPreferences preferences =
            context.getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            );

        String encryptedValue =
            preferences.getString(TOKEN_KEY, null);

        String ivValue =
            preferences.getString(IV_KEY, null);

        if (encryptedValue == null || ivValue == null) {
            return null;
        }

        byte[] encrypted = Base64.decode(
            encryptedValue,
            Base64.NO_WRAP
        );

        byte[] iv = Base64.decode(
            ivValue,
            Base64.NO_WRAP
        );

        SecretKey key = getOrCreateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            new GCMParameterSpec(128, iv)
        );

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(
            decrypted,
            StandardCharsets.UTF_8
        );
    }

    public static synchronized void delete(
        Context context
    ) throws Exception {

        SharedPreferences preferences =
            context.getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            );

        preferences.edit()
            .remove(TOKEN_KEY)
            .remove(IV_KEY)
            .apply();
    }
}
