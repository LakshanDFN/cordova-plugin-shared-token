
package com.directfn.sharedtoken;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

public class SharedTokenProvider extends ContentProvider {

    public static final String METHOD_GET_TOKEN = "getAMToken";

    public static final String KEY_CONTRACT_VERSION =
        "contractVersion";

    public static final String KEY_STATUS = "status";

    public static final String KEY_TOKEN = "AMToken";

    public static final String STATUS_SUCCESS = "SUCCESS";

    public static final String STATUS_TOKEN_NOT_FOUND =
        "TOKEN_NOT_FOUND";

    public static final String STATUS_ERROR = "ERROR";

    private static final int CONTRACT_VERSION = 1;

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(
        String method,
        String arg,
        Bundle extras
    ) {

        if (!METHOD_GET_TOKEN.equals(method)) {
            throw new IllegalArgumentException(
                "Unsupported provider operation"
            );
        }

        Context context = getContext();

        if (context == null) {
            return createResponse(STATUS_ERROR, null);
        }

        // Verify the calling application before accessing token storage.
        if (!TokenSecurity.isAuthorizedCaller(context)) {
            throw new SecurityException(
                "Unauthorized application"
            );
        }

        try {

            String token = SharedTokenStorage.get(context);

            if (token == null || token.trim().isEmpty()) {
                return createResponse(
                    STATUS_TOKEN_NOT_FOUND,
                    null
                );
            }

            return createResponse(
                STATUS_SUCCESS,
                token
            );

        } catch (Exception e) {

            // Do not expose internal exception details or token data.
            return createResponse(
                STATUS_ERROR,
                null
            );
        }
    }

    private Bundle createResponse(
        String status,
        String token
    ) {

        Bundle response = new Bundle();

        response.putInt(
            KEY_CONTRACT_VERSION,
            CONTRACT_VERSION
        );

        response.putString(KEY_STATUS, status);

        response.putString(KEY_TOKEN, token);

        return response;
    }

    // This provider exposes only the call() API.
    // Database-style operations are intentionally disabled.

    @Override
    public Cursor query(
        Uri uri,
        String[] projection,
        String selection,
        String[] selectionArgs,
        String sortOrder
    ) {
        throw new UnsupportedOperationException(
            "Query operation is not supported"
        );
    }

    @Override
    public String getType(Uri uri) {
        throw new UnsupportedOperationException(
            "MIME type operation is not supported"
        );
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException(
            "Insert operation is not supported"
        );
    }

    @Override
    public int delete(
        Uri uri,
        String selection,
        String[] selectionArgs
    ) {
        throw new UnsupportedOperationException(
            "Delete operation is not supported"
        );
    }

    @Override
    public int update(
        Uri uri,
        ContentValues values,
        String selection,
        String[] selectionArgs
    ) {
        throw new UnsupportedOperationException(
            "Update operation is not supported"
        );
    }
}
