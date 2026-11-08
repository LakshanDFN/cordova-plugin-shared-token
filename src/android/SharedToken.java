
package com.directfn.sharedtoken;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SharedToken extends CordovaPlugin {

    private static final String META_OSS_AUTHORITY =
        "com.directfn.sharedtoken.OSS_PROVIDER_AUTHORITY";

    private static final String META_OSS_PACKAGE =
        "com.directfn.sharedtoken.OSS_PACKAGE_ID";

    private static final String META_OSS_CERT =
        "com.directfn.sharedtoken.OSS_CERT_SHA256";

    private static final String OSS_PERMISSION_SUFFIX =
        ".sharedtoken.permission.ACCESS";

    private static final String META_OSS_PERMISSION =
    "com.directfn.sharedtoken.OSS_PERMISSION";
	
	private static final String METHOD_GET_TOKEN = "getAMToken";

    private static final String KEY_STATUS = "status";
    private static final String KEY_TOKEN = "AMToken";
    private static final String KEY_VERSION = "contractVersion";

    private static final String STATUS_SUCCESS = "SUCCESS";
    private static final String STATUS_NOT_FOUND = "TOKEN_NOT_FOUND";

    private static final int CONTRACT_VERSION = 1;

    private final ExecutorService executor =
        Executors.newSingleThreadExecutor();

    @Override
    public boolean execute(
        String action,
        JSONArray args,
        CallbackContext callbackContext
    ) throws JSONException {

        switch (action) {

            case "storeToken":
                storeToken(args, callbackContext);
                return true;

            case "getToken":
                getToken(callbackContext);
                return true;

            case "deleteToken":
                deleteToken(callbackContext);
                return true;

            default:
                return false;
        }
    }

    private void storeToken(
        JSONArray args,
        CallbackContext callbackContext
    ) {

        final String token = args.optString(0, null);

        if (token == null || token.trim().isEmpty()) {
            callbackContext.error("AMToken cannot be empty");
            return;
        }

        executor.execute(() -> {

            try {

                Context context = cordova.getActivity();

                SharedTokenStorage.store(context, token);

                callbackContext.success("SUCCESS");

            } catch (Exception e) {

                callbackContext.error(
                    "Unable to store AMToken"
                );
            }
        });
    }

    private void getToken(CallbackContext callbackContext) {

        executor.execute(() -> {

            try {

                Context context = cordova.getActivity();

                PackageManager packageManager =
                    context.getPackageManager();

                PackageInfo appInfo =
                    packageManager.getPackageInfo(
                        context.getPackageName(),
                        PackageManager.GET_META_DATA
                    );

                Bundle metadata = appInfo.applicationInfo.metaData;

                if (metadata == null) {
                    callbackContext.error(
                        "OSS configuration is missing"
                    );
                    return;
                }

                String authority =
                    metadata.getString(META_OSS_AUTHORITY);

                String ossPackage =
                    metadata.getString(META_OSS_PACKAGE);

                String expectedCertificate =
                    metadata.getString(META_OSS_CERT);

                if (isEmpty(authority) ||
                    isEmpty(ossPackage) ||
					isEmpty(permission) ||
                    isEmpty(expectedCertificate) ||
                    "NOT_CONFIGURED".equals(expectedCertificate)) {

                    callbackContext.error(
                        "OSS provider configuration is incomplete"
                    );
                    return;
                }

                // Confirm that the configured authority belongs
                // to the expected OSS application.
                android.content.pm.ProviderInfo providerInfo =
                    packageManager.resolveContentProvider(
                        authority,
                        PackageManager.GET_META_DATA
                    );

                if (providerInfo == null ||
                    !ossPackage.equals(providerInfo.packageName)) {

                    callbackContext.error(
                        "OSS ContentProvider is unavailable"
                    );
                    return;
                }

                String permission =
					metadata.getString(META_OSS_PERMISSION);

                if (context.checkSelfPermission(permission)
                    != PackageManager.PERMISSION_GRANTED) {

                    callbackContext.error(
                        "OSS signature permission is not granted"
                    );
                    return;
                }

                // Verify the OSS provider's actual signing identity.
                if (!TokenSecurity.isTrustedPackage(
                    context,
                    ossPackage,
                    expectedCertificate
                )) {

                    callbackContext.error(
                        "OSS signing certificate validation failed"
                    );
                    return;
                }

                Uri providerUri = Uri.parse(
                    "content://" + authority
                );

                Bundle response =
                    context.getContentResolver().call(
                        providerUri,
                        METHOD_GET_TOKEN,
                        null,
                        null
                    );

                if (response == null) {
                    callbackContext.error(
                        "OSS provider returned an empty response"
                    );
                    return;
                }

                int version =
                    response.getInt(KEY_VERSION, -1);

                if (version != CONTRACT_VERSION) {
                    callbackContext.error(
                        "Unsupported OSS contract version"
                    );
                    return;
                }

                String status =
                    response.getString(KEY_STATUS);

                if (STATUS_SUCCESS.equals(status)) {

                    String token =
                        response.getString(KEY_TOKEN);

                    if (isEmpty(token)) {
                        callbackContext.error(
                            "OSS returned an empty AMToken"
                        );
                        return;
                    }

                    callbackContext.success(token);

                } else if (STATUS_NOT_FOUND.equals(status)) {

                    callbackContext.error(
                        STATUS_NOT_FOUND
                    );

                } else {

                    callbackContext.error(
                        "Unable to retrieve AMToken from OSS"
                    );
                }

            } catch (SecurityException e) {

                callbackContext.error(
                    "OSS provider access was denied"
                );

            } catch (Exception e) {

                callbackContext.error(
                    "Unable to communicate with OSS"
                );
            }
        });
    }

    private void deleteToken(CallbackContext callbackContext) {

        executor.execute(() -> {

            try {

                Context context = cordova.getActivity();

                SharedTokenStorage.delete(context);

                callbackContext.success("SUCCESS");

            } catch (Exception e) {

                callbackContext.error(
                    "Unable to delete AMToken"
                );
            }
        });
    }

    private boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    @Override
    public void onDestroy() {
        executor.shutdown();
        super.onDestroy();
    }
}
