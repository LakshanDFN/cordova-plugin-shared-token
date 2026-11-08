
package com.directfn.sharedtoken;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Binder;

import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

public final class TokenSecurity {

    private static final String META_PACKAGE =
        "com.directfn.sharedtoken.OSS_PACKAGE_ID";

    private static final String META_CERTIFICATES =
        "com.directfn.sharedtoken.OSS_CERT_SHA256";

    private static final String PERMISSION_SUFFIX =
        ".sharedtoken.permission.ACCESS";

    private TokenSecurity() {
    }

    public static boolean isAuthorizedCaller(Context context) {

        try {
            int callingUid = Binder.getCallingUid();

            // Never trust a package name supplied by the caller.
            String[] packages =
                context.getPackageManager()
                    .getPackagesForUid(callingUid);

            if (packages == null || packages.length == 0) {
                return false;
            }

            // Read the expected OSS identity from DFN manifest metadata.
            android.content.pm.ApplicationInfo appInfo =
                context.getPackageManager().getApplicationInfo(
                    context.getPackageName(),
                    PackageManager.GET_META_DATA
                );

            android.os.Bundle metadata = appInfo.metaData;

            if (metadata == null) {
                return false;
            }

            String expectedPackage =
                metadata.getString(META_PACKAGE);

            String expectedCertificates =
                metadata.getString(META_CERTIFICATES);

            if (expectedPackage == null ||
                expectedPackage.trim().isEmpty() ||
                expectedCertificates == null ||
                expectedCertificates.trim().isEmpty()) {
                return false;
            }

            // Verify the caller's package identity.
            boolean packageMatched = false;

            for (String packageName : packages) {
                if (expectedPackage.equals(packageName)) {
                    packageMatched = true;
                    break;
                }
            }

            if (!packageMatched) {
                return false;
            }

            // Verify the signature-level permission.
            String permission =
                context.getPackageName() + PERMISSION_SUFFIX;

            if (context.checkCallingPermission(permission)
                    != PackageManager.PERMISSION_GRANTED) {
                return false;
            }

            // Verify the actual signing certificate.
			return isTrustedPackage(
				context,
				expectedPackage,
				expectedCertificates
			);

        } catch (Exception e) {
            // Fail closed.
            return false;
        }
    }

    private static boolean matchesAnyCertificate(
        Signature[] signatures,
        String expectedCertificates
    ) throws Exception {

        Set<String> allowedCertificates = new HashSet<>();

        for (String fingerprint : expectedCertificates.split(",")) {
            String normalized = normalize(fingerprint);

            if (!normalized.isEmpty()) {
                allowedCertificates.add(normalized);
            }
        }

        if (allowedCertificates.isEmpty()) {
            return false;
        }

        MessageDigest digest =
            MessageDigest.getInstance("SHA-256");

        for (Signature signature : signatures) {

            byte[] certificate = signature.toByteArray();

            byte[] hash = digest.digest(certificate);

            String actualFingerprint = toHex(hash);

            if (allowedCertificates.contains(actualFingerprint)) {
                return true;
            }
        }

        return false;
    }

    private static String normalize(String value) {

        if (value == null) {
            return "";
        }

        return value
            .replace(":", "")
            .replace(" ", "")
            .trim()
            .toUpperCase();
    }

    private static String toHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            result.append(
                String.format("%02X", b & 0xFF)
            );
        }

        return result.toString();
    }
	
	public static boolean isTrustedPackage(
		Context context,
		String packageName,
		String expectedCertificates
	) {

		try {

			if (packageName == null ||
				packageName.trim().isEmpty() ||
				expectedCertificates == null ||
				expectedCertificates.trim().isEmpty() ||
				"NOT_CONFIGURED".equals(expectedCertificates)) {
				return false;
			}

			PackageManager packageManager =
				context.getPackageManager();

			PackageInfo packageInfo;

			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

				packageInfo = packageManager.getPackageInfo(
					packageName,
					PackageManager.GET_SIGNING_CERTIFICATES
				);

				if (packageInfo.signingInfo == null) {
					return false;
				}

				Signature[] signatures =
					packageInfo.signingInfo.getApkContentsSigners();

				return signatures != null &&
					matchesAnyCertificate(
						signatures,
						expectedCertificates
					);

			} else {

				packageInfo = packageManager.getPackageInfo(
					packageName,
					PackageManager.GET_SIGNATURES
				);

				return packageInfo.signatures != null &&
					matchesAnyCertificate(
						packageInfo.signatures,
						expectedCertificates
					);
			}

		} catch (Exception e) {
			return false;
		}
	}
}
