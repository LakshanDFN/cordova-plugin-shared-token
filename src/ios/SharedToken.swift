import Foundation
import Security

@objc(SharedToken)
class SharedToken: CDVPlugin {

    // Shared Keychain configuration. DFN and OSS must use the same values.
    private let service = "com.dfn.shared.amtoken"
    private let account = "AMToken"
    private let accessGroup = "C98R689E4K.com.dfn.shared"

    // Store issuedAt as Keychain metadata (kSecAttrGeneric), not as part
    // of the token value. This preserves compatibility with existing
    // applications that expect kSecReturnData to contain the raw AMToken.

    // =======================================================
    // STORE TOKEN + ISSUANCE/LOGIN TIMESTAMP
    // =======================================================

    @objc(storeToken:)
    func storeToken(command: CDVInvokedUrlCommand) {

        guard let token = command.argument(at: 0) as? String,
              !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let issuedAtNumber = command.argument(at: 1) as? NSNumber else {
            sendError("AMToken and issuedAt are required", command: command)
            return
        }

        let issuedAt = issuedAtNumber.int64Value

        guard issuedAt > 0 else {
            sendError("issuedAt must be a valid Unix epoch timestamp in milliseconds", command: command)
            return
        }

        guard let tokenData = token.data(using: .utf8),
              let issuedAtData = String(issuedAt).data(using: .utf8) else {
            sendError("Unable to encode token details", command: command)
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup
        ]

        // Replace the existing shared item.
        SecItemDelete(query as CFDictionary)

        var attributes = query
        attributes[kSecValueData as String] = tokenData
        attributes[kSecAttrGeneric as String] = issuedAtData
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)

        if status == errSecSuccess {
            sendSuccess("SUCCESS", command: command)
        } else {
            sendKeychainError("Failed to store token", status: status, command: command)
        }
    }

    // =======================================================
    // GET TOKEN (backward-compatible raw string result)
    // =======================================================

    @objc(getToken:)
    func getToken(command: CDVInvokedUrlCommand) {

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess,
              let tokenData = item as? Data,
              let token = String(data: tokenData, encoding: .utf8),
              !token.isEmpty else {
            sendKeychainError("Failed to retrieve token", status: status, command: command)
            return
        }

        sendSuccess(token, command: command)
    }

    // =======================================================
    // GET TOKEN DETAILS (raw token + issuedAt metadata)
    // =======================================================

    @objc(getTokenDetails:)
    func getTokenDetails(command: CDVInvokedUrlCommand) {

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess,
              let result = item as? [String: Any],
              let tokenData = result[kSecValueData as String] as? Data,
              let token = String(data: tokenData, encoding: .utf8),
              !token.isEmpty,
              let issuedAtData = result[kSecAttrGeneric as String] as? Data,
              let issuedAtString = String(data: issuedAtData, encoding: .utf8),
              let issuedAt = Int64(issuedAtString),
              issuedAt > 0 else {
            if status == errSecSuccess {
                sendError(
                    "Stored token does not contain valid issuedAt metadata; re-authentication is required",
                    command: command
                )
            } else {
                sendKeychainError("Failed to retrieve token details", status: status, command: command)
            }
            return
        }

        let details: [String: Any] = [
            "AMToken": token,
            "issuedAt": issuedAt
        ]

        do {
            let jsonData = try JSONSerialization.data(
                withJSONObject: details,
                options: []
            )
            let jsonString = String(data: jsonData, encoding: .utf8) ?? "{}"
            sendSuccess(jsonString, command: command)
        } catch {
            sendError("Unable to serialize token details", command: command)
        }
    }

    // =======================================================
    // DELETE TOKEN
    // =======================================================

    @objc(deleteToken:)
    func deleteToken(command: CDVInvokedUrlCommand) {

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status == errSecSuccess || status == errSecItemNotFound {
            sendSuccess("SUCCESS", command: command)
        } else {
            sendKeychainError("Failed to delete token", status: status, command: command)
        }
    }

    // =======================================================
    // CORDOVA CALLBACK HELPERS
    // =======================================================

    private func sendSuccess(_ message: String, command: CDVInvokedUrlCommand) {
        let result = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: message
        )
        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func sendError(_ message: String, command: CDVInvokedUrlCommand) {
        let result = CDVPluginResult(
            status: CDVCommandStatus_ERROR,
            messageAs: message
        )
        commandDelegate.send(result, callbackId: command.callbackId)
    }

    private func sendKeychainError(
        _ prefix: String,
        status: OSStatus,
        command: CDVInvokedUrlCommand
    ) {
        let detail = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown Keychain error"
        sendError("\(prefix). OSStatus: \(status) - \(detail)", command: command)
    }
}
