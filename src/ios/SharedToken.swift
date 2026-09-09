import Foundation
import Security

@objc(SharedToken)
class SharedToken: CDVPlugin {

    // -------------------------------------------------------
    // Shared Keychain configuration
    // -------------------------------------------------------

    private let service = "com.dfn.shared.amtoken"

    private let account = "AMToken"

    // IMPORTANT:
    // Replace this with your actual Keychain Access Group.
    //
    // Example:
    // ABCDE12345.com.company.shared
    //
    // ABCDE12345 = Apple Team ID / App Identifier Prefix
    //
    //private let accessGroup = "Y4Z85796NV.com.dfn.shared"
	private let accessGroup = "C98R689E4K.com.dfn.shared"


    // =======================================================
    // STORE TOKEN
    // =======================================================

    @objc(storeToken:)
    func storeToken(command: CDVInvokedUrlCommand) {

        guard let token = command.argument(at: 0) as? String,
              let tokenData = token.data(using: .utf8) else {

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs: "Invalid token"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )

            return
        }


        // Query used to identify the Keychain item
        let query: [String: Any] = [

            kSecClass as String:
                kSecClassGenericPassword,

            kSecAttrService as String:
                service,

            kSecAttrAccount as String:
                account,

            kSecAttrAccessGroup as String:
                accessGroup
        ]


        // Delete existing token if one already exists
        SecItemDelete(query as CFDictionary)


        // Create new Keychain item
        var attributes = query

        attributes[kSecValueData as String] =
            tokenData

        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly


        let status = SecItemAdd(
            attributes as CFDictionary,
            nil
        )


        if status == errSecSuccess {

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: "Token stored successfully"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )

        } else {

            let errorMessage =
                SecCopyErrorMessageString(status, nil)
                as String? ?? "Unknown Keychain error"

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs:
                    "Failed to store token. OSStatus: \(status) - \(errorMessage)"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )
        }
    }


    // =======================================================
    // GET TOKEN
    // =======================================================

    @objc(getToken:)
    func getToken(command: CDVInvokedUrlCommand) {

        let query: [String: Any] = [

            kSecClass as String:
                kSecClassGenericPassword,

            kSecAttrService as String:
                service,

            kSecAttrAccount as String:
                account,

            kSecAttrAccessGroup as String:
                accessGroup,

            kSecReturnData as String:
                true,

            kSecMatchLimit as String:
                kSecMatchLimitOne
        ]


        var item: CFTypeRef?


        let status = SecItemCopyMatching(
            query as CFDictionary,
            &item
        )


        if status == errSecSuccess,
           let tokenData = item as? Data,
           let token = String(
                data: tokenData,
                encoding: .utf8
           ) {

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: token
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )

        } else {

            let errorMessage =
                SecCopyErrorMessageString(status, nil)
                as String? ?? "Unknown Keychain error"

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs:
                    "Failed to retrieve token. OSStatus: \(status) - \(errorMessage)"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )
        }
    }


    // =======================================================
    // DELETE TOKEN
    // =======================================================

    @objc(deleteToken:)
    func deleteToken(command: CDVInvokedUrlCommand) {

        let query: [String: Any] = [

            kSecClass as String:
                kSecClassGenericPassword,

            kSecAttrService as String:
                service,

            kSecAttrAccount as String:
                account,

            kSecAttrAccessGroup as String:
                accessGroup
        ]


        let status = SecItemDelete(
            query as CFDictionary
        )


        if status == errSecSuccess ||
           status == errSecItemNotFound {

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_OK,
                messageAs: "Token deleted successfully"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )

        } else {

            let errorMessage =
                SecCopyErrorMessageString(status, nil)
                as String? ?? "Unknown Keychain error"

            let pluginResult = CDVPluginResult(
                status: CDVCommandStatus_ERROR,
                messageAs:
                    "Failed to delete token. OSStatus: \(status) - \(errorMessage)"
            )

            self.commandDelegate.send(
                pluginResult,
                callbackId: command.callbackId
            )
        }
    }
}