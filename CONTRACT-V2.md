# Shared Token Contract – Version 2

Both DFN and OSS implementations must use the same contract.

## Android ContentProvider

Method: `getAMToken`

A successful `Bundle` contains:

| Key | Type | Required |
|---|---|---|
| `contractVersion` | Integer | Yes; value `2` |
| `status` | String | Yes; `SUCCESS` |
| `AMToken` | String | Yes |
| `issuedAt` | Long | Yes; Unix epoch milliseconds |

A token-not-found response contains `contractVersion=2` and
`status=TOKEN_NOT_FOUND`. An error response contains `contractVersion=2`
and `status=ERROR`. Token fields are omitted unless status is `SUCCESS`.

## Timestamp meaning

`issuedAt` is the login/session issuance time in Unix epoch milliseconds.
The originating application must capture it when the authentication session
is established and store it with the token. It must be preserved during
cross-application retrieval; the receiving application must not replace it
with the retrieval time. When a new login or token refresh creates a new
authentication session/token, update the timestamp according to the agreed
backend/session semantics.

If no backend-issued timestamp is available, both teams must agree that the
originating application records the login time. The timestamp is metadata
and does not replace backend token validation.

## JavaScript API

- `SharedToken.storeToken(token, issuedAt, success, error)`
- `SharedToken.getToken(success, error)` returns only the token (legacy API).
- `SharedToken.getTokenDetails(success, error)` returns `{ AMToken, issuedAt }`.
- `SharedToken.deleteToken(success, error)`

For compatibility, `storeToken(token, success, error)` is accepted and records
the current time. New integration code should pass the actual login timestamp.

## iOS Keychain item format

Both apps must use the same Keychain item identifiers:

- Access group: `YYQ695H283.com.dfn.shared`
- Service: `com.dfn.shared.amtoken`
- Account: `AMToken`

To preserve compatibility with existing applications that expect the Keychain
item's `kSecValueData` to contain the raw AMToken, store `issuedAt` as the
`kSecAttrGeneric` attribute of that same generic-password item. Encode the
timestamp as UTF-8 decimal epoch milliseconds. Do not replace the token value
with a JSON string.

The new `getTokenDetails()` method reads both the raw token and `kSecAttrGeneric`
timestamp and returns `{ "AMToken": "...", "issuedAt": 1794400000000 }`.

This format must be implemented identically by DFN and OSS.

## Migration note

Existing Android encrypted records and iOS raw Keychain records from the
previous POC do not contain a trustworthy `issuedAt`. They are not upgraded
by inventing a timestamp. A fresh login/store operation is required to write
the version 2 token payload.
