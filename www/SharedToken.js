var exec = require("cordova/exec");

function normalizeTokenDetails(value) {
    if (typeof value === "string") {
        try {
            return JSON.parse(value);
        } catch (e) {
            return value;
        }
    }
    return value;
}

var SharedToken = {

    /*
     * storeToken(token, issuedAt, successCallback, errorCallback)
     *
     * For backward compatibility, storeToken(token, success, error)
     * is also accepted. In that case the current time is recorded.
     *
     * issuedAt must be Unix epoch milliseconds. Prefer passing the
     * authentication/login timestamp supplied by the application/backend.
     */
    storeToken: function (token, issuedAt, successCallback, errorCallback) {

        if (typeof issuedAt === "function") {
            errorCallback = successCallback;
            successCallback = issuedAt;
            issuedAt = Date.now();
        }

        if (issuedAt === undefined || issuedAt === null) {
            issuedAt = Date.now();
        }

        issuedAt = Number(issuedAt);

        if (!isFinite(issuedAt) || issuedAt <= 0) {
            if (typeof errorCallback === "function") {
                errorCallback("issuedAt must be a valid Unix epoch timestamp in milliseconds");
            }
            return;
        }

        exec(
            successCallback,
            errorCallback,
            "SharedToken",
            "storeToken",
            [token, Math.floor(issuedAt)]
        );
    },

    // Retrieves only the token. Existing callers remain compatible.
    getToken: function (successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            "SharedToken",
            "getToken",
            []
        );
    },

    // Retrieves both the token and its original issuance/login timestamp.
    getTokenDetails: function (successCallback, errorCallback) {
        exec(
            function (result) {
                var details = normalizeTokenDetails(result);

                if (typeof successCallback === "function") {
                    successCallback(details);
                }
            },
            errorCallback,
            "SharedToken",
            "getTokenDetails",
            []
        );
    },

    deleteToken: function (successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            "SharedToken",
            "deleteToken",
            []
        );
    }
};

module.exports = SharedToken;
