var exec = require("cordova/exec");

var SharedToken = {

    storeToken: function (token, successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            "SharedToken",
            "storeToken",
            [token]
        );
    },

    getToken: function (successCallback, errorCallback) {
        exec(
            successCallback,
            errorCallback,
            "SharedToken",
            "getToken",
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