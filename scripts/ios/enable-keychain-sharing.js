'use strict';

var fs = require('fs');
var path = require('path');
var xcode = require('xcode');

module.exports = function (context) {

    var projectRoot = context.opts.projectRoot;

    var iosPath = path.join(
        projectRoot,
        'platforms',
        'ios'
    );

    if (!fs.existsSync(iosPath)) {
        console.log(
            '[SharedToken] iOS platform directory not found. Skipping Keychain Sharing configuration.'
        );

        return;
    }

    /*
     * Cordova normally creates:
     *
     * platforms/ios/App/App.xcodeproj/project.pbxproj
     *
     * But the project name can vary, so find the .xcodeproj dynamically.
     */

    var projectDirectories = fs.readdirSync(iosPath)
        .filter(function (item) {
            return item.endsWith('.xcodeproj');
        });

    if (projectDirectories.length === 0) {
        throw new Error(
            '[SharedToken] Could not find an Xcode project under platforms/ios.'
        );
    }

    var xcodeProjectPath = path.join(
        iosPath,
        projectDirectories[0],
        'project.pbxproj'
    );

    console.log(
        '[SharedToken] Updating Xcode project: ' +
        xcodeProjectPath
    );

    var project = xcode.project(xcodeProjectPath);

    project.parse(function (error) {

        if (error) {
            throw error;
        }

        /*
         * Find the main application target.
         */
        var target = project.getTarget(
            'com.apple.product-type.application'
        );

        if (!target || !target.target) {
            throw new Error(
                '[SharedToken] Could not find the main iOS application target.'
            );
        }

        /*
         * This is the equivalent of:
         *
         * Xcode
         *   → Signing & Capabilities
         *   → Keychain Sharing
         *
         * The capability is represented in project.pbxproj as:
         *
         * SystemCapabilities = {
         *     com.apple.KeychainSharing = {
         *         enabled = 1;
         *     };
         * };
         */

        var capabilities = {
            'com.apple.KeychainSharing': {
                enabled: 1
            }
        };

        project.addTargetAttribute(
            'SystemCapabilities',
            capabilities,
            target
        );

        fs.writeFileSync(
            xcodeProjectPath,
            project.writeSync(),
            'utf8'
        );

        console.log(
            '[SharedToken] Keychain Sharing capability enabled successfully.'
        );

    });
};