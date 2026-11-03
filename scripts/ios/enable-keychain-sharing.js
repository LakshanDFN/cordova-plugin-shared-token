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
            '[SharedToken] iOS platform directory not found. Skipping configuration.'
        );

        return;
    }

    /*
     * Find the Xcode project.
     */
    var projectDirectories = fs.readdirSync(iosPath)
        .filter(function (item) {
            return item.endsWith('.xcodeproj');
        });

    if (projectDirectories.length === 0) {
        throw new Error(
            '[SharedToken] Could not find Xcode project under platforms/ios.'
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
         * =====================================================
         * 1. Find DEVELOPMENT_TEAM
         * =====================================================
         *
         * Example:
         *
         * DEVELOPMENT_TEAM = C98R689E4K;
         */

        var projectContent = fs.readFileSync(
            xcodeProjectPath,
            'utf8'
        );

        var teamIdMatch = projectContent.match(
            /DEVELOPMENT_TEAM\s*=\s*([A-Z0-9]+)\s*;/
        );

        if (!teamIdMatch) {
            throw new Error(
                '[SharedToken] DEVELOPMENT_TEAM was not found in the Xcode project.'
            );
        }

        var teamId = teamIdMatch[1];

        console.log(
            '[SharedToken] Detected Apple Team ID: ' + teamId
        );


        /*
         * =====================================================
         * 2. Generate SharedTokenConfig.swift
         * =====================================================
         */

        var configDirectory = path.join(
            iosPath,
            'SharedToken'
        );

        if (!fs.existsSync(configDirectory)) {
            fs.mkdirSync(configDirectory, {
                recursive: true
            });
        }

        var configFilePath = path.join(
            configDirectory,
            'SharedTokenConfig.swift'
        );

        var accessGroup =
            teamId + '.com.dfn.shared';

        var configContent =
            'import Foundation\n\n' +
            'struct SharedTokenConfig {\n' +
            '    static let accessGroup = "' +
            accessGroup +
            '"\n' +
            '}\n';

        fs.writeFileSync(
            configFilePath,
            configContent,
            'utf8'
        );

        console.log(
            '[SharedToken] Generated Keychain Access Group: ' +
            accessGroup
        );


        /*
         * =====================================================
         * 3. Add generated Swift file to Xcode project
         * =====================================================
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
         * Check whether SharedTokenConfig.swift is already
         * included in the Xcode project.
         */

        var sourceFileAlreadyExists =
            projectContent.indexOf(
                'SharedTokenConfig.swift'
            ) !== -1;

        if (!sourceFileAlreadyExists) {

            project.addSourceFile(
                'SharedToken/SharedTokenConfig.swift',
                {},
                target.uuid
            );

            console.log(
                '[SharedToken] Added SharedTokenConfig.swift to Xcode project.'
            );
        }


        /*
         * =====================================================
         * 4. Enable Keychain Sharing capability
         * =====================================================
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

        console.log(
            '[SharedToken] Keychain Sharing capability enabled.'
        );


        /*
         * =====================================================
         * 5. Write modified Xcode project
         * =====================================================
         */

        fs.writeFileSync(
            xcodeProjectPath,
            project.writeSync(),
            'utf8'
        );

        console.log(
            '[SharedToken] iOS configuration completed successfully.'
        );
    });
};