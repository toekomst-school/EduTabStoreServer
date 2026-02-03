#!/usr/bin/env node
/**
 * PWA to APK Builder using @bubblewrap/core
 * This bypasses the interactive CLI and builds TWA APKs programmatically
 */

const path = require('path');
const fs = require('fs');

async function buildPwaApk(manifestUrl, outputDir, signingConfig) {
    // Dynamic import for ESM module
    const bubblewrap = await import('@bubblewrap/core');
    const { TwaManifest, TwaGenerator, GradleWrapper, AndroidSdkTools, Config, ConsoleLog } = bubblewrap;

    const JDK_PATH = process.env.JAVA_HOME || '/usr/lib/jvm/java-17-openjdk-amd64';
    const ANDROID_SDK_PATH = process.env.ANDROID_HOME || '/opt/android-sdk';

    console.log(`[pwa-builder] Starting build for ${manifestUrl}`);
    console.log(`[pwa-builder] Output dir: ${outputDir}`);
    console.log(`[pwa-builder] JDK: ${JDK_PATH}`);
    console.log(`[pwa-builder] Android SDK: ${ANDROID_SDK_PATH}`);

    try {
        // Create config
        const config = new Config(JDK_PATH, ANDROID_SDK_PATH);
        const log = new ConsoleLog('pwa-builder');

        // Fetch and create TWA manifest
        console.log('[pwa-builder] Fetching manifest...');
        const twaManifest = await TwaManifest.fromWebManifestUrl(manifestUrl);

        console.log(`[pwa-builder] App name: ${twaManifest.name}`);
        console.log(`[pwa-builder] Package: ${twaManifest.packageId}`);

        // Update signing key config if provided
        if (signingConfig) {
            twaManifest.signingKey = {
                path: signingConfig.path,
                alias: signingConfig.alias
            };
        }

        // Ensure output directory exists
        fs.mkdirSync(outputDir, { recursive: true });

        // Generate the Android project
        console.log('[pwa-builder] Generating Android project...');
        const twaGenerator = new TwaGenerator();
        await twaGenerator.createTwaProject(outputDir, twaManifest, log);

        console.log('[pwa-builder] Android project created');

        // Build the APK using Gradle
        console.log('[pwa-builder] Building APK with Gradle...');
        const gradleWrapper = new GradleWrapper(process, outputDir);

        await gradleWrapper.assembleRelease();

        console.log('[pwa-builder] Gradle build complete');

        // Find the generated APK
        const possiblePaths = [
            path.join(outputDir, 'app', 'build', 'outputs', 'apk', 'release', 'app-release-unsigned.apk'),
            path.join(outputDir, 'app', 'build', 'outputs', 'apk', 'release', 'app-release.apk'),
            path.join(outputDir, 'app-release-unsigned.apk'),
            path.join(outputDir, 'app-release.apk'),
        ];

        let apkPath = null;
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                apkPath = p;
                break;
            }
        }

        if (!apkPath) {
            // List what was created
            const listDir = (dir) => {
                try {
                    return fs.readdirSync(dir);
                } catch {
                    return [];
                }
            };
            console.log('[pwa-builder] Output dir contents:', listDir(outputDir));
            console.log('[pwa-builder] App dir contents:', listDir(path.join(outputDir, 'app')));
            return { success: false, error: 'APK file not found after build' };
        }

        // Sign the APK if signing config provided
        if (signingConfig && apkPath.includes('unsigned')) {
            console.log('[pwa-builder] Signing APK...');
            const signedApkPath = path.join(outputDir, 'app-release-signed.apk');
            const androidSdk = new AndroidSdkTools(process, config, log);

            await androidSdk.apksigner(
                apkPath,
                signedApkPath,
                signingConfig.path,
                signingConfig.alias,
                signingConfig.password,
                signingConfig.password
            );

            console.log(`[pwa-builder] Signed APK: ${signedApkPath}`);
            return { success: true, apkPath: signedApkPath, packageId: twaManifest.packageId };
        }

        console.log(`[pwa-builder] APK: ${apkPath}`);
        return { success: true, apkPath: apkPath, packageId: twaManifest.packageId };

    } catch (error) {
        console.error('[pwa-builder] Build error:', error);
        return { success: false, error: error.message || String(error) };
    }
}

// CLI interface
async function main() {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        console.log('Usage: pwa-builder.js <manifest-url> <output-dir> [keystore-path] [key-alias] [key-password]');
        process.exit(1);
    }

    const manifestUrl = args[0];
    const outputDir = args[1];
    const signingConfig = args.length >= 5 ? {
        path: args[2],
        alias: args[3],
        password: args[4]
    } : null;

    const result = await buildPwaApk(manifestUrl, outputDir, signingConfig);
    console.log(JSON.stringify(result));
    process.exit(result.success ? 0 : 1);
}

main().catch(err => {
    console.error(JSON.stringify({ success: false, error: err.message }));
    process.exit(1);
});
