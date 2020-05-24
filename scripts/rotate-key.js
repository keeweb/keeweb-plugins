/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');
const ps = require('child_process');

const oldKey = fs
    .readFileSync('keys/public-key-old.pem', 'utf8')
    .match(/-+BEGIN PUBLIC KEY-+([\s\S]+?)-+END PUBLIC KEY-+/)[1]
    .replace(/\s+/g, '');
const newKey = fs
    .readFileSync('keys/public-key.pem', 'utf8')
    .match(/-+BEGIN PUBLIC KEY-+([\s\S]+?)-+END PUBLIC KEY-+/)[1]
    .replace(/\s+/g, '');

const pluginDirs = ['docs/plugins', 'docs/translations'];
for (const pluginDir of pluginDirs) {
    for (const pluginName of fs.readdirSync(pluginDir).filter(dir => /^[\w-]+$/.test(dir))) {
        console.log(pluginName);
        const manifestPath = path.join(pluginDir, pluginName, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        if (manifest.publicKey !== oldKey) {
            throw `Bad key in ${manifestPath}`;
        }
        manifest.publicKey = newKey;
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
        const result = ps.spawnSync(
            'node',
            [
                '../keeweb/plugins/keeweb-plugin/keeweb-plugin.js',
                'sign',
                path.join(pluginDir, pluginName),
                '--signer-module=../../../keeweb-plugins/scripts/sign',
                '--bump-version'
            ],
            {
                stdio: 'inherit'
            }
        );
        if (result.status) {
            throw 'Sign error';
        }
    }
}
