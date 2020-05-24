/* eslint-disable no-console */

const fs = require('fs');
const sign = require('./sign');

console.log('Welcome to plugins updater');

console.log('Loading...');

const data = JSON.parse(fs.readFileSync('docs/plugins.json', 'utf8'));

data.signature = '';
data.date = '';
const oldData = JSON.stringify(data);

console.log('Adding translations...');

const allTranslations = JSON.parse(fs.readFileSync('docs/translations/meta.json', 'utf8'));
for (const translation of Object.keys(allTranslations)) {
    const manifest = JSON.parse(fs.readFileSync(`docs/translations/${translation}/manifest.json`));
    const url = `https://plugins.keeweb.info/translations/${translation}`;
    const official = true;
    const pluginMeta = { url, official, manifest };
    const ix = data.plugins.findIndex(p => p.manifest.name === manifest.name);
    if (ix >= 0) {
        data.plugins.splice(ix, 1, pluginMeta);
    } else {
        data.plugins.push(pluginMeta);
    }
}

console.log('Updating plugins...');
for (const plugin of data.plugins) {
    if (plugin.manifest.locale) {
        continue;
    }
    plugin.manifest = JSON.parse(
        fs.readFileSync(`docs/plugins/${plugin.manifest.name}/manifest.json`, 'utf8')
    );
}

console.log('Checking for changes...');

const newData = JSON.stringify(data);
if (newData === oldData) {
    console.log('No changes');
    process.exit(0);
}

console.log('Changes found, updating metadata...');

data.date = new Date().toISOString();

console.log('Signing...');

const dataToSign = Buffer.from(JSON.stringify(data, null, 2));

sign(dataToSign)
    .then(signature => {
        data.signature = signature.toString('base64');
        fs.writeFileSync('docs/plugins.json', JSON.stringify(data, null, 2));
        console.log('Done');
    })
    .catch(err => {
        console.error('Sign error', err);
        process.exit(1);
    });
