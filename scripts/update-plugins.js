const fs = require('fs');
const crypto = require('crypto');

console.log('Welcome to plugins updater');

const data = JSON.parse(fs.readFileSync('docs/plugins.json', 'utf8'));
const privateKey = fs.readFileSync('keys/private-key.pem', 'binary');

console.log('Updating metadata...');

data.date = new Date().toISOString();

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

console.log('Signing...');

data.signature = '';
const dataToSign = JSON.stringify(data, null, 2);

const sign = crypto.createSign('RSA-SHA256');
sign.write(new Buffer(dataToSign));
sign.end();

data.signature = sign.sign(privateKey).toString('base64');

fs.writeFileSync('docs/plugins.json', JSON.stringify(data, null, 2));

console.log('Done');
