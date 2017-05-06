/* eslint-disable no-console */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

const keys = require('../keys/onesky.json');

const USE_FILES = false;
const PROJECT_ID = '173183';
const API_URL = 'https://platform.api.onesky.io/1/projects/:project_id/translations/multilingual';
const API_URL_LANGUAGES = 'https://platform.api.onesky.io/1/projects/:project_id/languages';
const PHRASE_COUNT_THRESHOLD_PERCENT = 75;

const ts = Math.floor(new Date() / 1000);

const hashStr = ts + keys.secret;
const hash = crypto.createHash('md5').update(hashStr).digest('hex');
const urlParams = {
    'api_key': keys.public,
    'timestamp': ts,
    'dev_hash': hash,
    'source_file_name': 'base.json',
    'file_format': 'I18NEXT_MULTILINGUAL_JSON'
};

const pluginManifest = fs.readFileSync('tmpl/manifest.json', 'utf8');
const pluginIndexPage = fs.readFileSync('tmpl/language-index.html', 'utf8');
const privateKey = fs.readFileSync('keys/private-key.pem', 'binary');
const publicKey = fs.readFileSync('keys/public-key.pem', 'utf8')
    .match(/-+BEGIN PUBLIC KEY-+([\s\S]+?)-+END PUBLIC KEY-+/)[1]
    .replace(/\n/g, '');
const defaultCountries = { 'SE': 'sv' };

loadLanguages(languages =>
    loadTranslations(translations =>
        processData(languages, translations)
    )
);

function loadLanguages(callback) {
    if (USE_FILES) {
        return callback(JSON.parse(fs.readFileSync('./data/languages.json', 'utf8')));
    }
    console.log('Loading language names...');
    const url = API_URL_LANGUAGES.replace(':project_id', PROJECT_ID) + '?' +
        Object.keys(urlParams).map(param => param + '=' + urlParams[param]).join('&');
    https.get(url, res => {
        if (res.statusCode !== 200) {
            console.error(`API error ${res.statusCode}`);
            return;
        }
        console.log('Response received, reading...');
        const data = [];
        res.on('data', chunk => data.push(chunk));
        res.on('end', () => {
            console.log('Data received, parsing...');
            const json = Buffer.concat(data).toString('utf8');
            const parsed = JSON.parse(json);
            fs.writeFileSync('data/languages.json', JSON.stringify(parsed, null, 2));
            callback(parsed);
        });
    });
}

function loadTranslations(callback) {
    if (USE_FILES) {
        return callback(JSON.parse(fs.readFileSync('./data/translations.json', 'utf8')));
    }
    console.log('Loading translations...');
    const url = API_URL.replace(':project_id', PROJECT_ID) + '?' +
        Object.keys(urlParams).map(param => param + '=' + urlParams[param]).join('&');
    https.get(url, res => {
        if (res.statusCode !== 200) {
            console.error(`API error ${res.statusCode}`);
            return;
        }
        console.log('Response received, reading...');
        const data = [];
        res.on('data', chunk => data.push(chunk));
        res.on('end', () => {
            console.log('Data received, parsing...');
            const json = Buffer.concat(data).toString('utf8');
            const parsed = JSON.parse(json);
            fs.writeFileSync('data/translations.json', JSON.stringify(parsed, null, 2));
            callback(parsed);
        });
    });
}

function processData(languages, translations) {
    let langCount = 0;
    let skipCount = 0;
    const enUs = translations['en-US'].translation;
    const totalPhraseCount = Object.keys(enUs).length;
    let errors = 0;
    const meta = {};
    Object.keys(translations).forEach(lang => {
        const languageTranslations = translations[lang].translation;
        if (lang === 'en-US' || !languageTranslations) {
            return;
        }
        const langPhraseCount = Object.keys(languageTranslations).length;
        const percentage = Math.round(langPhraseCount / totalPhraseCount * 100);
        const included = percentage >= PHRASE_COUNT_THRESHOLD_PERCENT;
        const action = included ? '\x1b[36mOK\x1b[0m' : '\x1b[35mSKIP\x1b[0m';
        console.log(`[${lang}] ${langPhraseCount} / ${totalPhraseCount} (${percentage}%) -> ${action}`);
        if (included) {
            langCount++;
            for (const name of Object.keys(languageTranslations)) {
                let text = languageTranslations[name];
                let enText = enUs[name];
                if (text instanceof Array) {
                    if (!(enText instanceof Array)) {
                        languageTranslations[name] = text.join('\n');
                        console.error(`[${lang}]    \x1b[31mERROR:ARRAY\x1b[0m ${name}`);
                        enText = [enText];
                        errors++;
                    }
                    text = text.join('\n');
                    enText = enText.join('\n');
                }
                if (!enText) {
                    console.warn(`[${lang}] SKIP ${name}`);
                    delete languageTranslations[name];
                    continue;
                }
                const textMatches = text.match(/"/g);
                const textMatchesCount = textMatches && textMatches.length || 0;
                const enTextMatches = enText.match(/"/g);
                const enTextMatchesCount = enTextMatches && enTextMatches.length || 0;
                if (enTextMatchesCount !== textMatchesCount) {
                    const textHl = text.replace(/"/g, '\x1b[33m"\x1b[0m');
                    console.warn(`[${lang}]    \x1b[33mWARN:"\x1b[0m ${name}: ${textHl}`);
                }
                if (/[<>&]/.test(text)) {
                    const textHl = text.replace(/([<>&])/g, '\x1b[31m$1\x1b[0m');
                    console.error(`[${lang}]    \x1b[31mERROR:<>\x1b[0m ${name}: ${textHl}`);
                    errors++;
                }
                if (text.indexOf('{}') >= 0 && enText.indexOf('{}') < 0) {
                    const textHl = text.replace(/\{}/g, '\x1b[31m{}\x1b[0m');
                    console.error(`[${lang}]    \x1b[31mERROR:{}\x1b[0m ${name}: ${textHl}`);
                    errors++;
                }
                if (enText.indexOf('{}') >= 0 && text.indexOf('{}') < 0) {
                    const enTextHl = enText.replace(/\{}/g, '\x1b[31m{}\x1b[0m');
                    console.error(`[${lang}]    \x1b[31mERROR:NO{}\x1b[0m ${name}: ${text} <--> ${enTextHl}`);
                    errors++;
                }
            }
            const languageJson = JSON.stringify(languageTranslations, null, 2);
            const sign = crypto.createSign('RSA-SHA256');
            sign.write(Buffer.from(languageJson));
            sign.end();
            const signature = sign.sign(privateKey).toString('base64');

            const langInfo = languages.data.filter(x => x.code === lang)[0];
            const region = (defaultCountries[langInfo.region] || langInfo.region).toLowerCase();
            const langName = langInfo.locale === region ? langInfo.local_name.replace(/\s*\(.*\)/, '') : langInfo.local_name;
            const langNameEn = langInfo.locale === region ? langInfo.english_name.replace(/\s*\(.*\)/, '') : langInfo.english_name;
            meta[lang] = { name: langName, nameEn: langNameEn, count: langPhraseCount };

            if (fs.existsSync(`docs/translations/${lang}`)) {
                const manifest = JSON.parse(fs.readFileSync(`docs/translations/${lang}/manifest.json`, 'utf8'));
                if (manifest.resources.loc !== signature) {
                    const parts = manifest.version.split('.');
                    manifest.version = parts[0] + '.' + (+parts[1] + 1) + '.0';
                    manifest.resources.loc = signature;
                    fs.writeFileSync(`docs/translations/${lang}/manifest.json`, JSON.stringify(manifest, null, 2));
                    fs.writeFileSync(`docs/translations/${lang}/${lang}.json`, languageJson);
                }
                meta[lang].version = manifest.version;
            } else {
                fs.mkdirSync(`docs/translations/${lang}`);
                fs.writeFileSync(`docs/translations/${lang}/manifest.json`, pluginManifest
                    .replace(/{lang}/g, lang)
                    .replace(/{name_ascii}/g, langNameEn.replace(/\W+/g, '-').toLowerCase())
                    .replace(/{name_en}/g, langNameEn)
                    .replace(/{name}/g, langName)
                    .replace(/{signature}/g, signature)
                    .replace(/{key}/g, publicKey)
                );
                fs.writeFileSync(`docs/translations/${lang}/${lang}.json`, languageJson);
                fs.writeFileSync(`docs/translations/${lang}/index.html`, pluginIndexPage
                    .replace(/{lang}/g, lang)
                    .replace(/{name}/g, langName)
                );
                meta[lang].version = '1.0.0';
            }
        } else {
            skipCount++;
        }
    });
    console.log(`Done: ${langCount} written, ${skipCount} skipped, ${errors} errors`);
    if (errors) {
        console.error('There were errors, please check the output.');
        process.exit(1);
    }
    fs.writeFileSync('docs/translations/meta.json', JSON.stringify(meta, null, 2));
}
