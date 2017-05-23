let uninstall;
const timeout = setTimeout(run, 500);

function run() {
    const nodeRequire = window.require;

    const http = nodeRequire('http');
    const crypto = nodeRequire('crypto');
    const fs = nodeRequire('fs');
    const path = nodeRequire('path');
    const electron = nodeRequire('electron');

    const kdbxweb = require('kdbxweb');
    const AppModel = require('models/app-model');
    const EntryModel = require('models/entry-model');
    const AutoTypeFilter = require('auto-type/auto-type-filter');
    const Logger = require('util/logger');
    const Alerts = require('comp/alerts');
    const Generator = require('util/password-generator');
    const GeneratorPresets = require('comp/generator-presets');

    const Version = '1.8.4.2';
    const DebugMode = true;
    const FileReadTimeout = 500;
    const EntryTitle = 'KeePassHttp Settings';
    const EntryFieldPrefix = 'AES Key: ';

    const keys = {};
    const addedKeys = {};
    const logger = new Logger('keewebhttp');

    let uninstalled;
    let server;

    uninstall = function() {
        uninstalled = true;
        removeEventListeners();
        stopServer();
    };

    addEventListeners();
    startServer();
    readAllKeys();

    function addEventListeners() {
        AppModel.instance.files.on('add', fileOpened);
    }

    function removeEventListeners() {
        AppModel.instance.files.off('add', fileOpened);
    }

    function startServer() {
        if (uninstalled) {
            return;
        }
        server = http.createServer((req, res) => {
            const origin = req.headers.origin;
            const referer = req.headers.referrer || req.headers.referer;
            if (req.method !== 'POST' || referer || origin && !origin.startsWith('chrome-extension://')) {
                if (DebugMode) {
                    logger.debug('Request dropped', req.method, req.url, req.headers);
                }
                req.client.destroy();
                res.end();
                return;
            }
            if (req.method === 'POST') {
                const body = [];
                req.on('data', data => body.push(data));
                req.on('end', () => {
                    const postData = Buffer.concat(body).toString();
                    if (DebugMode) {
                        logger.debug('< ' + postData);
                    }
                    new RequestContext(postData)
                        .handle()
                        .then(response => {
                            if (DebugMode) {
                                logger.debug('> ' + response);
                            }
                            res.statusCode = 200;
                            res.setHeader('Content-Type', 'application/json');
                            res.end(response);
                        });
                });
            }
        });
        const port = 19455;
        const hostname = '127.0.0.1';
        server.listen(port, hostname, () => {
            if (uninstalled) {
                server.close();
                return;
            }
            logger.debug(`Server running at http://${hostname}:${port}/`);
        });
        server.on('connection', function (conn) {
            const key = conn.remoteAddress + ':' + conn.remotePort;
            server.conn[key] = conn;
            conn.on('close', () => {
                if (server) {
                    delete server.conn[key];
                }
            });
        });
        server.conn = {};
    }

    function stopServer() {
        if (server) {
            server.close();
            for (const key of Object.keys(server.conn)) {
                server.conn[key].destroy();
            }
            server = null;
        }
    }

    function fileOpened(file) {
        setTimeout(() => {
            readKeys(file);
            writeAddedKeys(file);
        }, FileReadTimeout);
    }

    function readAllKeys() {
        AppModel.instance.files.forEach(file => readKeys(file));
    }

    function readKeys(file) {
        if (uninstalled) {
            return;
        }
        const entry = getSettingsEntry(file);
        if (!entry) {
            return;
        }
        for (const field of Object.keys(entry.fields)) {
            if (field.startsWith(EntryFieldPrefix)) {
                const key = field.replace(EntryFieldPrefix, '');
                let value = entry.fields[field];
                if (value && value.isProtected) {
                    value = value.getText();
                }
                if (key && value && !keys[key]) {
                    keys[key] = value;
                }
            }
        }
    }

    function writeAddedKeysToAllFiles() {
        AppModel.instance.files.forEach(file => {
            writeAddedKeys(file);
        });
    }

    function writeAddedKeys(file) {
        if (uninstalled || !Object.keys(addedKeys).length) {
            return;
        }
        let settingsEntry = getSettingsEntry(file);
        if (!settingsEntry) {
            settingsEntry = EntryModel.newEntry(file.get('groups').first(), file);
            settingsEntry.setField('Title', EntryTitle);
        }
        for (const key of Object.keys(addedKeys)) {
            const keyFieldName = EntryFieldPrefix + key;
            const value = addedKeys[key];
            let oldValue = settingsEntry.fields[keyFieldName];
            if (oldValue && oldValue.isProtected) {
                oldValue = oldValue.getText();
            }
            if (oldValue !== value) {
                settingsEntry.setField(keyFieldName, kdbxweb.ProtectedValue.fromString(value));
            }
        }
        file.reload();
    }

    function getSettingsEntry(file) {
        let entry = null;
        file.get('groups').first().forEachOwnEntry({ textLower: EntryTitle.toLowerCase() }, e => {
            if (e.title === EntryTitle) {
                entry = e;
            }
        });
        return entry;
    }

    class RequestContext {
        constructor(postData) {
            this.postData = postData;
        }

        handle() {
            let result;
            try {
                this.req = JSON.parse(this.postData);
                const response = this.execute() || this.resp;
                if (response instanceof Promise) {
                    result = response.catch(e => {
                        return this.makeError(e);
                    });
                } else {
                    result = Promise.resolve(response);
                }
            } catch (e) {
                result = Promise.resolve(this.makeError(e));
            }
            return result.then(res => JSON.stringify(res));
        }

        execute() {
            switch (this.req.RequestType) {
                case 'test-associate':
                    return this.testAssociate();
                case 'associate':
                    return this.associate();
                case 'get-logins':
                    return this.getLogins({});
                case 'get-logins-count':
                    return this.getLogins({onlyCount: true});
                case 'get-all-logins':
                    return this.getLogins({all: true});
                case 'set-login':
                    return this.setLogin();
                case 'generate-password':
                    return this.generatePassword();
                default:
                    throw 'Not implemented';
            }
        }

        makeError(e, skipLog) {
            if (!skipLog) {
                logger.error('handleRequest error', e);
            }
            return {
                Error: e ? e.toString() : '',
                Success: false,
                RequestType: this.req ? this.req.RequestType : '',
                Version: Version
            };
        }

        decrypt(value) {
            if (!this.aesKey) {
                throw 'No key';
            }
            if (!this.req.Nonce) {
                throw 'No nonce';
            }
            const key = Buffer.from(this.aesKey, 'base64');
            const nonce = Buffer.from(this.req.Nonce, 'base64');
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, nonce);
            return Buffer.concat([decipher.update(value, 'base64'), decipher.final()]).toString();
        }

        encrypt(value) {
            if (!this.aesKey) {
                throw 'No aes key';
            }
            if (!this.resp || !this.resp.Nonce) {
                throw 'No nonce';
            }
            const key = Buffer.from(this.aesKey, 'base64');
            const nonce = Buffer.from(this.resp.Nonce, 'base64');
            const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);
            let data;
            if (value.isProtected) {
                const binaryData = value.getBinary();
                data = Buffer.from(binaryData);
                binaryData.fill(0);
            } else {
                data = Buffer.from(value, 'utf8');
            }
            const encrypted = Buffer.concat([cipher.update(data), cipher.final()]).toString('base64');
            data.fill(0);
            return encrypted;
        }

        getKeyById() {
            let key = keys[this.req.Id];
            if (!key) {
                keys[this.req.Id] = key;
            }
            return key;
        }

        saveKeyWithId() {
            keys[this.req.Id] = this.req.Key;
            addedKeys[this.req.Id] = this.req.Key;
            writeAddedKeysToAllFiles();
        }

        verifyRequest() {
            if (!this.req.Verifier) {
                throw 'No verifier';
            }
            if (!this.aesKey) {
                this.aesKey = this.getKeyById();
            }
            const decrypted = this.decrypt(this.req.Verifier);
            if (decrypted !== this.req.Nonce) {
                throw 'Bad signature';
            }
        }

        createResponse() {
            const resp = {
                Success: true,
                Nonce: '',
                Verifier: '',
                Version: Version,
                RequestType: this.req.RequestType
            };
            if (this.req.Id && keys[this.req.Id]) {
                const key = Buffer.from(keys[this.req.Id], 'base64');
                const nonce = crypto.randomBytes(16);
                const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);
                const encrypted = Buffer.concat([cipher.update(nonce.toString('base64'), 'utf8'), cipher.final()]).toString('base64');
                resp.Id = this.req.Id;
                resp.Nonce = nonce.toString('base64');
                resp.Verifier = encrypted;
            }
            this.resp = resp;
        }

        testAssociate() {
            if (!this.req.Id) {
                return this.makeError('', true);
            }
            if (!this.getKeyById(this.req.Id)) {
                return this.makeError('Unknown Id', true);
            }
            this.verifyRequest();
            this.createResponse();
        }

        associate() {
            if (this.req.Id) {
                throw 'Id not expected';
            }
            if (!this.req.Key) {
                throw 'No request key';
            }
            this.aesKey = this.req.Key;
            this.verifyRequest();
            electron.remote.app.getMainWindow().focus();
            return new Promise((resolve, reject) => {
                Alerts.yesno({
                    icon: 'plug',
                    header: 'External Connection',
                    body: 'Some app is trying to manage passwords in KeeWeb. If you are setting up your plugin, please allow the connection. Otherwise, click No.',
                    success: () => {
                        resolve();
                    },
                    cancel: () => {
                        reject('Rejected by user');
                    }
                });
            }).then(() => {
                this.req.Id = 'KeeWeb_' + new Date().toISOString() + '_' + crypto.randomBytes(16).toString('hex');
                logger.info(`associate: ${this.req.Id}`);
                this.saveKeyWithId();
                this.createResponse();
                return this.resp;
            });
        }

        getLogins(config) {
            this.verifyRequest();
            if (!this.req.Url && !config.all) {
                throw 'No url';
            }
            const url = this.req.Url ? this.decrypt(this.req.Url) : '';
            this.createResponse();
            const filter = new AutoTypeFilter({url}, AppModel.instance);
            if (config.all) {
                filter.ignoreWindowInfo = true;
            }
            const entries = filter.getEntries();
            this.resp.Count = entries.length;
            logger.info(`getLogins(${url}): ${this.resp.Count}`);
            if (!config.onlyCount) {
                this.resp.Entries = entries.map(entry => ({
                    Login: entry.user ? this.encrypt(entry.user) : '',
                    Name: entry.title ? this.encrypt(entry.title) : '',
                    Password: entry.password ? this.encrypt(entry.password) : '',
                    StringFields: null,
                    Uuid: this.encrypt(entry.id)
                }));
            }
        }

        setLogin() {
            this.verifyRequest();
            if (!this.req.Url || !this.req.Login || !this.req.Password) {
                throw 'Invalid request';
            }
            const url = this.decrypt(this.req.Url);
            const login = this.decrypt(this.req.Login);
            const password = this.decrypt(this.req.Password);
            logger.info('setLogin', url, login, password);
            this.createResponse();
        }

        generatePassword() {
            this.verifyRequest();
            this.createResponse();
            const preset = GeneratorPresets.all.filter(p => p.default)[0] || GeneratorPresets.defaultPreset;
            const password = Generator.generate(preset);
            const bits = Buffer.from(password, 'utf8').byteLength * 8;
            this.resp.Count = 1;
            this.resp.Entries = [{
                Login: this.encrypt(bits.toString()),
                Name: '',
                Password: this.encrypt(password),
                StringFields: null,
                Uuid: ''
            }];
        }
    }
}

module.exports.uninstall = function() {
    if (uninstall) {
        uninstall();
    } else {
        clearTimeout(timeout);
    }
};
