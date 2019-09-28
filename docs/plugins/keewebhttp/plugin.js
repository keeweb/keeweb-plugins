let uninstall;
let restart;
let serverPort = 19455;
const timeout = setTimeout(run, 500);

function run() {
    const nodeRequire = window.require;

    const http = nodeRequire('http');
    const crypto = nodeRequire('crypto');
    const electron = nodeRequire('electron');

    const kdbxweb = require('kdbxweb');
    const Events = require('framework/events').Events;
    const AppModel = require('models/app-model').AppModel;
    const EntryModel = require('models/entry-model').EntryModel;
    const GroupModel = require('models/group-model').GroupModel;
    const AutoTypeFilter = require('auto-type/auto-type-filter').AutoTypeFilter;
    const Logger = require('util/logger').Logger;
    const Alerts = require('comp/ui/alerts').Alerts;
    const PasswordGenerator = require('util/generators/password-generator').PasswordGenerator;
    const GeneratorPresets = require('comp/app/generator-presets').GeneratorPresets;

    const Version = '1.8.4.2';
    const DebugMode = localStorage.keewebhttpDebug;
    const FileReadTimeout = 500;
    const EntryTitle = 'KeePassHttp Settings';
    const EntryFieldPrefix = 'AES Key: ';
    const EntryUuid = 'NGl6QIpbQcCfNol9Yj7LMQ==';
    const CreatePasswordsGroupTitle = 'KeePassHttp Passwords';

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

    restart = function() {
        stopServer();
        startServer();
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
            if (req.method !== 'POST' || referer || origin &&
                !origin.startsWith('chrome-extension://') && !origin.startsWith('safari-extension://')
            ) {
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
        const port = serverPort;
        const hostname = '127.0.0.1';
        server.listen(port, hostname, () => {
            if (uninstalled) {
                server.close();
                return;
            }
            logger.debug(`Server running at http://${hostname}:${port}/`);
        });
        server.on('connection', conn => {
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
            settingsEntry = EntryModel.newEntry(file.groups[0], file);
            settingsEntry.entry.uuid = new kdbxweb.KdbxUuid(EntryUuid);
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
        Events.emit('refresh');
    }

    function getSettingsEntry(file) {
        return file.getEntry(file.subId(EntryUuid));
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
            const requestType = this.req && this.req.RequestType || '';
            if (!skipLog) {
                logger.error('handleRequest error', requestType, e);
            }
            return {
                Error: e ? e.toString() : '',
                Success: false,
                RequestType: requestType,
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
            return keys[this.req.Id];
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
                this.req.Id = 'KeeWeb ' + new Date().toISOString();
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
            if (!AppModel.instance.files.hasOpenFiles()) {
                if (this.req.TriggerUnlock === true || this.req.TriggerUnlock === 'true') {
                    electron.remote.app.getMainWindow().focus();
                }
                return this.makeError('Locked', true);
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
                this.resp.Entries = entries.map(entry => {
                    let customFields = null;
                    for (const field of Object.keys(entry.fields)) {
                        if (!customFields) {
                            customFields = [];
                        }
                        const fieldKey = this.encrypt(field);
                        const fieldValue = this.encrypt(entry.fields[field]);
                        customFields.push({ Key: fieldKey, Value: fieldValue });
                    }
                    return {
                        Login: entry.user ? this.encrypt(entry.user) : '',
                        Name: entry.title ? this.encrypt(entry.title) : '',
                        Password: entry.password ? this.encrypt(entry.password) : '',
                        StringFields: customFields,
                        Uuid: this.encrypt(entry.entry.uuid.id)
                    };
                });
            }
        }

        setLogin() {
            this.verifyRequest();
            if (!this.req.Url || !this.req.Login || !this.req.Password) {
                throw 'Invalid request';
            }
            const uuid = this.req.Uuid ? this.decrypt(this.req.Uuid) : null;
            const url = this.decrypt(this.req.Url);
            const login = this.decrypt(this.req.Login);
            const password = this.decrypt(this.req.Password);

            if (uuid) {
                let result = 'not found';
                AppModel.instance.files.forEach(file => {
                    const entry = file.getEntry(file.subId(uuid));
                    if (entry) {
                        if (entry.user !== login) {
                            entry.setField('UserName', login);
                        }
                        if (!entry.password.equals(password)) {
                            entry.setField('Password', kdbxweb.ProtectedValue.fromString(password));
                        }
                    }
                    result = 'updated';
                });
                logger.info(`setLogin(${url}, ${login}, ${password.length}): ${result}`);
            } else {
                logger.info(`setLogin(${url}, ${login}, ${password.length}): inserted`);
                let group, file;
                AppModel.instance.files.forEach(f => {
                    f.forEachGroup(g => {
                        if (g.title === CreatePasswordsGroupTitle) {
                            group = g;
                            file = f;
                        }
                    });
                });
                if (!group) {
                    file = AppModel.instance.files[0];
                    group = GroupModel.newGroup(file.groups[0], file);
                    group.setName(CreatePasswordsGroupTitle);
                }
                const entry = EntryModel.newEntry(group, file);
                const domain = url.match(/^(?:\w+:\/\/)?(?:(?:www|wwws|secure)\.)?([^\/]+)\/?(?:.*)/);
                const title = domain && domain[1] || 'Saved Password';
                entry.setField('Title', title);
                entry.setField('URL', url);
                entry.setField('UserName', login);
                entry.setField('Password', kdbxweb.ProtectedValue.fromString(password));
            }
            Events.emit('refresh');

            this.createResponse();
        }

        generatePassword() {
            this.verifyRequest();
            this.createResponse();
            const preset = GeneratorPresets.all.filter(p => p.default)[0] || GeneratorPresets.defaultPreset;
            const password = PasswordGenerator.generate(preset);
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

module.exports.getSettings = function() {
    return [{
        name: 'ServerPort',
        label: 'Port to listen to (do not change this setting without a special need to do so)',
        type: 'text',
        maxlength: 5,
        placeholder: '19455',
        value: '19455'
    }];
};

module.exports.setSettings = function(changes) {
    if (changes.ServerPort) {
        const port = +changes.ServerPort;
        if (port > 1024 && port < 65535) {
            serverPort = port;
            if (restart) {
                restart();
            }
        }
    }
};

module.exports.uninstall = function() {
    if (uninstall) {
        uninstall();
    } else {
        clearTimeout(timeout);
    }
};
