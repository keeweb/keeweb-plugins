const nodeRequire = window.require;

const http = nodeRequire('http');
const crypto = nodeRequire('crypto');
const fs = nodeRequire('fs');
const path = nodeRequire('path');
const electron = nodeRequire('electron');

const AutoType = require('auto-type/index');
const AutoTypeFilter = require('auto-type/auto-type-filter');
const Logger = require('util/logger');
const Alerts = require('comp/alerts');

// const appModel = ...; TODO: use AppModel.instance

const Version = '1.8.4.2';
const DebugMode = true;

const keys = {};

const logger = new Logger('keewebhttp');

let server;
let uninstalled = false;

setTimeout(init, 0);

function init() {
    if (uninstalled) {
        return;
    }
    server = http.createServer((req, res) => {
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
        } else {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/plain');
            res.end('Hey dude, you should POST here!');
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
    server.on('connection', function(conn) {
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
                return this.getLogins({ onlyCount: true });
            case 'get-all-logins':
                return this.getLogins({ all: true });
            case 'set-login':
                return this.setLogin();
            case 'generate-password':
                return this.generatePassword();
            default:
                throw 'Not implemented';
        }
    }

    makeError(e) {
        logger.error('handleRequest error', e);
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
            throw 'No key';
        }
        if (!this.resp || !this.resp.Nonce) {
            throw 'No nonce';
        }
        const key = Buffer.from(this.aesKey, 'base64');
        const nonce = Buffer.from(this.resp.Nonce, 'base64');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);
        return Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]).toString('base64');
    }

    getKeyById() {
        return keys[this.req.Id];
    }

    saveKeyWithId() {
        keys[this.req.Id] = this.req.Key;
        // TODO
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
            return this.makeError('');
        }
        this.verifyRequest();
        this.createResponse();
    }

    associate() {
        if (this.req.Id) {
            throw 'Id not expected';
        }
        if (!this.req.Key) {
            throw 'No key';
        }
        this.aesKey = this.req.Key;
        this.verifyRequest();
        electron.remote.app.getMainWindow().focus();
        return new Promise((resolve, reject) => {
            Alerts.yesno({
                header: 'External Connection',
                body: 'Some app is trying to connect to KeeWeb. If you are setting up your plugin, please allow the connection. Otherwise, click No.',
                success: () => { resolve(); },
                cancel: () => { reject('Rejected by user'); }
            });
        }).then(() => {
            this.req.Id = 'KeeWeb_' + new Date().toISOString() + '_' + crypto.randomBytes(16).toString('hex');
            this.saveKeyWithId();
            this.createResponse();
            return this.resp;
        });
    }

    getLogins(config) {
        this.verifyRequest();
        if (!this.req.Url) {
            throw 'No url';
        }
        const url = this.decrypt(this.req.Url);
        logger.debug('get-logins', url);
        this.createResponse();
        const filter = new AutoTypeFilter({ url }, AutoType.appModel);
        const entries = filter.getEntries();
        this.resp.Count = entries.length;
        if (!config.onlyCount) {
            this.resp.Entries = entries.map(entry => ({
                Login: entry.user ? this.encrypt(entry.user) : '',
                Name: entry.title ? this.encrypt(entry.title) : '',
                Password: entry.password ? this.encrypt(entry.password.getText()) : '',
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
        logger.debug('set-login', url, login, password);
        this.createResponse();
    }

    generatePassword() {
        this.verifyRequest();
        this.createResponse();
        this.resp.Count = 1;
        this.resp.Entries = [{
            Login: '',
            Name: '',
            Password: this.encrypt('I am generated password: ' + new Date()),
            StringFields: null,
            Uuid: ''
        }];
    }
}

module.exports.uninstall = function() {
    if (server) {
        server.close();
        for (const key of Object.keys(server.conn)) {
            server.conn[key].destroy();
        }
        server = null;
    }
    uninstalled = true;
};
