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
const SignatureError = 'Request signature missing';

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
                logger.debug('<', postData);
                handleRequest(postData).then(result => {
                    logger.debug('>', JSON.stringify(result));
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify(result));
                });
            });
        } else {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/plain');
            res.end('Nice to meet you! But you should POST here.');
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

function handleRequest(req) {
    try {
        req = JSON.parse(req);
        const response = executeRequest(req);
        if (response instanceof Promise) {
            return response.catch(e => {
                return returnError(req, e);
            });
        } else {
            return Promise.resolve(response);
        }
    } catch (e) {
        return returnError(req, e);
    }
}

function returnError(req, e) {
    if (e !== SignatureError) {
        logger.error('handleRequest error', e);
    }
    return Promise.resolve({
        Error: e ? e.toString() : '',
        Success: false,
        RequestType: req ? req.RequestType : '',
        Version
    });
}

function executeRequest(req) {
    switch (req.RequestType) {
        case 'test-associate':
            return testAssociate(req);
        case 'associate':
            return associate(req);
        case 'get-logins':
            return getLogins(req, {});
        case 'get-logins-count':
            return getLogins(req, { onlyCount: true });
        case 'get-all-logins':
            return getLogins(req, { all: true });
        case 'set-login':
            return setLogin(req);
        case 'generate-password':
            return generatePassword(req);
        default:
            throw 'Not implemented';
    }
}

function decrypt(req, value) {
    const reqKey = keys[req.Id] || req.Key;
    if (!reqKey || !req.Nonce || !req.Verifier) {
        throw SignatureError;
    }
    const key = Buffer.from(reqKey, 'base64');
    const nonce = Buffer.from(req.Nonce, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, nonce);
    return Buffer.concat([decipher.update(value, 'base64'), decipher.final()]).toString();
}

function encrypt(resp, value) {
    const key = Buffer.from(keys[resp.Id], 'base64');
    const nonce = Buffer.from(resp.Nonce, 'base64');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);
    return Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]).toString('base64');
}

function verifyRequest(req) {
    if (req.Id && !keys[req.Id]) {
        // TODO: get key
    }
    const decrypted = decrypt(req, req.Verifier);
    if (decrypted !== req.Nonce) {
        throw 'Invalid signature';
    }
}

function wrapResponse(resp, id) {
    resp = Object.assign({
        Success: true,
        Nonce: '',
        Verifier: '',
        Version: Version
    }, resp);
    if (id && keys[id]) {
        const key = Buffer.from(keys[id], 'base64');
        const nonce = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, nonce);
        const encrypted = Buffer.concat([cipher.update(nonce.toString('base64'), 'utf8'), cipher.final()]).toString('base64');
        resp.Id = id;
        resp.Nonce = nonce.toString('base64');
        resp.Verifier = encrypted;
    }
    return resp;
}

function testAssociate(req) {
    verifyRequest(req);
    return wrapResponse({
        RequestType: req.RequestType,
        TriggerUnlock: req.TriggerUnlock
    }, req.Id);
}

function associate(req) {
    verifyRequest(req);
    electron.remote.app.getMainWindow().focus();
    return new Promise((resolve, reject) => {
        Alerts.yesno({
            header: 'Plugin Connecting',
            body: 'A plugin is trying to connect to KeeWeb. If you are setting up your plugin, please allow the connection. ' +
            'Otherwise, click No.',
            success: () => { resolve(); },
            cancel: () => { reject('Rejected'); }
        });
    }).then(() => {
        const id = 'KeeWeb_' + new Date().toISOString() + '_' + crypto.randomBytes(16).toString('hex');
        keys[id] = req.Key;
        fs.writeFileSync(path.join(__dirname, 'keys.json'), JSON.stringify(keys));
        return wrapResponse({
            RequestType: req.RequestType
        }, id);
    });
}

function getLogins(req, config) {
    verifyRequest(req);
    if (!req.Url) {
        throw 'Invalid request';
    }
    const url = decrypt(req, req.Url);
    logger.debug('get-logins', url);
    const response = wrapResponse({
        RequestType: req.RequestType
    }, req.Id);
    const filter = new AutoTypeFilter({ url }, AutoType.appModel);
    const entries = filter.getEntries();
    response.Count = entries.length;
    if (!config.onlyCount) {
        response.Entries = entries.map(entry => ({
            Login: entry.user ? encrypt(response, entry.user) : '',
            Name: entry.title ? encrypt(response, entry.title) : '',
            Password: entry.password ? encrypt(response, entry.password.getText()) : '',
            StringFields: null,
            Uuid: encrypt(response, entry.id)
        }));
    }
    return response;
}

function setLogin(req) {
    verifyRequest(req);
    if (!req.Url || !req.Login || !req.Password) {
        throw 'Invalid request';
    }
    const url = decrypt(req, req.Url);
    const login = decrypt(req, req.Login);
    const password = decrypt(req, req.Password);
    logger.debug('set-login', url, login, password);
    return wrapResponse({
        RequestType: req.RequestType
    }, req.Id);
}

function generatePassword(req) {
    verifyRequest(req);
    const response = wrapResponse({
        RequestType: req.RequestType
    }, req.Id);
    response.Count = 1;
    response.Entries = [{
        Login: '',
        Name: '',
        Password: encrypt(response, 'I am generated password: ' + new Date()),
        StringFields: null,
        Uuid: ''
    }];
    return response;
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
