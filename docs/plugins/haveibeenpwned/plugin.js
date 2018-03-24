/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const DetailsView = require('views/details/details-view');
const Alerts = require('comp/alerts');
const Logger = require('util/logger');
const InputFx = require('util/input-fx');
const Kdbxweb = require('kdbxweb');
const _ = require('_');

const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;

DetailsView.prototype.checkPwnedOnSettingsChanged = function (changes) {
    // if (changes['CheckPwnedPwd'] || changes['CheckPwnedName'] || changes['BlockPwnedPwd'] || changes['BlockPwnedName']) {
    //   info('Full HaveIBeenPwned check not yet implemented. Checks are done one by one when you change a name or a password.');
    // }
};

let _seen = [];
class HIBPUtils {
    constructor() {
        _seen = [];
        this.checkPwnedPwd = true;
        this.checkPwnedName = true;
        this.blockPwnedPwd = false;
        this.blockPwnedName = false;
        this.logger = new Logger('HaveIBeenPwned');
    };
    replacer(key, value) {
        if (value != null && typeof value === 'object') {
            if (_seen.indexOf(value) >= 0) {
                return;
            }
            _seen.push(value);
        }
        return value;
    };
    stringify(obj) {
        const ret = JSON.stringify(obj, this.replacer);
        _seen = [];
        return ret;
    };
    xhrcall (config) {
        const xhr = new XMLHttpRequest();
        if (config.responseType) {
            xhr.responseType = config.responseType;
        }
        const statuses = config.statuses || [200];
        xhr.addEventListener('load', () => {
            if (statuses.indexOf(xhr.status) >= 0) {
                return config.success && config.success(xhr.response, xhr);
            } else {
                return config.error && config.error('http status ' + xhr.status, xhr);
            }
        });
        xhr.addEventListener('error', () => {
            return config.error && config.error('network error', xhr);
        });
        xhr.addEventListener('timeout', () => {
            return config.error && config.error('timeout', xhr);
        });
        xhr.open(config.method || 'GET', config.url);
        if (config.headers) {
            config.headers.forEach((value, key) => {
                xhr.setRequestHeader(key, value);
            });
        };
        xhr.send(config.data);
    };
    hex (buffer) {
        const hexCodes = [];
        const view = new DataView(buffer);
        for (let i = 0; i < view.byteLength; i += 4) {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            const value = view.getUint32(i);
            // toString(16) will give the hex representation of the number without padding
            const stringValue = value.toString(16);
            // We use concatenation and slice for padding
            const padding = '00000000';
            const paddedValue = (padding + stringValue).slice(-padding.length);
            hexCodes.push(paddedValue);
        }
        // Join all the hex strings into one
        return hexCodes.join('');
    };
    digest(algo, str) {
        // We transform the string into an arraybuffer.
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        const _self = this;
        return subtle.digest(algo, buffer).then(hash => {
            return _self.hex(hash);
        });
    };
    sha1(str) {
        return this.digest('SHA-1', str);
    };
    sha256(str) {
        return this.digest('SHA-256', str);
    };
    alert (msg) {
        Alerts.info({ body: msg, title: 'HaveIBeenPwned' });
    };
}

const hibp = new HIBPUtils();

DetailsView.prototype.checkNamePwned = function (name) {
    hibp.logger.info('check hibp name ' + name);
    name = encodeURIComponent(name);
    const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
    hibp.logger.info('url ' + url);
    hibp.xhrcall({
        url: url,
        method: 'GET',
        responseType: 'json',
        headers: undefined,
        data: null,
        statuses: [200, 404],
        success: (data, xhr) => {
            hibp.logger.info('xhr ' + JSON.stringify(xhr));
            if (data && data.length > 0) {
                hibp.logger.info('found breaches ' + JSON.stringify(data));
                let breaches = '';
                data.forEach(breach => { breaches += '<li>' + _.escape(breach.Name) + '</li>\n'; });
                hibp.alert(`WARNING! This account has been pawned in the following breaches<br/>\n<ul>\n${breaches}\n</ul>\n<p>Please check on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>\n`);
                this.userEditView.$el.focus();
                this.userEditView.$el.addClass('input--error');
                InputFx.shake(this.userEditView.$el);
            } else {
                hibp.logger.info('check pwnd name passed...');
                this.userEditView.$el.removeClass('input--error');
            }
        },
        error: (e, xhr) => {
            const err = xhr.response && xhr.response.error || new Error('Network error');
            hibp.logger.error('Pwned Password API error', 'GET', xhr.status, err);
            err.status = xhr.status;
        }
    });
};

DetailsView.prototype.checkPwdPwned = function (passwordHash) {
    hibp.logger.info('check hibp pwd (hash) ' + passwordHash);
    const prefix = passwordHash.substring(0, 5);
    hibp.xhrcall({
        url: `https://api.pwnedpasswords.com/range/${prefix}`,
        method: 'GET',
        responseType: 'text',
        headers: undefined,
        data: null,
        statuses: [200, 404],
        success: data => {
            if (data) {
                hibp.logger.info('found breaches ' + JSON.stringify(data));
                data.split('\r\n').forEach(line => {
                    const h = line.split(':');
                    const suffix = h[0];
                    if (prefix + suffix === passwordHash) {
                        const nb = _.escape(h[1]);
                        hibp.alert(`WARNING: This password is referenced as pawned ${nb} times on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>!\n`);
                        this.passEditView.$el.focus();
                        this.passEditView.$el.addClass('input--error');
                        InputFx.shake(this.passEditView.$el);
                    }
                });
            } else {
                hibp.logger.info('check pwnd passwd passed...');
                this.passEditView.$el.removeClass('input--error');
            }
        },
        error: (e, xhr) => {
            const err = xhr.response && xhr.response.error || new Error('Network error');
            hibp.logger.error('Pwned Password API error', 'GET', xhr.status, err);
            err.status = xhr.status;
        }
    });
};

DetailsView.prototype.fieldChanged = function (e) {
    detailsViewFieldChanged.apply(this, arguments);
    if (e.field) {
        // hibp.logger.info('field changed ' + hibp.stringify(e));
        if (e.field === '$Password' && hibp.checkPwnedPwd) {
            if (this.passEditView.value) {
                const pwd = this.passEditView.value.getText();
                if (pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:')) {
                    hibp.sha1(pwd).then(hash => {
                        this.checkPwdPwned(hash.toUpperCase());
                    });
                }
            }
        } else if (e.field === '$UserName' && hibp.checkPwnedName) {
            this.checkNamePwned(e.val);
        }
    }
};

module.exports.getSettings = function () {
    const ret = [{
        name: 'checkPwnedPwd',
        label: 'Check passwords against HaveIBeenPwned list',
        type: 'checkbox',
        value: hibp.checkPwnedPwd
    }, {
        name: 'checkPwnedName',
        label: 'Check user ids against HaveIBeenPwned list',
        type: 'checkbox',
        value: hibp.checkPwnedName
    }, {
        name: 'blockPwnedPwd',
        label: 'Block pwned passwords if they are in HaveIBeenPwned list',
        type: 'checkbox',
        value: hibp.blockPwnedPwd
    }, {
        name: 'blockPwnedName',
        label: 'Block pwned names if they are in HaveIBeenPwned list',
        type: 'checkbox',
        value: hibp.blockPwnedName
    }];
    hibp.logger.info(hibp.stringify(ret));
    return ret;
};

module.exports.setSettings = function (changes) {
    // apply changed settings in plugin logic
    // this method will be called:
    // 1. when any of settings fields is modified by user
    // 2. after plugin startup, with saved values
    // only changed settings will be passed

    // example: { MyText: 'value', MySel: 'selected-value', MyCheckbox: true }
    // info(JSON.stringify(changes));

    for (const field in changes) {
        const ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        hibp[ccfield] = changes[field];
    }
    DetailsView.prototype.checkPwnedOnSettingsChanged.apply(changes);
    // hibp.logger.info(hibp.stringify(hibp));
};

module.exports.uninstall = function () {
    DetailsView.prototype.fieldChanged = detailsViewFieldChanged;
};
