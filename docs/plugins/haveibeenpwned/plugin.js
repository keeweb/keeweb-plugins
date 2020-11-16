/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const Logger = require('util/logger').Logger;
// change log level here.
const LogLevel = Logger.Level.Info;

const DetailsView = require('views/details/details-view').DetailsView;
const InputFx = require('util/ui/input-fx').InputFx;
const Kdbxweb = require('kdbxweb');
const utilFn = require('util/fn');
const Tip = require('util/ui/tip').Tip;
const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;

let _seen = [];
class HIBPUtils {
    constructor() {
        _seen = [];
        this.checkPwnedPwd = true;
        this.checkPwnedName = true;
        this.blockPwnedPwd = false;
        this.blockPwnedName = false;
        this.logger = new Logger('HaveIBeenPwned');
        this.logger.setLevel(LogLevel);
    }

    replacer(key, value) {
        if (value != null && typeof value === 'object') {
            if (_seen.indexOf(value) >= 0) {
                return;
            }
            _seen.push(value);
        }
        return value;
    }

    stringify(obj) {
        const ret = JSON.stringify(obj, this.replacer);
        _seen = [];
        return ret;
    }

    xhrcall(config) {
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
            const err = (xhr.response && xhr.response.error) || new Error('Network error');
            this.logger.error('HaveIBeenPwned API error', 'GET', xhr.status, err);
            err.status = xhr.status;
            return err;
        });
        xhr.addEventListener('timeout', () => {
            return config.error && config.error('timeout', xhr);
        });
        xhr.open(config.method || 'GET', config.url);
        if (config.headers) {
            for (const key in config.headers) {
                xhr.setRequestHeader(key, config.headers[key]);
            }
        }
        xhr.send(config.data);
    }

    hex(buffer) {
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
    }

    digest(algo, str) {
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        const _self = this;
        return subtle.digest(algo, buffer).then((hash) => {
            return _self.hex(hash);
        });
    }

    sha1(str) {
        return this.digest('SHA-1', str);
    }

    sha256(str) {
        return this.digest('SHA-256', str);
    }

    alert(el, msg) {
        // Alerts.info({ body: msg, title: 'HaveIBeenPwned' });
        el.focus();
        el.addClass('input--error');
        el.addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' });
        InputFx.shake(el);
    }

    passed(el, msg) {
        hibp.logger.info(msg);
        el.removeClass('input--error');
        el.removeClass('hibp-pwned');
    }
}

const hibp = new HIBPUtils();

DetailsView.prototype.checkNamePwned = function (name) {
    hibp.logger.info('check hibp name ' + name);
    name = encodeURIComponent(name);
    const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
    hibp.logger.debug('url ' + url);
    hibp.xhrcall({
        url: url,
        method: 'GET',
        responseType: 'json',
        data: null,
        statuses: [200, 404],
        success: (data, xhr) => {
            if (data && data.length > 0) {
                hibp.logger.debug('found breaches ' + JSON.stringify(data));
                let breaches = '';
                data.forEach((breach) => {
                    breaches += '<li>' + utilFn.escape(breach.Name) + '</li>\n';
                });
                hibp.alert(
                    this.userEditView.$el,
                    `WARNING! This account has been pawned in the following breaches<br/>\n<ul>\n${breaches}\n</ul>\n<p>Please check on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>\n`
                );
            } else {
                hibp.passed(this.userEditView.$el, 'check pwned user name passed...');
            }
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
        data: null,
        statuses: [200, 404],
        success: (data) => {
            if (data) {
                hibp.logger.debug('found breaches ' + JSON.stringify(data));
                data.split('\r\n').forEach((line) => {
                    const h = line.split(':');
                    const suffix = h[0];
                    if (prefix + suffix === passwordHash) {
                        const nb = utilFn.escape(h[1]);
                        hibp.alert(
                            this.getFieldView('$Password').$el,
                            `WARNING: This password is referenced as pawned ${nb} times on https://haveibeenpwned.com!\n`
                        );
                    }
                });
            } else {
                hibp.passed(this.userEditView.$el, 'check pwned password passed...');
            }
        }
    });
};

DetailsView.prototype.fieldChanged = function (e) {
    detailsViewFieldChanged.apply(this, arguments);
    if (e.field) {
        hibp.logger.debug('field changed ' + hibp.stringify(e));
        if (e.field === '$Password' && hibp.checkPwnedPwd) {
            if (this.getFieldView('$Password').value) {
                const pwd = this.getFieldView('$Password').value.getText();
                if (pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:')) {
                    hibp.sha1(pwd).then((hash) => {
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
    return [
        {
            name: 'checkPwnedPwd',
            label: 'Check passwords against HaveIBeenPwned list',
            type: 'checkbox',
            value: hibp.checkPwnedPwd
            // disabled since API V3 of HaveIbeenPwned is not free anymore for checking accounts
            //    }, {
            //        name: 'checkPwnedName',
            //        label: 'Check user ids against HaveIBeenPwned list',
            //        type: 'checkbox',
            //        value: hibp.checkPwnedName
        },
        {
            name: 'blockPwnedPwd',
            label: 'Block pwned passwords if they are in HaveIBeenPwned list',
            type: 'checkbox',
            value: hibp.blockPwnedPwd
            //    }, {
            //        name: 'blockPwnedName',
            //        label: 'Block pwned names if they are in HaveIBeenPwned list',
            //        type: 'checkbox',
            //        value: hibp.blockPwnedName
        }
    ];
};
// disabled since API V3 of HaveIbeenPwned is not free anymore for checking accounts
hibp.checkPwnedName = false;
hibp.blockPwnedName = false;

module.exports.setSettings = function (changes) {
    for (const field in changes) {
        const ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        hibp[ccfield] = changes[field];
    }
};

module.exports.uninstall = function () {
    DetailsView.prototype.fieldChanged = detailsViewFieldChanged;
};
