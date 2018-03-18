/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const DetailsView = require("views/details/details-view");
const Alerts = require("comp/alerts");
const Logger = require('util/logger');
const InputFx = require('util/input-fx');

const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;

DetailsView.prototype.checkPwnedPwd = false;
DetailsView.prototype.checkPwnedName = false;
DetailsView.prototype.blockPwnedPwd = false;
DetailsView.prototype.blockPwnedName = false;
DetailsView.prototype.logger = new Logger("HaveIBeenPwned");

DetailsView.prototype._alert = function (msg) {
    Alerts.info({ body: msg, title: "HaveIBeenPwned" });
}

DetailsView.prototype.checkPwnedOnSettingsChanged = function (changes) {
    //if (changes['CheckPwnedPwd'] || changes['CheckPwnedName'] || changes['CheckPwnedName'] || changes['CheckPwnedName']) {
    // info('Full HaveIBeenPwned check not yet implemented. Checks are done one by one when you change a name or a password.');
    //}
};

seen = [];
class HIBPUtils {
    constructor() {
        seen = [];
    }

    replacer(key, value) {
        if (value != null && typeof value == "object") {
            if (seen.indexOf(value) >= 0) {
                return;
            }
            seen.push(value);
        }
        return value;
    }
    stringify(obj) {
        var ret = JSON.stringify(obj, this.replacer);
        seen = [];
        return ret;
    }
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
        if (config.headers) config.headers.forEach((value, key) => {
            xhr.setRequestHeader(key, value);
        });
        xhr.send(config.data);
    };

    hex (buffer) {
        var hexCodes = [];
        var view = new DataView(buffer);
        for (var i = 0; i < view.byteLength; i += 4) {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            var value = view.getUint32(i)
            // toString(16) will give the hex representation of the number without padding
            var stringValue = value.toString(16)
            // We use concatenation and slice for padding
            var padding = '00000000'
            var paddedValue = (padding + stringValue).slice(-padding.length)
            hexCodes.push(paddedValue);
        }

        // Join all the hex strings into one
        return hexCodes.join("");
    }

    digest(algo, str) {
        // We transform the string into an arraybuffer.
        const buffer = new TextEncoder("utf-8").encode(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        var _self = this;
        return crypto.subtle.digest(algo, buffer).then(function (hash) {
            return _self.hex(hash);
        });        
    }


    sha1(str) {
        return this.digest("SHA-1", str);
    }

    sha256(str) {
        return this.digest("SHA-256", str);
    }
}

DetailsView.prototype.checkNamePwned = function (name) {
    this.logger.info('check hibp name ' + name);
    name = encodeURIComponent(name);
    const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
    this.logger.info('url ' + url);
    new HIBPUtils().xhrcall({
        url: url,
        method: 'GET',
        responseType: 'json',
        headers: undefined,
        data: null,
        statuses: [200, 404],
        success: (data, xhr) => {
            this.logger.info('xhr ' + JSON.stringify(xhr));
            if (data && data.length > 0) {
                this.logger.info('found breaches ' + JSON.stringify(data));
                var breaches = "";
                data.forEach(breach => { breaches += `<li>${breach.Name}</li>\n`; });
                this._alert(`WARNING! This account has been pawned in the following breaches<br/>\n<ul>\n${breaches}\n</ul>\n<p>Please check on <a href="https://haveibeenpwned.com">https://haveibeenpwned.com</a>\n`);
                this.userEditView.$el.focus();
                this.userEditView.$el.addClass('input--error');
                InputFx.shake(this.userEditView.$el);
            } else {
                this.logger.info("check pwnd name passed...");
                this.userEditView.$el.removeClass('input--error');
            }
        },
        error: (e, xhr) => {
            let err = xhr.response && xhr.response.error || new Error('Network error');
            this.logger.error('Pwned Password API error', 'GET', xhr.status, err);
            err.status = xhr.status;
        }
    });   
};

DetailsView.prototype.checkPwdPwned = function (passwordHash) {
    this.logger.info('check hibp pwd (hash) ' + passwordHash);
    
    prefix = passwordHash.substring(0, 5);
    new HIBPUtils().xhrcall({
        url: `https://api.pwnedpasswords.com/range/${prefix}`,
        method: 'GET',
        responseType: 'text',
        headers: undefined,
        data: null,
        statuses: [200, 404],
        success: data => {
            if (data) {
                this.logger.info('found breaches ' + JSON.stringify(data));
                data.split('\r\n').forEach(line => {
                    h = line.split(':');
                    suffix = h[0]; nb = h[1];
                    if (prefix + suffix === passwordHash) {
                        this._alert(`WARNING: This password is referenced as pawned ${nb} times on <a href="https://haveibeenpwned.com">https://haveibeenpwned.com</a>!\n`);
                        this.passEditView.$el.focus();
                        this.passEditView.$el.addClass('input--error');
                        InputFx.shake(this.passEditView.$el);
                    }
                });
            } else {
                this.logger.info("check pwnd passwd passed...");
                this.passEditView.$el.removeClass('input--error');
            }    
        },
        error: (e, xhr) => {
            let err = xhr.response && xhr.response.error || new Error('Network error');
            this.logger.error('Pwned Password API error', 'GET', xhr.status, err);
            err.status = xhr.status;
        }
    });
};

DetailsView.prototype.fieldChanged = function (e) {
    //this.logger.info('field changed ' + new HIBPUtils().stringify(e));
    detailsViewFieldChanged.apply(this, [e]);
    if (e.field) {
        if (e.field === '$Password' && this.checkPwnedPwd) {
            if (this.passEditView.value) {
                const pwd = this.passEditView.value.getText();
                if (pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:')) {
                    new HIBPUtils().sha1(pwd).then(hash => {
                        this.checkPwdPwned(hash.toUpperCase());
                    });
                }
            }
        } else if (e.field === '$UserName' && this.checkPwnedName) {
            this.checkNamePwned(e.val);
        }
    }
};

module.exports.getSettings = function () {
    return [{
        name: 'checkPwnedPwd',
        label: 'Check passwords against HaveIBeenPwned list',
        type: 'checkbox',
        value: 'true'
    }, {
        name: 'checkPwnedName',
        label: 'Check user ids against HaveIBeenPwned list',
        type: 'checkbox',
        value: 'true'
    }, {
        name: 'blockPwnedPwd',
        label: 'Block pwned passwords if they are in HaveIBeenPwned list',
        type: 'checkbox',
        value: 'true'
    }, {
        name: 'blockPwnedName',
        label: 'Block pwned names if they are in HaveIBeenPwned list',
        type: 'checkbox',
        value: 'true'
    }];
};

module.exports.setSettings = function (changes) {
    // apply changed settings in plugin logic
    // this method will be called:
    // 1. when any of settings fields is modified by user
    // 2. after plugin startup, with saved values
    // only changed settings will be passed

    // example: { MyText: 'value', MySel: 'selected-value', MyCheckbox: true }
    // info(JSON.stringify(changes));
    s = ''
    for (field in changes) {
        ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        DetailsView.prototype[ccfield] = changes[field];
        //s += ccfield + '=' + DetailsView.prototype[ccfield] + '; ';
    }
    DetailsView.prototype.checkPwnedOnSettingsChanged.apply(changes);
    //alert(s);
};

module.exports.uninstall = function () {
    fieldChanged = detailsViewFieldChanged;
};
