/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const HIBPCheckLevel = {
    None: 'none',
    Alert: 'alert',
    AskMe: 'askme'
};

const Logger = require('util/logger');
// change log level here.
const LogLevel = Logger.Level.All;

const DetailsView = require('views/details/details-view');
const InputFx = require('util/input-fx');
const Kdbxweb = require('kdbxweb');
const _ = require('_');
const Tip = require('util/tip');
const Alerts = require('comp/alerts');

const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;
const detailsViewAddFieldViews = DetailsView.prototype.addFieldViews;
let _seen = [];
class HIBPUtils {
    constructor() {
        _seen = [];
        this.checkPwnedPwd = HIBPCheckLevel.Alert;
        this.checkPwnedName = HIBPCheckLevel.Alert;
        this.logger = new Logger('HaveIBeenPwned');
        this.logger.setLevel(LogLevel);
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
    xhrpromise(config) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            if (config.responseType) {
                xhr.responseType = config.responseType;
            }
            const statuses = config.statuses || [200];
            xhr.open(config.method || 'GET', config.url);
            if (config.headers) {
                config.headers.forEach((value, key) => {
                    xhr.setRequestHeader(key, value);
                });
            };
            xhr.addEventListener('load', () => {
                if (statuses.indexOf(xhr.status) >= 0) {
                    resolve(xhr.response);
                } else {
                    reject(xhr.statusText);
                }
            });
            xhr.addEventListener('error', () => {
                const err = xhr.response && xhr.response.error || new Error('Network error');
                this.logger.error('HaveIBeenPwned API error', 'GET', xhr.status, err);
                reject(xhr.statusText);
            });
            xhr.send(config.data);
        });
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
    };
    digest(algo, str) {
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
    alert(el, msg) {
        // Alerts.info({ body: msg, title: 'HaveIBeenPwned' });
        hibp.logger.info(msg);
        el.focus();
        el.addClass('input--error');
        el.find('.details__field-value').addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' }); // .show();
        InputFx.shake(el);
        var err = new Error();
        hibp.logger.debug(err.stack);
    };
    passed(el, msg) {
        hibp.logger.info(msg);
        el.removeClass('input--error');
        el.find('.details__field-value').removeClass('hibp-pwned');
        const tip = el._tip;
        if (tip) {
            tip.hide();
            tip.title = null;
        }
    }
};

const hibp = new HIBPUtils();

DetailsView.prototype.checkNamePwned = function (name) {
    hibp.logger.info('check hibp name ' + name);
    name = encodeURIComponent(name);
    const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
    // hibp.logger.debug('url ' + url);
    return hibp.xhrpromise({
        url: url,
        method: 'GET',
        responseType: 'json',
        headers: undefined,
        data: null,
        statuses: [200, 404]
    }).then(data => {
        if (data && data.length > 0) {
            hibp.logger.debug('found breaches ' + JSON.stringify(data));
            let breaches = '';
            data.forEach(breach => { breaches += '<li>' + _.escape(breach.Name) + '</li>\n'; });
            return breaches;
        } else return null;
    });
};

DetailsView.prototype.checkPwdPwned = function (passwordHash) {
    passwordHash = passwordHash.toUpperCase();
    hibp.logger.info('check hibp pwd (hash) ' + passwordHash);
    const prefix = passwordHash.substring(0, 5);
    return hibp.xhrpromise({
        url: `https://api.pwnedpasswords.com/range/${prefix}`,
        method: 'GET',
        responseType: 'text',
        headers: undefined,
        data: null,
        statuses: [200, 404]
    }).then(data => {
        let nb = null;
        if (data) {
            // hibp.logger.debug('found breaches ' + JSON.stringify(data));
            data.split('\r\n').some(line => {
                const h = line.split(':');
                const suffix = h[0];
                if (prefix + suffix === passwordHash) {
                    nb = _.escape(h[1]);
                    // hibp.logger.debug('matching breach ' + suffix);
                    return true;
                }
            });
        }
        hibp.logger.debug('pawned:' + nb);
        return nb;
    });
};

DetailsView.prototype.fieldChanged = function (e) {
    if (e.field) {
        // hibp.logger.debug('field changed ' + hibp.stringify(e));
        if (e.field === '$Password' && hibp.checkPwnedPwd !== HIBPCheckLevel.None && this.passEditView.value) {
//            const oldpwd = this.model.entry.fields.Password || Kdbxweb.ProtectedValue.fromString('');
            let pwd = e.val.getText();
            if (typeof pwd !== 'string') pwd = pwd.getText();
//            hibp.logger.debug('pwd:>>>' + pwd + '<<< (obj=' + hibp.stringify(pwd) + ') oldpwd:>>>' + oldpwd + '<<<');
            hibp.logger.debug('pwd:>>>' + pwd + '<<< obj=' + hibp.stringify(pwd));
            if (pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:')) {
                hibp.sha1(pwd)
                    .then(this.checkPwdPwned)
                    .then(res => { // pawned
                        if (res) {
                            const warning = `WARNING: This password is referenced as pawned ${res} times on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>!`;
                            if (hibp.checkPwnedPwd === HIBPCheckLevel.AskMe) {
                                // ask before taking the field change into account
                                let ok = false;
                                Alerts.yesno({
                                    header: 'Revert to previous password?',
                                    body: warning,
                                    icon: 'exclamation-triangle',
                                    cancel: () => { // keep password but set an alert
                                        if (!ok) {
                                            detailsViewFieldChanged.apply(this, arguments);
                                            hibp.alert(this.passEditView.$el, warning);
                                        }    
                                    },
                                    success: () => { // reset password
                                        hibp.logger.info('keeping old passwd');
                                        ok = true;
 //                                       this.model.setField('Password', oldpwd);
                                    }
                                });
                            } else { // check level = alert, keep pwd, set an alert
                                detailsViewFieldChanged.apply(this, arguments);
                                hibp.alert(this.passEditView.$el, warning);
                            }
                        } else { // not pawned
                            hibp.passed(this.passEditView.$el, 'check pwned password passed...');
                            detailsViewFieldChanged.apply(this, arguments);
                        }
                    }).catch(error => {
                        hibp.logger.info('check pwned password error: ' + error.message);
                    });
            } else {
                detailsViewFieldChanged.apply(this, arguments);
            }
        } else if (e.field === '$UserName' && hibp.checkPwnedName !== HIBPCheckLevel.None) {
            let name = e.val;
            if (name && name.replace(/\s/, '') !== '')
                this.checkNamePwned(name)
                    .then(res => {
                        if (res) {  // pawned
                            name = _.escape(name); // res already escaped
                            const warning = `WARNING! The account named "${name}" has been pawned in the following breaches<br/>
                        <ul>
                        ${res}
                        </ul>
                        <p>Please check on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a></p>`;
                            if (hibp.checkPwnedName === HIBPCheckLevel.AskMe) {
                                // ask before taking the field change into account
                                Alerts.yesno({
                                    header: 'Revert to previous user name ?',
                                    body: warning,
                                    icon: 'exclamation-triangle',
                                    cancel: res => { // keep name, but set an alert
                                        hibp.logger.debug('cancel: ' + res);
                                        detailsViewFieldChanged.apply(this, arguments);
                                        hibp.alert(this.userEditView.$el, warning);
                                    },
                                    success: () => { // reset name by not registering change
                                        hibp.logger.info('keeping old user name');
                                    }
                                });
                            } else { // check level = alert, keep new name but sets an alert
                                detailsViewFieldChanged.apply(this, arguments);
                                hibp.alert(this.userEditView.$el, warning);
                            }
                        } else { // not pawned
                            hibp.passed(this.userEditView.$el, 'check pwned user name passed...');
                            detailsViewFieldChanged.apply(this, arguments);
                        }
                    }).catch(error => {
                        hibp.logger.info('check pwned name error: ' + error.message);
                    });
        } else {
            detailsViewFieldChanged.apply(this, arguments);
        }
    } else {
        detailsViewFieldChanged.apply(this, arguments);
    }
};

DetailsView.prototype.addFieldViews = function () {
    detailsViewAddFieldViews.apply(this, arguments);
    let pwd = this.model.entry.fields.Password;
    if (typeof pwd !== 'string') pwd = pwd.getText();
    hibp.logger.debug('addfv pwd:>>>' + pwd + '<<<');
    if (hibp.checkPwnedPwd !== HIBPCheckLevel.None && pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:')) {
        hibp.sha1(pwd)
            .then(this.checkPwdPwned)
            .then(res => {
                if (res) { // pawned
                    const warning = `WARNING: This password is referenced as pawned ${res} times on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>!`;
                    hibp.alert(this.passEditView.$el, warning);
                } else { // not pawned
                    hibp.passed(this.passEditView.$el, 'check pwned password passed...');
                }
            }).catch(error => {
                hibp.logger.info('check pwned password error: ' + error.message);
            });
    }
    let name = this.userEditView.value;
    hibp.logger.debug('addfv name:>>>' + name + '<<<');
    if (name && name.replace(/\s/, '') !== '' && hibp.checkPwnedName !== HIBPCheckLevel.None) {
        this.checkNamePwned(name)
            .then(res => {
                if (res) {  // pawned
                    name = _.escape(name); // res already escaped
                    const warning = `WARNING! The account named "${name}" has been pawned in the following breaches<br/>
                        <ul>
                        ${res}
                        </ul>
                        <p>Please check on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a></p>`;
                    hibp.alert(this.userEditView.$el, warning);
                } else { // not pawned
                    hibp.passed(this.userEditView.$el, 'check pwned user name passed...');
                }
            }).catch(error => {
                hibp.logger.info('check pwned name error: ' + error.message);
            });
    }
};

module.exports.getSettings = function () {
    const options = [
        { value: HIBPCheckLevel.None, label: 'No thanks, don\'t check' },
        { value: HIBPCheckLevel.Alert, label: 'Yes and alert me if pwned' },
        { value: HIBPCheckLevel.AskMe, label: 'Yes and ask me if pwned' }
    ];
    return [
        {
            name: 'checkPwnedPwd',
            label: 'Should I check passwords against HaveIBeenPwned list?',
            type: 'select',
            options: options,
            value: hibp.checkPwnedPwd
        }, {
            name: 'checkPwnedName',
            label: 'Should I check user name against HaveIBeenPwned list?',
            type: 'select',
            options: options,
            value: hibp.checkPwnedName
        }
    ];
};

module.exports.setSettings = function (changes) {
    for (const field in changes) {
        const ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        hibp[ccfield] = changes[field];
    }
    hibp.logger.debug(hibp.stringify(hibp));
};

module.exports.uninstall = function () {
    DetailsView.prototype.fieldChanged = detailsViewFieldChanged;
    DetailsView.prototype.addFieldViews = detailsViewAddFieldViews;
};
