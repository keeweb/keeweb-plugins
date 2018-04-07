/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const Logger = require('util/logger');
// change log level here.
const LogLevel = Logger.Level.All;
// Strings that should be localized
const HIBPLocale = {
    hibpCheckPwnedPwd: 'Should I check passwords against HaveIBeenPwned list?',
    hibpCheckPwnedName: 'Should I check user name against HaveIBeenPwned list?',
    hibpCheckLevelNone: 'No thanks, don\'t check',
    hibpCheckLevelAlert: 'Yes and alert me if pwned',
    hibpCheckLevelAskMe: 'Yes and ask me if pwned',
    hibpCheckOnList: 'Show pawned entries on list',
    hibpPwdWarning: `WARNING! This password was used by {} pawned accounts referenced on <a href='https://haveibeenpwned.com'>https://haveibeenpwned.com</a>!`,
    hibpNameWarning: 'WARNING! The account named "{name}" has been pawned in the following breaches<br/>\n<ul>\n{breaches}\n</ul><p>Please check on <a href=\'https://haveibeenpwned.com\'>https://haveibeenpwned.com</a></p>',
    hibpChangePwd: 'Do you want to keep this new password?',
    hibpChangeName: 'Do you want to keep this new user name?',
    hibpApiError: 'HaveIBeenPwned API error'
};

const HIBPCheckLevel = {
    None: 'none',
    Alert: 'alert',
    AskMe: 'askme'
};

const DetailsView = require('views/details/details-view');
const ListView = require('views/list-view');
const AppModel = require('models/app-model');
const InputFx = require('util/input-fx');
const Kdbxweb = require('kdbxweb');
const _ = require('_');
const Tip = require('util/tip');
const Alerts = require('comp/alerts');

const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;
const detailsViewAddFieldViews = DetailsView.prototype.addFieldViews;
const listViewRender = ListView.prototype.render;
const appModelGetEntriesByFilter = AppModel.prototype.getEntriesByFilter;

let _seen = [];
class HIBPUtils {
    constructor() {
        _seen = [];
        this.checkPwnedPwd = HIBPCheckLevel.Alert;
        this.checkPwnedName = HIBPCheckLevel.Alert;
        this.checkPwnedList = false;
        this._pwnedNamesListChecked = {};
        this._pwnedPwdsListChecked = {};
        this.logger = new Logger('HaveIBeenPwned');
        this.logger.setLevel(LogLevel);
    };
    _replacer(key, value) {
        if (value != null && typeof value === 'object') {
            if (_seen.indexOf(value) >= 0) {
                return;
            }
            _seen.push(value);
        }
        return value;
    };
    stringify(obj) {
        const ret = JSON.stringify(obj, hibp._replacer);
        _seen = [];
        return ret;
    };
    _xhrpromise(config) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            if (config.responseType) {
                xhr.responseType = config.responseType;
            }
            const statuses = config.statuses || [200];
            xhr.open(config.method || 'GET', config.url);
            if (config.headers) {
                _.forEach(config.headers, (value, key) => {
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
                hibp.logger.error(HIBPLocale.hibpApiError, 'GET', xhr.status, err);
                reject(xhr.statusText);
            });
            xhr.send(config.data);
        });
    }
    _hex(buffer) {
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
    _digest(algo, str) {
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        return subtle.digest(algo, buffer).then(hash => {
            return hibp._hex(hash);
        });
    };
    sha1(str) {
        return hibp._digest('SHA-1', str);
    };
    sha256(str) {
        return hibp._digest('SHA-256', str);
    };
    stackTrace() {
        const err = new Error();
        hibp.logger.debug(err.stack);
    }
    alert(el, msg) {
        // Alerts.info({ body: msg, title: 'HaveIBeenPwned' });
        hibp.logger.info(msg);
        el.focus();
        el.addClass('input--error');
        el.find('.details__field-value').addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' }); // .show();
        InputFx.shake(el);
        // hibp.stackTrace();
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
    checkNamePwned (name) {
        hibp.logger.info('check hibp name ' + name);
        if (hibp._pwnedNamesListChecked[name]) {
            return Promise.resolve(hibp._pwnedNamesListChecked[name] !== '' ? hibp._pwnedNamesListChecked[name] : null);
        } else {
            name = encodeURIComponent(name);
            const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
            // hibp.logger.debug('url ' + url);
            return hibp._xhrpromise({
                url: url,
                method: 'GET',
                responseType: 'json',
                headers: null,
                data: null,
                statuses: [200, 404]
            }).then(data => {
                if (data && data.length > 0) {
                    hibp.logger.debug('found breaches ' + JSON.stringify(data));
                    let breaches = '';
                    data.forEach(breach => { breaches += '<li>' + _.escape(breach.Name) + '</li>\n'; });
                    hibp._pwnedNamesListChecked[name] = breaches || '';
                    if (breaches) hibp.logger.debug(`name ${name} pwned in ${breaches}`);
                    return breaches;
                } else {
                    hibp._pwnedNamesListChecked[name] = '';
                    return null;
                }
            });
        }
    };
    checkPwdPwned (passwordHash) {
        passwordHash = passwordHash.toUpperCase();
        hibp.logger.info('check hibp pwd (hash) ' + passwordHash);
        const prefix = passwordHash.substring(0, 5);
        if (hibp._pwnedPwdsListChecked[passwordHash]) {
            return (hibp._pwnedPwdsListChecked[passwordHash] !== ''
                ? hibp._pwnedPwdsListChecked[passwordHash] : null);
        } else {
            return hibp._xhrpromise({
                url: `https://api.pwnedpasswords.com/range/${prefix}`,
                method: 'GET',
                responseType: 'text',
                headers: null,
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
                hibp._pwnedPwdsListChecked[passwordHash] = nb || '';
                if (nb) hibp.logger.debug(`password ${passwordHash} pawned ${nb} times`);
                return nb;
            });
        }
    };
    elligiblePwd(pwd) {
        return (pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:'));
    }
    showItem(model) {
        if (model) {
            hibp.logger.debug('show entry ' + model.title +
                ': name=' + model.user + ', pwd=' + (model.password ? model.password.getText() : 'undefined') +
                ', namePwned=' + model.namePwned + ', pwdPwned=' + model.pwdPwned
            );
        }
    }
};

const hibp = new HIBPUtils();

DetailsView.prototype.fieldChanged = function (e) {
    if (e.field) {
        // hibp.logger.debug('field changed ' + hibp.stringify(e));
        if (e.field === '$Password' && hibp.checkPwnedPwd !== HIBPCheckLevel.None && this.passEditView.value) {
            let pwd = e.val.getText();
            if (typeof pwd !== 'string') pwd = pwd.getText();
            hibp.logger.debug('pwd:>>>' + pwd + '<<< obj=' + hibp.stringify(pwd));
            if (hibp.elligiblePwd(pwd)) {
                hibp.sha1(pwd)
                    .then(hibp.checkPwdPwned)
                    .then(npwned => { // pawned
                        if (npwned) {
                            const warning = HIBPLocale.hibpPwdWarning.replace('{}', npwned);
                            if (hibp.checkPwnedPwd === HIBPCheckLevel.AskMe) {
                                // ask before taking the field change into account
                                Alerts.yesno({
                                    header: HIBPLocale.hibpChangePwd,
                                    body: warning,
                                    icon: 'exclamation-triangle',
                                    success: () => { // keep password but set an alert
                                        this.model.pwdPwned = npwned;
                                        detailsViewFieldChanged.apply(this, arguments);
                                        hibp.alert(this.passEditView.$el, warning);
                                    },
                                    cancel: () => { // reset password by not registering change
                                        hibp.logger.info('keeping old passwd');
                                    }
                                });
                            } else { // check level = alert, keep pwd, set an alert
                                this.model.pwdPwned = npwned;
                                detailsViewFieldChanged.apply(this, arguments);
                                hibp.alert(this.passEditView.$el, warning);
                            }
                        } else { // not pawned
                            hibp.passed(this.passEditView.$el, 'check pwned password passed...');
                            this.model.pwdPwned = null;
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
            if (name && name.replace(/\s/, '') !== '') {
                hibp.checkNamePwned(name)
                    .then(breaches => {
                        if (breaches) { // pawned
                            name = _.escape(name); // breaches already escaped
                            const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                            if (hibp.checkPwnedName === HIBPCheckLevel.AskMe) {
                                // ask before taking the field change into account
                                Alerts.yesno({
                                    header: HIBPLocale.hibpChangeName,
                                    body: warning,
                                    icon: 'exclamation-triangle',
                                    success: () => { // keep name, but set an alert
                                        this.model.namePwned = breaches;
                                        detailsViewFieldChanged.apply(this, arguments);
                                        hibp.alert(this.userEditView.$el, warning);
                                    },
                                    cancel: () => { // reset name by not registering change
                                        hibp.logger.info('keeping old user name');
                                    }
                                });
                            } else { // check level = alert, keep new name but sets an alert
                                this.model.namePwned = breaches;
                                detailsViewFieldChanged.apply(this, arguments);
                                hibp.alert(this.userEditView.$el, warning);
                            }
                        } else { // not pawned
                            hibp.passed(this.userEditView.$el, 'check pwned user name passed...');
                            this.model.namePwned = null;
                            detailsViewFieldChanged.apply(this, arguments);
                        }
                    }).catch(error => {
                        hibp.logger.info('check pwned name error: ' + error.message);
                    });
            }
        } else {
            detailsViewFieldChanged.apply(this, arguments);
        }
    } else {
        detailsViewFieldChanged.apply(this, arguments);
    }
};

DetailsView.prototype.addFieldViews = function () {
    detailsViewAddFieldViews.apply(this, arguments);
    const pwd = this.model.password ? this.model.password.getText() : null;
    // hibp.logger.debug('addfv pwd:>>>' + pwd + '<<<');
    if (hibp.checkPwnedPwd !== HIBPCheckLevel.None && hibp.elligiblePwd(pwd)) {
        hibp.sha1(pwd)
            .then(hibp.checkPwdPwned)
            .then(npwned => {
                this.model.pwdPwned = npwned;
                if (npwned) { // pawned
                    const warning = HIBPLocale.hibpPwdWarning.replace('{}', npwned);
                    hibp.alert(this.passEditView.$el, warning);
                } else { // not pawned
                    hibp.passed(this.passEditView.$el, 'check pwned password passed...');
                }
            }).catch(error => {
                hibp.logger.info('check pwned pwd error: ' + error);
            });
    }
    let name = this.userEditView.value;
    // hibp.logger.debug('addfv name:>>>' + name + '<<<');
    if (name && name.replace(/\s/, '') !== '' && hibp.checkPwnedName !== HIBPCheckLevel.None) {
        hibp.checkNamePwned(name)
            .then(breaches => {
                this.model.namePwned = breaches;
                if (breaches) { // pawned
                    name = _.escape(name); // breaches already escaped
                    const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                    hibp.alert(this.userEditView.$el, warning);
                } else { // not pawned
                    hibp.passed(this.userEditView.$el, 'check pwned user name passed...');
                }
            }).catch(error => {
                hibp.logger.info('check pwned name error: ' + hibp.stringify(error));
            });
    }
};

ListView.prototype.render = function () {
    listViewRender.apply(this, arguments);
    hibp.logger.debug('rendering list in hibp');
    // this.items.forEach(hibp.showItem);
    this.items.filter(item => item.namePwned || item.pwdPwned).forEach(item => {
        hibp.logger.debug('list pwned ' + item.title);
        const itemEl = document.getElementById(item.id);
        if (itemEl) { itemEl.classList.add('hibp-pwned'); }
    });
};

AppModel.prototype.getEntriesByFilter = function (filter) {
    const entries = appModelGetEntriesByFilter.apply(this, arguments);
    /*    const names = {};
    const pwds = {};

    if (hibp.checkPwnedList && entries && entries.length) {
        hibp.logger.debug('getEntriesByFilter');
        entries.forEach(item => {
            hibp.logger.debug('getEntriesByFilter: item = ' + item.title);
            // get different user names and pwds to optimize queries
            const name = item.user;
            if (name !== '') {
                if (names[name]) names[name].push(item);
                else names[name] = [item];
            }
            let pwd = item.password;
            if (pwd) {
                // hibp.logger.debug(`getEntriesByFilter: pwd=${pwd}`);
                pwd = pwd.getText();
                if (pwds[pwd]) pwds[pwd].push(item);
                else pwds[pwd] = [item];
            }
        });
        // asynchronously look for pawned names
        setTimeout(() => {
            Object.entries(names).forEach(([name, items]) => {
                hibp.logger.debug('getEntriesByFilter: check name ' + name);
                hibp.checkNamePwned(name)
                    .then(breaches => {
                        items.forEach(item => { item.namePwned = breaches; });
                        if (breaches) this.refresh();
                    });
            });
        }, 20);
        // asynchronously look for pawned pwds
        setTimeout(() => {
            Object.entries(pwds).forEach(([pwd, items]) => {
                hibp.logger.debug('getEntriesByFilter: check pwd ' + pwd);
                hibp.sha1(pwd)
                    .then(hibp.checkPwdPwned)
                    .then(nb => {
                        items.forEach(item => { item.pwdPwned = nb; });
                        if (nb) this.refresh();
                    });
            });
        }, 20);
    }
    */
    if (hibp.checkPwnedList && entries && entries.length) {
        // asynchronously look for pawned names and pwds
        setTimeout(() => {
            entries.forEach(item => {
                hibp.logger.debug('getEntriesByFilter: check item ' + item.title);
                hibp.checkNamePwned(item.user)
                    .then(breaches => {
                        const itemPwned = item.namePwned;
                        item.namePwned = breaches;
                        if (!breaches !== !itemPwned) { // XOR
                            this.refresh();
                        }
                    });
                const pwd = item.password ? item.password.getText() : null;
                if (hibp.elligiblePwd(pwd)) {
                    hibp.sha1(pwd)
                        .then(hibp.checkPwdPwned)
                        .then(nb => {
                            const itemPwned = item.pwdPwned;
                            item.pwdPwned = nb;
                            if (!nb !== !itemPwned) { // XOR
                                this.refresh();
                            }
                        });
                }
            });
        }, 20);
    }
    return entries;
};

// for debug purpose
// const dvrender = DetailsView.prototype.render;
// DetailsView.prototype.render = function () {
//     dvrender.apply(this, arguments);
//     hibp.showItem(this.model);
// },

module.exports.getSettings = function () {
    const options = [
        { value: HIBPCheckLevel.None, label: HIBPLocale.hibpCheckLevelNone },
        { value: HIBPCheckLevel.Alert, label: HIBPLocale.hibpCheckLevelAlert },
        { value: HIBPCheckLevel.AskMe, label: HIBPLocale.hibpCheckLevelAskMe }
    ];
    return [
        {
            name: 'checkPwnedPwd',
            label: HIBPLocale.hibpCheckPwnedPwd,
            type: 'select',
            options: options,
            value: hibp.checkPwnedPwd
        }, {
            name: 'checkPwnedName',
            label: HIBPLocale.hibpCheckPwnedName,
            type: 'select',
            options: options,
            value: hibp.checkPwnedName
        }, {
            name: 'checkPwnedList',
            label: HIBPLocale.hibpCheckOnList,
            type: 'checkbox',
            value: hibp.checkPwnedList
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
    ListView.prototype.render = listViewRender;
    AppModel.prototype.getEntriesByFilter = appModelGetEntriesByFilter;
};
