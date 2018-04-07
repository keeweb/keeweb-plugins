/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const Logger = require('util/logger');
// change log level here. Should be changed to Info when issue #893 fixed on keeweb
const LogLevel = Logger.Level.Debug;

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
        // the 3 options with their default values
        this.checkPwnedPwd = HIBPCheckLevel.Alert;
        this.checkPwnedName = HIBPCheckLevel.Alert;
        this.checkPwnedList = false;
        // cache variables
        this._pwnedNamesCache = {};
        this._pwnedPwdsCache = {};
        // local logger
        this.logger = new Logger('HaveIBeenPwned');
        this.logger.setLevel(LogLevel);
    };
    // used for cyclic stringifier
    _replacer(key, value) {
        if (value != null && typeof value === 'object') {
            if (_seen.indexOf(value) >= 0) {
                return;
            }
            _seen.push(value);
        }
        return value;
    };
    // cyclic objects enabled stringifier
    stringify(obj) {
        const ret = JSON.stringify(obj, hibp._replacer);
        _seen = [];
        return ret;
    };
    // prints a stack trace in debug mode
    stackTrace() {
        const err = new Error();
        hibp.logger.debug(err.stack);
    }
    // show the details of an entry in debug mode
    showItem(model) {
        if (model) {
            hibp.logger.debug('show entry ' + model.title +
                ': name=' + model.user + ', pwd=' + (model.password ? model.password.getText() : 'undefined') +
                ', namePwned=' + model.namePwned + ', pwdPwned=' + model.pwdPwned
            );
        }
    }
    // XML HTTP Request with Promises, modified from StorageBase
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
    // transforms a byte array into an hex string
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
    // applies a digest algorithm and returns the corresponding hex string
    _digest(algo, str) {
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        return subtle.digest(algo, buffer).then(hash => {
            return hibp._hex(hash);
        });
    };
    // returns the SHA-1 hex string of the input string
    sha1(str) {
        return hibp._digest('SHA-1', str);
    };
    // returns the SHA-256 hex string of the input string
    sha256(str) {
        return hibp._digest('SHA-256', str);
    };
    // add css stuff + tip on fields to show an alert on pawned fields
    alert(el, msg) {
        hibp.logger.info(msg);
        el.focus();
        el.addClass('input--error');
        el.find('.details__field-value').addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' });
        InputFx.shake(el);
        // hibp.stackTrace();
    };
    // reset css stuff and tip on fields to remove alerts on pawned fields
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
    // store the cache variable name cacheName in local storage
    storeCache(cacheName) {
        // TODO: implement this method
    }
    // checks if the input name is pawned in breaches on haveibeenpwned.
    // Uses a cache to avoid calling hibp again and again with the same values
    // Returns a promise resolving to an html string containing a list of breaches names if pwned or null
    checkNamePwned (name) {
        hibp.logger.info('check hibp name ' + name);
        if (hibp._pwnedNamesCache[name]) {
            return Promise.resolve(hibp._pwnedNamesCache[name] !== '' ? hibp._pwnedNamesCache[name] : null);
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
                    hibp._pwnedNamesCache[name] = breaches || '';
                    if (breaches) hibp.logger.debug(`name ${name} pwned in ${breaches}`);
                    hibp.storeCache('_pwnedNamesCache');
                    return breaches;
                } else {
                    hibp._pwnedNamesCache[name] = '';
                    hibp.storeCache('_pwnedNamesCache');
                    return null;
                }
            });
        }
    };
    // checks if the input password (hashed in sha-1) is pawned in breaches on haveibeenpwned.
    // Uses a cache to avoid calling hibp again and again with the same values
    // Returns a promise resolving to a string containing the number of pwnages if pwned or null
    checkPwdPwned (passwordHash) {
        passwordHash = passwordHash.toUpperCase();
        hibp.logger.info('check hibp pwd (hash) ' + passwordHash);
        const prefix = passwordHash.substring(0, 5);
        if (hibp._pwnedPwdsCache[passwordHash]) {
            return (hibp._pwnedPwdsCache[passwordHash] !== ''
                ? hibp._pwnedPwdsCache[passwordHash] : null);
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
                hibp._pwnedPwdsCache[passwordHash] = nb || '';
                if (nb) hibp.logger.debug(`password ${passwordHash} pawned ${nb} times`);
                hibp.storeCache('_pwnedPwdsCache');
                return nb;
            });
        }
    };
    // returns true if the pwd can be checked
    elligiblePwd (pwd) {
        return (pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:'));
    }
    alertPwdPwned (dview, npwned, warning, args) {
        if (npwned) { // pwned
            // record pawnage in the model to be able to show it in list view
            dview.model.pwdPwned = npwned;
            // calls original function
            detailsViewFieldChanged.apply(dview, args);
            // sets the alert
            hibp.alert(dview.passEditView.$el, warning);
        } else { // not pwned
            // reset css and tip
            hibp.passed(dview.passEditView.$el, 'check pwned password passed...');
            // reset pawnage in the model
            dview.model.pwdPwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
    alertNamePwned (dview, breaches, warning, args) {
        if (breaches) { // pwned
            // remember breaches in the model to be able to show it in list view
            dview.model.namePwned = breaches;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
            // adds an alert
            hibp.alert(dview.userEditView.$el, warning);
        } else { // not pwned
            // reset alert
            hibp.passed(dview.userEditView.$el, 'check pwned user name passed...');
            // reset the model
            dview.model.namePwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
};

const hibp = new HIBPUtils();

// Replaces the fiedChanged function of DetailsView to add checks on user names and passwords
DetailsView.prototype.fieldChanged = function (e) {
    if (e.field) {
        // hibp.logger.debug('field changed ' + hibp.stringify(e));
        // first check password
        if (e.field === '$Password' && hibp.checkPwnedPwd !== HIBPCheckLevel.None && this.passEditView.value) {
            const pwd = e.val ? e.val.getText() : null;
            if (hibp.elligiblePwd(pwd)) {
                hibp.logger.debug('pwd:>>>' + pwd + '<<<');
                hibp.sha1(pwd)
                    .then(hibp.checkPwdPwned)
                    .then(npwned => {
                        const warning = HIBPLocale.hibpPwdWarning.replace('{}', npwned);
                        if (npwned) { // pawned
                            if (hibp.checkPwnedPwd === HIBPCheckLevel.AskMe) {
                                // ask before taking the field change into account
                                Alerts.yesno({
                                    header: HIBPLocale.hibpChangePwd,
                                    body: warning,
                                    icon: 'exclamation-triangle',
                                    success: () => { // keep password, just set an alert
                                        hibp.alertPwdPwned(this, npwned, warning, arguments);
                                    },
                                    cancel: () => { // reset password by not registering change
                                        hibp.logger.info('keeping old passwd');
                                    }
                                });
                            } else { // check level = alert, keep pwd, set an alert
                                hibp.alertPwdPwned(this, npwned, warning, arguments);
                            }
                        } else { // not pawned
                            hibp.alertPwdPwned(this, null, null, arguments);
                        }
                    }).catch(error => {
                        hibp.logger.info('check pwned password error: ' + error.message);
                    });
            } else {
                hibp.alertPwdPwned(this, null, null, arguments);
            }
            // second, check user name
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
                                        hibp.alertNamePwned(this, breaches, warning, arguments);
                                    },
                                    cancel: () => { // reset name by not registering change
                                        hibp.logger.info('keeping old user name');
                                    }
                                });
                            } else { // check level = alert, keep new name but sets an alert
                                hibp.alertNamePwned(this, breaches, warning, arguments);
                            }
                        } else { // not pawned
                            hibp.alertNamePwned(this, null, null, arguments);
                        }
                    }).catch(error => {
                        hibp.logger.info('check pwned name error: ' + error.message);
                    });
            }
        } else {
            hibp.alertNamePwned(this, null, null, arguments);
        }
    } else {
        detailsViewFieldChanged.apply(this, arguments);
    }
};

// replaces initial addFieldViews in DetailsView
// Allows showing pwned fields when displaying entry details
DetailsView.prototype.addFieldViews = function () {
    // call initial function
    detailsViewAddFieldViews.apply(this, arguments);
    // check password
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
    // check user name
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
