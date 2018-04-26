/**
 * KeeWeb plugin: haveibeenpwned
 * @author Olivier LEVILLAIN
 * @license MIT
 */

const Logger = require('util/logger');
/**
 * local logger
 * @type {Logger}
 */
const hLogger = new Logger('HaveIBeenPwned');
/** change log level here. Should be changed to Info when issue #893 fixed on keeweb */
hLogger.setLevel(Logger.Level.Debug);

/**
 * Cache time to live
 * Set to 14 days (in milliseconds)
 * @type {number}
 */
const CacheTTL = 1000 * 3600 * 24 * 14;

/** Strings that should be localized */
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

/** What chcking level to use
 * None: no checking
 * Alert: Draw an alert near the pawned item
 * AskMe: Interactively ask me to revert to the previous value if pawned
 */
const HIBPCheckLevel = {
    None: 'none',
    Alert: 'alert',
    AskMe: 'askme'
};

/** Required modules */
const DetailsView = require('views/details/details-view');
const ListView = require('views/list-view');
const AppModel = require('models/app-model');
const InputFx = require('util/input-fx');
const Kdbxweb = require('kdbxweb');
const _ = require('_');
const Tip = require('util/tip');
const Alerts = require('comp/alerts');
const StorageBase = require('storage/storage-base');
const IoBrowserCache = require('storage/io-browser-cache');

/** Keeps track of 4 replaced methods */
const detailsViewFieldChanged = DetailsView.prototype.fieldChanged;
const detailsViewAddFieldViews = DetailsView.prototype.addFieldViews;
const listViewRender = ListView.prototype.render;
const appModelGetEntriesByFilter = AppModel.prototype.getEntriesByFilter;

/**
 * Storage cache based on IoBrowserCache.
 * Inspired from storage-cache.js with a specific config
 * TODO: test this cache in Desktop app
 */
class StorageCache extends StorageBase {
    constructor() {
        super();
        this.name = 'cache';
        this.enabled = IoBrowserCache.enabled;
        this.system = true;
        this.init(); // storage base
        this.io = new IoBrowserCache({
            cacheName: 'HIBPCache',
            logger: hLogger
        });
    };

    save(id, data, callback) {
        this.io.save(id, data, callback);
    };
    load(id, callback) {
        this.io.load(id, callback);
    };
    remove(id, callback) {
        this.io.remove(id, callback);
    }
};

let _seen = [];
const HIBPUtils = {
    /**
     * cyclic objects enabled stringifier
     * @param {object} obj the object to be stringified
     * @returns {string} the stringified object
     */
    stringify: (obj) => {
        const ret = JSON.stringify(obj, (key, value) => {
            if (value != null && typeof value === 'object') {
                if (_seen.indexOf(value) >= 0) {
                    return;
                }
                _seen.push(value);
            }
            return value;
        });
        _seen = [];
        return ret;
    },
    /**
     * writes the stingified object on the console if in debug mode
     * @param {object} obj the object to be dumped
     */
    dump: (obj) => {
        hLogger.debug(HIBPUtils.stringify(obj));
    },
    /**
     * Prints a stack trace in debug mode
     */
    stackTrace: () => {
        const err = new Error();
        hLogger.debug(err.stack);
    },
    /**
     * XML HTTP Request with Promises,
     * modified from StorageBase
     * @param {object} config the XML HTTP Request configuration. Same as StorageBase
     * @returns {Promise}
     */
    xhrpromise: (config) => {
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
                    hLogger.error(HIBPLocale.hibpApiError, 'GET', xhr.status, xhr.statusText);
                    reject(xhr.statusText);
                }
            });
            xhr.addEventListener('error', () => {
                const err = xhr.response && xhr.response.error || new Error('Network error');
                hLogger.error(HIBPLocale.hibpApiError, 'GET', xhr.status, err);
                reject(xhr.statusText);
            });
            xhr.send(config.data);
        });
    },
    /**
     * Applies a digest algorithm on input string
     * @param {algo} algorithm to be applied (e.g. 'SHA-1' 'SHA-2456'
     * @returns {string} the "digested" hex string
     */
    digest: (algo, str) => {
        const buffer = Kdbxweb.ByteUtils.stringToBytes(str);
        const subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        return subtle.digest(algo, buffer).then(buffer => {
            // transforms the buffer into an hex string
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
        });
    }
};

/**
 * This is were most HaveIBeenPwned stuff lies.
 */
class HIBP {
    constructor() {
        // the 3 options with their default values
        this.checkPwnedPwd = HIBPCheckLevel.Alert;
        this.checkPwnedName = HIBPCheckLevel.Alert;
        this.checkPwnedList = false;
        // cache variables
        this._pwnedNamesCache = {};
        this._pwnedPwdsCache = {};
        // cache manager
        this.cache = new StorageCache();
        this.loadCache('_pwnedNamesCache');
        this.loadCache('_pwnedPwdsCache');
    }
    /**
     * Show the details of an entry in debug mode
     * @param {Entry} entry the entry to be shown
     */
    showItem(entry) {
        if (entry) {
            hLogger.debug('show entry ' + entry.title +
                ': name=' + entry.user + ', pwd=' + (entry.password ? entry.password.getText() : 'undefined') +
                ', namePwned=' + entry.namePwned + ', pwdPwned=' + entry.pwdPwned
            );
        }
    }
    /**
     * Add css stuff + tip on fields to show an alert on pawned fields
     * @param {Element} el the HTML element of the field
     * @param {string} msg the message to print in the tip
     */
    alert(el, msg) {
        hLogger.info(msg);
        el.focus();
        el.addClass('input--error');
        el.find('.details__field-value').addClass('hibp-pwned');
        Tip.createTip(el, { title: msg, placement: 'bottom' });
        InputFx.shake(el);
    };
    /**
     * Reset css stuff and tip on fields to remove alerts on pawned fields
     * @param {Element} el the HTML element of the field
     * @param {string} msg the message to print in the console
     */
    passed(el, msg) {
        hLogger.info(msg);
        el.removeClass('input--error');
        el.find('.details__field-value').removeClass('hibp-pwned');
        const tip = el._tip;
        if (tip) {
            tip.hide();
            tip.title = null;
        }
    }
    /**
     * Store the desired cache in local storage
     * @param {string} cacheVarName the name of the cache variable ('_pwnedNamesCache' or '_pwnedPwdsCache')
     */
    storeCache(cacheVarName) {
        this.cache.save(cacheVarName, this[cacheVarName], (err) => {
            if (err) {
                hLogger.error('can\'t store cache ' + cacheVarName + ': ' + err);
            }
        });
    }
    /**
     * Load desired cache from local storage
     * Values older than CacheTTL are discarded
     * @param {string} cacheVarName the name of the cache variable ('_pwnedNamesCache' or '_pwnedPwdsCache')
     */
    loadCache(cacheVarName) {
        this.cache.load(cacheVarName, (err, res) => {
            if (err) {
                hLogger.info('can\'t load cache ' + cacheVarName + ': ' + err);
            } else {
                // check each element to remove too old ones
                for (const key in res) {
                    const value = res[key];
                    const diff = Date.now() - value.date; // cache age in millisec
                    if (diff < CacheTTL) {
                        this[cacheVarName][key] = value;
                    } else {
                        hLogger.info('cache too old for ' + cacheVarName + '.' + key);
                        this[cacheVarName][key] = undefined;
                    }
                    // HIBPUtils.dump(this);
                }
            }
        });
    }
    /**
     * true if cached element exist and is not too old
     * @param {string} cachedElem the cache element to check
     * @returns {boolean}
     */
    checkCache(cachedElem) {
        return (cachedElem && (Date.now() - cachedElem.date) < CacheTTL);
    }
    /**
     * Computes and returns the SHA1 hash of a string
     * @param {string} str the input string
     * @returns {string} the SHA-1 hex string of the input string
     */
    sha1(str) {
        return HIBPUtils.digest('SHA-1', str);
    };
    /**
     * Computes and returns the SHA256 hash of a string
     * @param {string} str the input string
     * @returns {string} the SHA-256 hex string of the input string
     */
    sha256(str) {
        return HIBPUtils.digest('SHA-256', str);
    };
    /**
     * Checks if the input name is pawned in breaches on haveibeenpwned.
     * Uses a cache to avoid calling hibp again and again with the same values
     * @param {string} name the name to check
     * @returns {Promise} a promise resolving to an html string containing a list of breaches names if pwned, or null
     */
    checkNamePwned (uname) {
        hLogger.debug('checking user name ' + uname);
        const name = encodeURIComponent(uname);
        if (this.checkCache(this._pwnedNamesCache[name])) {
            hLogger.debug(' user name found in cache: ' + name);
            return Promise.resolve(this._pwnedNamesCache[name].val);
        } else {
            hLogger.debug('USER NAME NOT FOUND in cache: ' + name); // + ' cache=' + this.stringify(this._pwnedNamesCache));
            const url = `https://haveibeenpwned.com/api/v2/breachedaccount/${name}?truncateResponse=true`;
            // hLogger.debug('url ' + url);
            return HIBPUtils.xhrpromise({
                url: url,
                method: 'GET',
                responseType: 'json',
                headers: null,
                data: null,
                statuses: [200, 404]
            }).then(data => {
                let breaches = null;
                if (data && data.length > 0) {
                    // hLogger.debug('found breaches ' + JSON.stringify(data));
                    breaches = '';
                    data.forEach(breach => { breaches += '<li>' + _.escape(breach.Name) + '</li>\n'; });
                }
                this._pwnedNamesCache[name] = { date: Date.now(), val: breaches };
                if (breaches) hLogger.info(`name ${name} pwned in ${breaches}`);
                this.storeCache('_pwnedNamesCache');
                return breaches;
            });
        }
    };
    /**
     * Checks if the input password (hashed in sha-1) is pawned in breaches on haveibeenpwned.
     * Uses a cache to avoid calling hibp again and again with the same values
     * @param { string } pwd the sha1 hashed password to check
     * @returns { Promise } a promise resolving to the number of pwnages if pwned or null
     */
    checkPwdPwned (passwordHash) {
        passwordHash = passwordHash.toUpperCase();
        hLogger.debug('checking pwd (hashed) ' + passwordHash);
        const prefix = passwordHash.substring(0, 5);
        if (this.checkCache(this._pwnedPwdsCache[passwordHash])) {
            const val = this._pwnedPwdsCache[passwordHash].val ? this._pwnedPwdsCache[passwordHash].val : null;
            hLogger.debug('found pwd in cache: ' + passwordHash + ' val:' + val);
            return Promise.resolve(val);
        } else {
            hLogger.debug('PWD NOT FOUND in cache: ' + passwordHash); // + ' cache=' + this.stringify(this._pwnedPwdsCache));
            return HIBPUtils.xhrpromise({
                url: `https://api.pwnedpasswords.com/range/${prefix}`,
                method: 'GET',
                responseType: 'text',
                headers: null,
                data: null,
                statuses: [200, 404]
            }).then(data => {
                let nb = null;
                if (data) {
                    // hLogger.debug('found breaches ' + JSON.stringify(data));
                    data.split('\r\n').some(line => {
                        const h = line.split(':');
                        const suffix = h[0];
                        if (prefix + suffix === passwordHash) {
                            nb = _.escape(h[1]);
                            // hLogger.debug('matching breach ' + suffix);
                            return true;
                        }
                    });
                }
                this._pwnedPwdsCache[passwordHash] = { date: Date.now(), val: nb };
                if (nb) hLogger.info(`password ${passwordHash} pawned ${nb} times`);
                this.storeCache('_pwnedPwdsCache');
                return nb;
            });
        }
    };
    /**
     * filter passwords needing to be checked
     * @param {string} pwd the password to check
     * @returns {boolean} true if the pwd can be checked
     */
    elligiblePwd (pwd) {
        return (pwd && pwd.replace(/\s/, '') !== '' && !pwd.startsWith('{REF:'));
    }
    /**
     * Change the password field to display an alert or reset it depending on npwned value
     * @param {View} dview the details view
     * @param {number} npwned the number of times the password has been pawned (or null or 0 if none)
     * @param {string} warning the warning to display
     * @param {...} args the arguments to be passed to the original 'fieldChanged' function
     */
    alertPwdPwned (dview, npwned, warning, args) {
        if (npwned) { // pwned
            // record pawnage in the model to be able to show it in list view
            dview.model.pwdPwned = npwned;
            // calls original function
            detailsViewFieldChanged.apply(dview, args);
            // sets the alert
            this.alert(dview.passEditView.$el, warning);
        } else { // not pwned
            // reset css and tip
            this.passed(dview.passEditView.$el, 'check pwned password passed...');
            // reset pawnage in the model
            dview.model.pwdPwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
    /**
     * filter names needing to be checked
     * @param {string} name the name to check
     * @returns {boolean} true if the name can be checked
     */
    elligibleName(name) {
        return (name && name.replace(/\s/, '') !== '');
    }
    /**
     * Change the name field to display an alert or reset it depending on breaches value
     * @param {View} dview the details view
     * @param {string} breaches the breaches in which the name has been pawned (or null or '' if none)
     * @param {string} warning the warning to display
     * @param {...} args the arguments to be passed to the original 'fieldChanged' function
     */
    alertNamePwned (dview, breaches, warning, args) {
        if (breaches) { // pwned
            // remember breaches in the model to be able to show it in list view
            dview.model.namePwned = breaches;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
            // adds an alert
            this.alert(dview.userEditView.$el, warning);
        } else { // not pwned
            // reset alert
            this.passed(dview.userEditView.$el, 'check pwned user name passed...');
            // reset the model
            dview.model.namePwned = null;
            // call initial function
            detailsViewFieldChanged.apply(dview, args);
        }
    };
    /**
     * Looks up the password on HaveIBeenPwned and handle the results
     * If the password is pawned, depending on the check level, puts some icon warning, or asks to revert to the previous one
     * @param {DetailedView} dview the detailed view containing the password
     * @param {string} pwd the pwd to check
     */
    handlePasswordChange(dview, pwd, args) {
        pwd = pwd ? pwd.getText() : null;
        if (hibp.elligiblePwd(pwd)) {
            // hLogger.debug('pwd:>>>' + pwd + '<<<');
            this.sha1(pwd)
                .then(hpwd => {
                    return this.checkPwdPwned(hpwd);
                })
                .then(npwned => {
                    const warning = HIBPLocale.hibpPwdWarning.replace('{}', npwned);
                    if (npwned) { // pawned
                        if (this.checkPwnedPwd === HIBPCheckLevel.AskMe) {
                            // ask before taking the field change into account
                            Alerts.yesno({
                                header: HIBPLocale.hibpChangePwd,
                                body: warning,
                                icon: 'exclamation-triangle',
                                success: () => { // keep password, just set an alert
                                    this.alertPwdPwned(dview, npwned, warning, args);
                                },
                                cancel: () => { // reset password by not registering change
                                    hLogger.info('keeping old passwd');
                                }
                            });
                        } else { // check level = alert, keep pwd, set an alert
                            this.alertPwdPwned(dview, npwned, warning, args);
                        }
                    } else { // not pawned
                        this.alertPwdPwned(dview, null, null, args);
                    }
                }).catch(error => {
                    hLogger.error('check pwned password error: ' + error.message);
                });
        } else {
            this.alertPwdPwned(dview, null, null, args);
        }
    }
    /**
     * Looks up the user name on HaveIBeenPwned and handle the results
     * If the name is pawned, depending on the check level, puts some icon warning, or asks to revert to the previous one
     * @param {DetailedView} dview the detailed view containing the user name
     * @param {string} name the user name to check
     */
    handleNameChange(dview, name, args) {
        if (this.elligibleName(name)) {
            this.checkNamePwned(name)
                .then(breaches => {
                    if (breaches) { // pawned
                        name = _.escape(name); // breaches already escaped
                        const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                        if (this.checkPwnedName === HIBPCheckLevel.AskMe) {
                            // ask before taking the field change into account
                            Alerts.yesno({
                                header: HIBPLocale.hibpChangeName,
                                body: warning,
                                icon: 'exclamation-triangle',
                                success: () => { // keep name, but set an alert
                                    this.alertNamePwned(dview, breaches, warning, args);
                                },
                                cancel: () => { // reset name by not registering change
                                    hLogger.info('reverting to previous user name');
                                }
                            });
                        } else { // check level = alert, keep new name but sets an alert
                            this.alertNamePwned(dview, breaches, warning, args);
                        }
                    } else { // not pawned
                        this.alertNamePwned(dview, null, null, args);
                    }
                }).catch(error => {
                    hLogger.error('check pwned name error: ' + error.message);
                });
        } else {
            hibp.alertNamePwned(this, null, null, args);
        }
    }
    displayFields(dview) {
        // check password
        const pwd = dview.model.password ? dview.model.password.getText() : null;
        // hLogger.debug('addfv pwd:>>>' + pwd + '<<<');
        if (this.checkPwnedPwd !== HIBPCheckLevel.None && this.elligiblePwd(pwd)) {
            this.sha1(pwd)
                .then(hpwd => {
                    return this.checkPwdPwned(hpwd);
                })
                .then(nb => {
                    // hLogger.debug(pwd + ' pppwand: ' + nb);
                    dview.model.pwdPwned = nb;
                    if (nb) { // pawned
                        const warning = HIBPLocale.hibpPwdWarning.replace('{}', nb);
                        this.alert(dview.passEditView.$el, warning);
                    } else { // not pawned
                        this.passed(dview.passEditView.$el, 'check pwned password passed...');
                    }
                }).catch(error => {
                    hLogger.error('check pwned pwd error: ' + error);
                });
        }
        // check user name
        let name = dview.userEditView.value;
        // hLogger.debug('addfv name:>>>' + name + '<<<');
        if (this.elligibleName(name) && this.checkPwnedName !== HIBPCheckLevel.None) {
            this.checkNamePwned(name)
                .then(breaches => {
                    dview.model.namePwned = breaches;
                    if (breaches) { // pawned
                        name = _.escape(name); // breaches already escaped
                        const warning = HIBPLocale.hibpNameWarning.replace('{name}', name).replace('{breaches}', breaches);
                        this.alert(dview.userEditView.$el, warning);
                    } else { // not pawned
                        this.passed(dview.userEditView.$el, 'check pwned user name passed...');
                    }
                }).catch(error => {
                    hLogger.error('check pwned name error: ' + HIBPUtils.stringify(error));
                });
        }
    };
    filterEntries(app, entries) {
        // hLogger.debug('getEntriesByFilter: entries = ' + JSON.stringify(entries));
        if (this.checkPwnedList && entries && entries.length) {
            // get all different names and pwds to reduce the number of calls to the HIBP API
            const names = [];
            const pwds = [];
            entries.forEach(item => {
                // hLogger.debug('getEntriesByFilter: item = ' + item.title);
                // get different user names and pwds to optimize queries
                const name = item.user;
                if (this.elligibleName(name)) {
                    const fname = names.find(elem => elem.name === name);
                    // hLogger.debug("fname=" + JSON.stringify(fname));
                    if (fname) fname.items.push(item);
                    else names.push({ name: name, items: [item] });
                }
                let pwd = item.password;
                if (pwd) {
                    pwd = pwd.getText();
                    if (this.elligiblePwd(pwd)) {
                        const fpwd = pwds.find(elem => elem.pwd === pwd);
                        if (fpwd) fpwd.items.push(item);
                        else pwds.push({ pwd: pwd, items: [item] });
                    }
                }
            });

            // asynchronously look for pawned names and pwds
            // do somme throttling on names as HIBP does not allow more than one call every 1500 millisecs
            let throttle = 2000; // millisecs betwwen 2 calls
            names.forEach((elem, index) => {
                // hLogger.debug('getEntriesByFilter: check item ' + item.title);
                setTimeout(() => {
                    this.checkNamePwned(elem.name)
                        .then(breaches => {
                            let refresh = false;
                            elem.items.forEach(item => {
                                const itemPwned = item.namePwned;
                                item.namePwned = breaches;
                                refresh = refresh || (!breaches !== !itemPwned); // XOR
                            });
                            refresh && app.refresh();
                        })
                        .catch(err => {
                            hLogger.error('error in checking name ' + elem.name + 'in get entries by filter: ' + err);
                        });
                }, index * throttle);
            });
            // no need of throttling for passwords on HIBP, use a low throttle value
            throttle = 100; // millisecs
            pwds.forEach((elem, index) => {
                setTimeout(() => {
                    this.sha1(elem.pwd)
                        .then(hpwd => {
                            return this.checkPwdPwned(hpwd);
                        })
                        .then(nb => {
                            let refresh = false;
                            elem.items.forEach(item => {
                                const itemPwned = item.pwdPwned;
                                item.pwdPwned = nb;
                                refresh = refresh || (!nb !== !itemPwned); // XOR
                            });
                            refresh && app.refresh();
                        })
                        .catch(err => {
                            hLogger.error('error in checking pwd ' + elem.pwd + ' in get entries by filter: ' + err);
                        });
                }, index * throttle);
            });
        }
    }
};

/** the HIBP singleton
 * @type {HIBP}
 */
const hibp = new HIBP();

/**
 * Replaces the fiedChanged function of DetailsView to add checks on user names and passwords
 * @param {Event} e the event that triggered the change
 */
DetailsView.prototype.fieldChanged = function (e) {
    if (e.field) {
        // hLogger.debug('field changed ' + hibp.stringify(e));
        // first check password
        if (e.field === '$Password' && hibp.checkPwnedPwd !== HIBPCheckLevel.None && this.passEditView.value) {
            hibp.handlePasswordChange(this, e.val, arguments);
            // second, check user name
        } else if (e.field === '$UserName' && hibp.checkPwnedName !== HIBPCheckLevel.None) {
            hibp.handleNameChange(this, e.val, arguments);
        }
    } else { // not name, not password
        detailsViewFieldChanged.apply(this, arguments);
    }
};

/**
 * Replaces initial addFieldViews function in DetailsView
 * Allows showing pawned fields when displaying entry details
 */
DetailsView.prototype.addFieldViews = function () {
    // call initial function
    detailsViewAddFieldViews.apply(this, arguments);
    hibp.displayFields(this);
};

/**
 * Replaces initial render function in ListView
 */
ListView.prototype.render = function () {
    listViewRender.apply(this, arguments);
    hLogger.debug('rendering list in hibp');
    this.items.filter(item => item.namePwned || item.pwdPwned).forEach(item => {
        hLogger.debug('list pwned item "' + item.title + '"');
        const itemEl = document.getElementById(item.id);
        if (itemEl) { itemEl.classList.add('hibp-pwned'); }
    });
};

/**
 * Replaces initial getEntriesByFilter in AppModel
 * Check all entries to see if they are pawned
 * @param {Filter} filter 
 */
AppModel.prototype.getEntriesByFilter = function (filter) {
    const entries = appModelGetEntriesByFilter.apply(this, arguments);
    hibp.filterEntries(this, entries);
    return entries;
};

/**
 * @return settings of the plugin
 */
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

/**
 * Take settings changes into account
 * @param {Settings array} changes 
 */
module.exports.setSettings = function (changes) {
    for (const field in changes) {
        const ccfield = field.substr(0, 1).toLowerCase() + field.substring(1);
        hibp[ccfield] = changes[field];
    }
    HIBPUtils.dump(hibp);
};

/**
 * Reset all changes when the plugin is uninstalled
 */
module.exports.uninstall = function () {
    DetailsView.prototype.fieldChanged = detailsViewFieldChanged;
    DetailsView.prototype.addFieldViews = detailsViewAddFieldViews;
    ListView.prototype.render = listViewRender;
    AppModel.prototype.getEntriesByFilter = appModelGetEntriesByFilter;
};
