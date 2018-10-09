/**
 * KeeWeb plugin: keeweb-mojave
 * @author agurodriguez
 * @license MIT
 */

const AppSettingsModel = require('models/app-settings-model');
const FeatureDetector = require('util/feature-detector');

const FIRST_RUN_KEY = 'keeweb-mojave-first-run';
const PREVIOUS_TITLEBAR_STYLE_KEY = 'keeweb-mojave-previous-titlebar-style';

if (FeatureDetector.isDesktop) {
    if (!localStorage.getItem(FIRST_RUN_KEY)) {
        localStorage.setItem(FIRST_RUN_KEY, true);
        localStorage.setItem(PREVIOUS_TITLEBAR_STYLE_KEY, AppSettingsModel.instance.get('titlebarStyle'));
        AppSettingsModel.instance.set('titlebarStyle', 'hidden');
    }
}

module.exports.uninstall = function() {
    localStorage.removeItem(FIRST_RUN_KEY);
    localStorage.removeItem(PREVIOUS_TITLEBAR_STYLE_KEY);
};