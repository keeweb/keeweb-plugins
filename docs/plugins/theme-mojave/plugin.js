/**
 * KeeWeb plugin: keeweb-mojave
 * @author agurodriguez
 * @license MIT
 */

const AppSettingsModel = require('models/app-settings-model');
const RuntimeDataModel = require('models/runtime-data-model');
const FeatureDetector = require('util/feature-detector');

const FIRST_RUN_KEY = 'keeweb-mojave-first-run';

if (FeatureDetector.isDesktop) {
    if (!RuntimeDataModel.instance.get(FIRST_RUN_KEY)) {
        AppSettingsModel.instance.set('titlebarStyle', 'hidden');
        RuntimeDataModel.instance.set(FIRST_RUN_KEY, true);
    }
}

module.exports.uninstall = function() {
    RuntimeDataModel.instance.unset(FIRST_RUN_KEY);
};
