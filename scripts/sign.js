const fs = require('fs');
const signer = require('pkcs15-smartcard-sign');
const keychain = require('keychain');

const verifyKey = fs.readFileSync('keys/public-key.pem');

function getPin() {
    if (getPin.pin) {
        return Promise.resolve(getPin.pin);
    }
    return new Promise((resolve, reject) => {
        keychain.getPassword({ account: 'keeweb', service: 'keeweb.pin', type: 'generic' }, (err, pass) => {
            if (err) {
                reject(err);
            } else {
                getPin.pin = pass;
                resolve(pass);
            }
        });
    });
}

module.exports = function sign(data) {
    return getPin().then(pin => signer.sign({ data, verifyKey, pin }).then(data => data.toString('base64')));
};
