/**
 * KeeWeb plugin: steam-totp
 * @author Dylan Monroe
 * @license MIT
 */

const Otp = require('util/otp');

const Logger = require('util/logger');
// change log level here.
const LogLevel = Logger.Level.Info;

const logger = new Logger('steam-totp');
logger.setLevel(LogLevel);

const otpNext = Otp.prototype.next;

const STEAMCHARS = '23456789BCDFGHJKMNPQRTVWXY';

const steamNext = function(callback) {
  if (this.issuer !== 'Steam') return otpNext.call(this, callback);
  let valueForHashing;
  let timeLeft;
  const now = Date.now();
  const epoch = Math.round(now / 1000);
  valueForHashing = Math.floor(epoch / this.period);
  const msPeriod = this.period * 1000;
  timeLeft = msPeriod - (now % msPeriod);

  const data = new Uint8Array(8).buffer;
  new DataView(data).setUint32(4, valueForHashing);
  this.hmac(data, (sig, err) => {
    if (!sig) {
      logger.error('Steam TOTP calculation error', err);
      return callback();
    }
    const sigDV = new DataView(sig);
    const offset = sigDV.getInt8(sigDV.byteLength - 1) & 0xf;
    let fullcode = sigDV.getUint32(offset) & 0x7fffffff;
    let pass = '';
    for (let i = 0; i < 5; ++i) {
      pass += STEAMCHARS.charAt(fullcode % STEAMCHARS.length);
      fullcode /= STEAMCHARS.length;
    }
    callback(pass, timeLeft);
  });
};
Otp.prototype.next = steamNext;

module.exports.uninstall = function() {
  Otp.prototype.next = otpNext;
};
