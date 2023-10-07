/**
 * KeeWeb plugin: keeweb-s3-storage
 * @author Sergey Starostin
 * @license MIT
 */

const Storage = require('storage/index').Storage;
const BaseLocale = require('locales/base');
const StorageBase = require('storage/storage-base').StorageBase;
const Logger = require('util/logger').Logger;
const signV4Algorithm = "AWS4-HMAC-SHA256";

const HMAC = {
    m: new Uint32Array(64),
    littleEndian: !!new Uint8Array(new Uint32Array([1]).buffer)[0],
    encoder: new TextEncoder("utf-8"),

    _getFractionalBits: function(n) {
        return ((n - (n | 0)) * Math.pow(2, 32)) | 0;
    },

    get origin() {
        delete this.origin;
        let defaultState = new Uint32Array(8);
        let roundConstants = [];
        let n = 2,
            nPrime = 0;
        while (nPrime < 64) {
            let isPrime = true;
            for (var factor = 2; factor <= n / 2; factor++) {
                if (n % factor === 0) {
                    isPrime = false;
                }
            }
            if (isPrime) {
                if (nPrime < 8) {
                    defaultState[nPrime] = this._getFractionalBits(Math.pow(n, 1 / 2));
                }
                roundConstants[nPrime] = this._getFractionalBits(Math.pow(n, 1 / 3));
                nPrime++;
            }
            n++;
        }
        return this.origin = {
            defaultState,
            roundConstants
        };
    },

    _convertEndian: function(word) {
        if (this.littleEndian) {
            return (
                (word >>> 24) |
                (((word >>> 16) & 0xff) << 8) |
                ((word & 0xff00) << 8) |
                (word << 24)
            );
        } else {
            return word;
        }
    },

    _rightRotate: function(word, bits) {
        return (word >>> bits) | (word << (32 - bits));
    },

    _sha256: function(data) {
        let state = this.origin.defaultState.slice();
        let length = data.length;

        let bitLength = length * 8;
        let newBitLength = (512 - ((bitLength + 64) % 512) - 1) + bitLength + 65;

        let bytes = new Uint8Array(newBitLength / 8);
        let words = new Uint32Array(bytes.buffer);

        bytes.set(data, 0);
        bytes[length] = 0b10000000;
        words[words.length - 1] = this._convertEndian(bitLength);

        let round;

        for (let block = 0; block < newBitLength / 32; block += 16) {
            let workingState = state.slice();

            for (round = 0; round < 64; round++) {
                let MRound;
                if (round < 16) {
                    MRound = this._convertEndian(words[block + round]);
                } else {
                    let gamma0x = this.m[round - 15];
                    let gamma1x = this.m[round - 2];
                    MRound =
                        this.m[round - 7] + this.m[round - 16] + (
                            this._rightRotate(gamma0x, 7) ^
                            this._rightRotate(gamma0x, 18) ^
                            (gamma0x >>> 3)
                        ) + (
                            this._rightRotate(gamma1x, 17) ^
                            this._rightRotate(gamma1x, 19) ^
                            (gamma1x >>> 10)
                        );
                }

                this.m[round] = MRound |= 0;

                let t1 =
                    (
                        this._rightRotate(workingState[4], 6) ^
                        this._rightRotate(workingState[4], 11) ^
                        this._rightRotate(workingState[4], 25)
                    ) +
                    (
                        (workingState[4] & workingState[5]) ^
                        (~workingState[4] & workingState[6])
                    ) + workingState[7] + MRound + this.origin.roundConstants[round];
                let t2 =
                    (
                        this._rightRotate(workingState[0], 2) ^
                        this._rightRotate(workingState[0], 13) ^
                        this._rightRotate(workingState[0], 22)
                    ) +
                    (
                        (workingState[0] & workingState[1]) ^
                        (workingState[2] & (workingState[0] ^
                            workingState[1]))
                    );

                for (let i = 7; i > 0; i--) {
                    workingState[i] = workingState[i - 1];
                }
                workingState[0] = (t1 + t2) | 0;
                workingState[4] = (workingState[4] + t1) | 0;
            }

            for (round = 0; round < 8; round++) {
                state[round] = (state[round] + workingState[round]) | 0;
            }
        }

        let self = this;
        return new Uint8Array(new Uint32Array(
            state.map(function(val) {
                return self._convertEndian(val);
            })
        ).buffer);
    },

    _hmac: function(key, data) {
        if (key.length > 64)
            key = this._sha256(key);

        if (key.length < 64) {
            const tmp = new Uint8Array(64);
            tmp.set(key, 0);
            key = tmp;
        }

        let innerKey = new Uint8Array(64);
        let outerKey = new Uint8Array(64);
        for (var i = 0; i < 64; i++) {
            innerKey[i] = 0x36 ^ key[i];
            outerKey[i] = 0x5c ^ key[i];
        }

        let msg = new Uint8Array(data.length + 64);
        msg.set(innerKey, 0);
        msg.set(data, 64);

        let result = new Uint8Array(64 + 32);
        result.set(outerKey, 0);
        result.set(this._sha256(msg), 64);

        return this._sha256(result);
    },

    sign: function(inputKey, inputData) {
        const key = typeof inputKey === "string" ? this.encoder.encode(inputKey) : inputKey;
        const data = typeof inputData === "string" ? this.encoder.encode(inputData) : inputData;
        return this._hmac(key, data);
    },

    hash: function(str) {
        return this.hex(this._sha256(this.encoder.encode(str)));
    },

    hex: function(bin) {
        return bin.reduce((acc, val) =>
            acc + ("00" + val.toString(16)).substr(-2), "");
    },

    hashSign: function(inputKey, inputData) {
        return this.sign(inputKey, inputData);
    },

    hashHexSign: function(inputKey, inputData) {
        return this.hex(this.sign(inputKey, inputData));
    }

};

class S3Storage extends StorageBase {
    constructor(props) {
        super(props);
        this.name = "s3Storage";
        this.icon = "database";
        this.enabled = true;
        this.uipos = 100;
        this.logger = new Logger("storage-s3");
    }

    needShowOpenConfig() {
        return true;
    }

    getOpenConfig() {
        return {
            fields: [{
                    id: "key",
                    title: "s3AccessKeyTitle",
                    desc: "s3AccessKeyDesc",
                    placeholder: "s3AccessKeyPlaceholder",
                    type: "text",
                    required: true,
                },
                {
                    id: "secret",
                    title: "s3SecretTitle",
                    desc: "s3SecretDesc",
                    placeholder: "s3SecretPlaceholder",
                    type: "password",
                    required: true
                },
                {
                    id: "region",
                    title: "s3RegionTitle",
                    desc: "s3RegionDesc",
                    placeholder: "s3RegionPlaceholder",
                    type: "text"
                },
                {
                    id: "origin",
                    title: "s3OriginTitle",
                    desc: "s3OriginDesc",
                    placeholder: "s3OriginPlaceholder",
                    type: "text",
                    required: true
                },
                {
                    id: "path",
                    title: "s3PathTitle",
                    desc: "s3PathDesc",
                    placeholder: "s3PathPlaceholder",
                    type: "text",
                    required: true
                }
            ]
        };
    }

    getSettingsConfig() {
        return {
            fields: []
        };
    }

    fileOptsToStoreOpts(opts, file) {
        const result = {
            key: opts.key,
            secret: opts.secret,
            region: opts.region,
            origin: opts.origin
        };
        return result;
    }

    storeOptsToFileOpts(opts, file) {
        const result = {
            key: opts.key,
            secret: opts.secret,
            region: opts.region,
            origin: opts.origin
        };
        return result;
    }

    applySetting(key, value) {
        this.appSettings[key] = value;
    }

    getPathForName(fileName) {
        return fileName;
    }

    load(path, opts, callback) {
        this._request({
                op: "Load",
                method: "GET",
                path,
                key: opts ? opts.key : null,
                secret: opts ? opts.secret : null,
                region: opts ? opts.region : null,
                origin: opts ? opts.origin : null
            },
            callback ?
            (err, xhr) => {
                this.logger.debug(xhr, err, callback);
                callback(err, xhr.response, this._calcStatByContent(xhr));
            } :
            null
        );
    }

    stat(path, opts, callback) {
        this._statRequest(
            path,
            opts,
            "Stat",
            callback ? (err, xhr, stat) => callback(err, stat) : null
        );
    }

    _isNumber(v) {
        return typeof v === "number" && !isNaN(v);
    }

    _isString(v) {
        return (typeof v === "string" || v instanceof String);
    }

    _isObject(v) {
        return (typeof v === "object" || v !== null);
    }

    _isArray(v) {
        return (v.constructor === Array);
    }

    _statRequest(path, opts, op, callback) {
        this._request({
                op,
                method: "GET",
                path,
                key: opts ? opts.key : null,
                secret: opts ? opts.secret : null,
                region: opts ? opts.region : null,
                origin: opts ? opts.origin : null
            },
            callback ?
            (err, xhr) => {
                callback(err, xhr, this._calcStatByContent(xhr));
            } :
            null
        );
    }

    save(path, opts, data, callback, rev) {
        const cb = function(err, xhr, stat) {
            if (callback) {
                callback(err, stat);
                callback = null;
            }
        };
        const saveOpts = {
            path,
            key: opts ? opts.key : null,
            secret: opts ? opts.secret : null,
            region: opts ? opts.region : null,
            origin: opts ? opts.origin : null
        };
        this._statRequest(path, opts, "Save:stat", (err, xhr, stat) => {
            if (err) {
                if (!err.notFound) {
                    return cb(err);
                } else {
                    this.logger.debug("Save: not found, creating");
                }
            } else if (stat.rev !== rev) {
                this.logger.debug("Save error", path, "rev conflict", stat.rev, rev);
                return cb({
                    revConflict: true
                }, xhr, stat);
            }

            this._request({
                    ...saveOpts,
                    op: "Save:put",
                    method: "PUT",
                    data
                },
                (err) => {
                    if (err) {
                        return cb(err);
                    }
                    this._statRequest(path, opts, "Save:stat", (err, xhr, stat) => {
                        cb(err, xhr, stat);
                    });
                }
            );
        });
    }

    list(dir, callback) {
        callback("fail");
    }

    remove(path, callback) {
        callback("fail");
    }

    setEnabled(enabled) {
        StorageBase.prototype.setEnabled.call(this, enabled);
    }

    _getCanonicalRequest(method, path, headers, signedHeaders) {
        if (!this._isString(method)) {
            //method should be of type "string"
        }
        if (!this._isString(path)) {
            //path should be of type "string"
        }
        if (!this._isObject(headers)) {
            //headers should be of type "object"
        }
        if (!this._isArray(signedHeaders)) {
            //signedHeaders should be of type "array"
        }

        const headersArray = signedHeaders.reduce((acc, i) => {
            // Trim spaces from the value (required by V4 spec)
            const val = `${headers[i]}`.replace(/ +/g, " ");
            acc.push(`${i.toLowerCase()}:${val}`);
            return acc;
        }, []);

        const canonical = [];
        canonical.push(method.toUpperCase());
        canonical.push(path);
        canonical.push("");
        canonical.push(headersArray.join("\n") + "\n");
        canonical.push(signedHeaders.join(";").toLowerCase());
        canonical.push("UNSIGNED-PAYLOAD");
        return canonical.join("\n");
    }

    _makeDateShort(date) {
        date = date || new Date();

        // Gives format like: "2017-08-07T16:28:59.889Z"
        date = date.toISOString();

        return date.substr(0, 4) +
            date.substr(5, 2) +
            date.substr(8, 2);
    }

    _makeDateLong(date) {
        date = date || new Date();

        // Gives format like: "2017-08-07T16:28:59.889Z"
        date = date.toISOString();

        return date.substr(0, 4) +
            date.substr(5, 2) +
            date.substr(8, 5) +
            date.substr(14, 2) +
            date.substr(17, 2) + "Z";
    }

    _getScope(region, date, serviceName = "s3") {
        return `${this._makeDateShort(date)}/${region}/${serviceName}/aws4_request`;
    }

    _uriEscape(string) {
        return string.split("").reduce((acc, elem) => {
            let bytes = [];
            let code = elem.charCodeAt(0);
            bytes.push(code & 0xff);
            let e = code / 256 >>> 0;
            if (e > 0) {
                bytes.push(e);
            }
            if (bytes.length === 1) {
                // length 1 indicates that elem is not a unicode character.
                // Check if it is an unreserved characer.
                if ("A" <= elem && elem <= "Z" ||
                    "a" <= elem && elem <= "z" ||
                    "0" <= elem && elem <= "9" ||
                    elem === "_" ||
                    elem === "." ||
                    elem === "~" ||
                    elem === "-") {
                    // Unreserved characer should not be encoded.
                    acc = acc + elem;
                    return acc;
                }
            }
            // elem needs encoding - i.e elem should be encoded if it's not unreserved
            // character or if it's a unicode character.
            for (var i = 0; i < bytes.length; i++) {
                acc = acc + "%" + bytes[i].toString(16).toUpperCase();
            }
            return acc;
        }, "");
    }

    _uriResourceEscape(string) {
        return this._uriEscape(string).replace(/%2F/g, '/');
    }

    _getCredential(accessKey, region, requestDate, serviceName = "s3") {
        if (!this._isString(accessKey)) {
            //accessKey should be of type "string"
        }
        if (!this._isString(region)) {
            //region should be of type "string"
        }
        if (!this._isObject(requestDate)) {
            //requestDate should be of type "object"
        }
        return `${accessKey}/${this._getScope(region, requestDate, serviceName)}`;
    }

    _getSignedHeaders(headers) {
        if (!this._isObject(headers)) {
            //request should be of type "object"
        }

        const passedHeaders = ["host", "x-amz-", "content-type"];

        let _ = Object.entries(headers);
        return _.map(([header, value]) => header)
            .filter((header) => {
                return passedHeaders.some(h => header.toLowerCase().includes(h));
            });
    }

    // returns the key used for calculating signature
    _getSigningKey(date, region, secretKey, serviceName = "s3") {
        if (!this._isObject(date)) {
            //date should be of type "object"
        }
        if (!this._isString(region)) {
            //region should be of type "string"
        }
        if (!this._isString(secretKey)) {
            //secretKey should be of type "string"
        }
        const dateLine = this._makeDateShort(date);
        let hmac1 = HMAC.hashSign("AWS4" + secretKey, dateLine),
            hmac2 = HMAC.hashSign(hmac1, region),
            hmac3 = HMAC.hashSign(hmac2, serviceName);
        return HMAC.hashSign(hmac3, "aws4_request");
    }

    // returns the string that needs to be signed
    _getStringToSign(canonicalRequest, requestDate, region, serviceName = "s3") {
        if (!this._isString(canonicalRequest)) {
            //canonicalRequest should be of type "string"
        }
        if (!this._isObject(requestDate)) {
            //requestDate should be of type "object"
        }
        if (!this._isString(region)) {
            //region should be of type "string"
        }
        const hash = HMAC.hash(canonicalRequest);
        const scope = this._getScope(region, requestDate, serviceName);
        const stringToSign = [];
        stringToSign.push(signV4Algorithm);
        stringToSign.push(this._makeDateLong(requestDate));
        stringToSign.push(scope);
        stringToSign.push(hash);
        const signString = stringToSign.join("\n");
        return signString;
    }

    // calculate the signature of the POST policy
    _postPresignSignatureV4(region, date, secretKey, policyBase64) {
        if (!this._isString(region)) {
            //region should be of type "string"
        }
        if (!this._isObject(date)) {
            //date should be of type "object"
        }
        if (!this._isString(secretKey)) {
            //secretKey should be of type "string"
        }
        if (!this._isString(policyBase64)) {
            //policyBase64 should be of type "string"
        }
        const signingKey = this._getSigningKey(date, region, secretKey);
        return HMAC.hashHexSign(signingKey, policyBase64).toLowerCase();
    }

    // Returns the authorization header
    _signV4(request, accessKey, secretKey, region, requestDate, serviceName = "s3") {
        if (!this._isObject(request)) {
            //request should be of type "object"
        }
        if (!this._isString(accessKey)) {
            //accessKey should be of type "string"
        }
        if (!this._isString(secretKey)) {
            //secretKey should be of type "string"
        }
        if (!this._isString(region)) {
            //region should be of type "string"
        }

        if (!accessKey) {
            //accessKey is required for signing
        }
        if (!secretKey) {
            //secretKey is required for signing
        }

        let sortedHeaders = [];
        for (var header in request.headers) {
            sortedHeaders.push([header, request.headers[header]]);
        }
        sortedHeaders.sort((a, b) => a[0].localeCompare(b[0], undefined, {
            sensitivity: "base"
        }));

        request.headers = {};
        sortedHeaders.forEach(function(item) {
            request.headers[item[0]] = item[1];
        });

        const signedHeaders = this._getSignedHeaders(request.headers);
        const canonicalRequest = this._getCanonicalRequest(request.method, request.path, request.headers,
            signedHeaders);
        const serviceIdentifier = serviceName || "s3";
        requestDate = requestDate || new Date();
        const stringToSign = this._getStringToSign(canonicalRequest, requestDate, region, serviceIdentifier);
        const signingKey = this._getSigningKey(requestDate, region, secretKey, serviceIdentifier);
        const credential = this._getCredential(accessKey, region, requestDate, serviceIdentifier);
        const signature = HMAC.hashHexSign(signingKey, stringToSign).toLowerCase();

        return `${signV4Algorithm} Credential=${credential},SignedHeaders=${signedHeaders.join(";").toLowerCase()},Signature=${signature}`;
    }

    _signV4ByServiceName(request, accessKey, secretKey, region, requestDate, serviceName = "s3") {
        return this._signV4(request, accessKey, secretKey, region, requestDate, serviceName);
    }

    _calcStatByContent(xhr) {
        if (
            xhr.status !== 200 ||
            xhr.responseType !== "arraybuffer" ||
            !xhr.response ||
            !xhr.response.byteLength
        ) {
            this.logger.debug("Cannot calculate rev by content");
            return null;
        }

        const rev = HMAC.hash(
            String.fromCharCode.apply(null, new Uint16Array(xhr.response))
        ).substr(0, 10);
        this.logger.debug("Calculated rev by content", `${xhr.response.byteLength} bytes`, rev);
        return { rev };
    }

    _request(config, callback) {
        if (config.rev) {
            this.logger.debug(config.op, config.path, config.rev);
        } else {
            this.logger.debug(config.op, config.path);
        }
        if (!config.headers) {
            config.headers = {};
        }

        const ts = this.logger.ts();
        const xhr = new XMLHttpRequest();
        xhr.responseType = "arraybuffer";
        xhr.addEventListener("load", () => {
            if ([200, 201, 204].indexOf(xhr.status) < 0) {
                this.logger.debug(
                    config.op + " error",
                    config.path,
                    xhr.status,
                    this.logger.ts(ts)
                );
                let err;
                switch (xhr.status) {
                    case 404:
                        err = {
                            notFound: true
                        };
                        break;
                    case 412:
                        err = {
                            revConflict: true
                        };
                        break;
                    default:
                        err = "HTTP status " + xhr.status;
                        break;
                }
                if (callback) {
                    callback(err, xhr);
                    callback = null;
                }
                return;
            }
            const rev = xhr.getResponseHeader("Last-Modified");
            const completedOpName =
                config.op + (config.op.charAt(config.op.length - 1) === "e" ? "d" : "ed");
            this.logger.debug(completedOpName, config.path, rev, this.logger.ts(ts));
            if (callback) {
                callback(null, xhr, rev ? {
                    rev
                } : null);
                callback = null;
            }
        });
        xhr.addEventListener("error", () => {
            this.logger.debug(config.op + " error", config.path, this.logger.ts(ts));
            if (callback) {
                callback("network error", xhr);
                callback = null;
            }
        });
        xhr.addEventListener("abort", () => {
            this.logger.debug(config.op + " error", config.path, "aborted", this.logger.ts(ts));
            if (callback) {
                callback("aborted", xhr);
                callback = null;
            }
        });

        config.headers["host"] = (new URL(config.origin)).host;
        config.headers["x-amz-date"] = this._makeDateLong(new Date());
        config.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD";
        config.headers["content-type"] = "application/octet-stream";

        xhr.open(config.method, config.origin + config.path);

        if (["GET", "HEAD"].indexOf(config.method) >= 0) {
            xhr.setRequestHeader("cache-control", "no-cache");
        }
        if (config.key) {
            xhr.setRequestHeader("authorization", this._signV4ByServiceName(config, config.key, config.secret, config.region));
        }
        if (config.headers) {
            for (const [header, value] of Object.entries(config.headers)) {
                if (header != "host") {
                    xhr.setRequestHeader(header, value);
                }
            }
        }
        if (config.data) {
            const blob = new Blob([config.data], {
                type: "application/octet-stream"
            });
            xhr.send(blob);
        } else {
            xhr.send();
        }
    }
}

Object.assign(BaseLocale, {
    s3Storage: "S3 Storage",
    s3AccessKeyTitle: "Access Key",
    s3AccessKeyDesc: "An access key grants programmatic access to your resources.",
    s3AccessKeyPlaceholder: "AKIAJSIE27KKMHXI3BJQ",
    s3SecretTitle: "Secret Key",
    s3SecretDesc: "Secret access keys are secrets, like your password.",
    s3SecretPlaceholder: "5bEYu26084qjSFyclM/f2pz4gviSfoOg+mFwBH39",
    s3RegionTitle: "Region",
    s3RegionDesc: "Amazon S3 creates bucket in a region you specify.",
    s3RegionPlaceholder: "us-east-1",
    s3OriginTitle: "Origin",
    s3OriginDesc: "An S3 bucket can be accessed through its URL.",
    s3OriginPlaceholder: "http://docexamplebucket1.s3.amazonaws.com",
    s3PathTitle: "Path to .kdbx",
    s3PathDesc: "Path to KeePass data file in the bucket.",
    s3PathPlaceholder: "/bucket/file.kdbx",
    s3SaveMove: "Upload a temporary file and move",
    s3SavePut: "Overwrite the kdbx file with PUT"
});

Storage.s3Storage = new S3Storage();

module.exports.uninstall = function() {
    delete BaseLocale.s3Storage;
    delete Storage.s3Storage;
};
