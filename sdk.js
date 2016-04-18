'use strict';

const P         = require('bluebird');
const bs58check = require('bs58check');
const crypto    = require('crypto');
const elliptic  = require('elliptic');
const request   = require('request');
const ripemd160 = require('ripemd160');
const urlModule = require('url');

module.exports = {
  generate: {
    address: generateWalletAddress,
    currency: generateCurrencyIssuer,
    transaction: generateTransactionRequest
  },
  register: {
    address: registerWalletAddress,
    currency: registerCurrencyIssuer,
    transaction: registerTransactionRequest
  },
  check: {
    address: {
      balance: checkAddressBalance
    }
  }
};

/*--------------------------------------------------------------------------------*/

/** Generates and new key pair, derives an address and a signs a registration statement
 * @param  {Object} options - Cryptographic scheme and address type
 * @return {Object} wallet - Wallet address, public/private keys and a signed statement
 */
function generateWalletAddress(options) {
  options = options || {};

  let keys = generateKeyPair(options.scheme || 'ed25519');
  let address = deriveWalletAddress(keys.public, options.type);
  let statement = createAddressRegistrationStatement(address, keys, options);

  let wallet = {
    address: address,
    keys: keys,
    statement: statement
  };

  return wallet;
}

/** Generates a new key pair, derives a currency issuer address and signs a registration statement
 * @param  {Object} options - Cryptographic scheme and address type
 * @return {Object} - Currency issuer address, public/private keys and a signed statement
 */
function generateCurrencyIssuer(options) {
  options = options || {};
  options.type = 'issuer';

  return generateWalletAddress(options);
}

/** Generates a transaction request document in the form of an IOU
 * @param {Object} signer - Wallet whose private key is to be used for signing the IOU
 * @param {Object} transaction - Transaction parameters
 * @param {Object} options
 * @return {Object} - A cryptographically signed IOU
 */
function generateTransactionRequest(signer, transaction, options) {
  let iou = {
    amt: transaction.amount,
    cur: transaction.currency,
    sub: signer.address,
    aud: transaction.destination,
    nce: String(Math.floor(Math.random() * 1000000000))
  };

  return createTransactionRequestStatement(signer, iou, options);
}

/** Sends a wallet address registration request to the supplied URL
 * @param {string} url - The URL of a webwallet server 
 * @param {Object} body - A wallet address registration statement
 * @param {Object} options - Request parameters such as method and headers
 * @return {Promise} - Resolves to the response body
 */
function registerWalletAddress(url, body, options) {
  options = options || {};
  url = resolveURL(url, '/address');

  return new P(function (resolve, reject) {
    request({
      url: url,
      method: options.method || 'POST',
      body: body,
      json: true,
      headers: options.headers
    }, function (err, res, body) {
      if (err) return reject(err);
      return resolve(body);
    });
  });
}

/** Sends a currency issuer registration request to the supplied URL
 * @param {string} url - The URL of a webwallet server
 * @param {Object} body - A currency issuer registration statement
 * @param {Object} options - Request parameters such as method and headers
 * @return {Promise} - Resolves to the response body
 */
function registerCurrencyIssuer(url, body, options) {
  options = options || {};
  url = resolveURL(url, '/currency');

  return new P(function (resolve, reject) {
    request({
      url: url,
      method: options.method || 'POST',
      body: body,
      json: true,
      headers: options.headers
    }, function (err, res, body) {
      if (err) return reject(err);
      return resolve(body);
    });
  });
}

/** Sends a transaction request to the supplied URL
 * @param {string} url - The URL of a webwallet server
 * @param {Object} body - A transaction request statement
 * @param {Object} options - Request parameters such as method and headers
 * @return {Promise} - Resolves to the response body
 */
function registerTransactionRequest(url, body, options) {
  options = options || {};
  url = resolveURL(url, '/transaction');

  return new P(function (resolve, reject) {
    request({
      url: url,
      method: options.method || 'POST',
      body: body,
      json: true,
      headers: options.headers
    }, function (err, res, body) {
      if (err) return reject(err);
      return resolve(body);
    });
  });
}

/** Checks the balance of a wallet address
 * @param {string} url - The URL of a webwallet server
 * @param {string} address - A wallet address
 * @param {Object} options - Request parameters such as headers
 * @return {Promise} - Resolves to the response body
 */
function checkAddressBalance(url, address, options) {
  options = options || {};
  let path = '/address/.../balance'.replace('...', address);
  url = resolveURL(url, path);

  return new P(function (resolve, reject) {
    request({
      url: url,
      method: 'GET',
      headers: options.headers
    }, function (err, res, body) {
      if (err) return reject(err);
      return resolve(body);
    });
  });
}

/*--------------------------------------------------------------------------------*/

const hashes = ['sha256', 'sha512'];
const schemes = {
  'ed25519': new elliptic.ec('ed25519'),
  'secp256k1': new elliptic.ec('secp256k1')
};

/** Generates a pair of cryptographic keys
 * @param {string} scheme - A cryptographic scheme
 * @return {Object} keys - A cryptographic key pair
 */
function generateKeyPair(scheme) {
  let keypair;
  let keys;

  switch (scheme) {
    case 'ed25519':
    case 'secp256k1':
      keypair = schemes[scheme].genKeyPair();
      keys = {
        scheme: scheme,
        private: keypair.getPrivate('hex'),
        public: keypair.getPublic('hex')
      };
      break;
    default:
      throw new Error('invalid-scheme');
      break;
  }

  return keys;
}

/** Derives a wallet address from a public key
 * @param {<type>} publicKey - A public key to derive the address from
 * @param {string} type - The type of wallet address to derive
 * @return {string} base58public - A base58check encoded wallet address
 */
function deriveWalletAddress(publicKey, type) {
  let keyBuffer = new Buffer(publicKey, 'hex');
  let firstHash = crypto.createHash('sha256').update(keyBuffer).digest();
  let secondHash = ripemd160(firstHash);
  let extendedHash = (type === 'issuer' ? '57' : '87') + secondHash.toString('hex');
  let base58Public = bs58check.encode(new Buffer(extendedHash, 'hex'));

  return base58Public;
}

/** Creates and signs a statement to be sent for registering an address
 * @param {string} address - A wallet address
 * @param {Object} keys - An object containing a cryptograhic key pair
 * @param {Object} options - Parameters such as hash type
 * @return {Object} - A cryptographically signed statement
 */
function createAddressRegistrationStatement(address, keys, options) {
  options = options || {};

  /* Create an extended JSON Web Signatures object */
  let jws = {
    hash: {
      type: (hashes.indexOf(options.hash) > -1) ? options.hash : 'sha256',
      value: ''
    },
    payload: {
      address: address,
      keys: [
        keys.public
      ],
      threshold: 1
    },
    signatures: [
      {
        header: {
          alg: keys.scheme,
          kid: '0'
        },
        signature: ''
      }
    ]
  };

  /* Generate a cryptogrphic hash of the payload */
  jws.hash.value = crypto.createHash(jws.hash.type)
    .update(JSON.stringify(jws.payload)).digest('hex');

  /* Sign the hash of the payload */
  jws.signatures[0].signature = schemes[keys.scheme]
    .sign(jws.hash.value, keys.private, 'hex').toDER('hex');

  return jws;
}

/** Creates a transaction request statement in the form of an IOU
 * @param {Object} signer - Wallet whose private key is to be used for signing the IOU
 * @param {Object} iou - The IOU to sign
 * @param {Object} options - Parameters such as hash type
 * @return {Object} - A cryptographically signed IOU
 */
function createTransactionRequestStatement(signer, iou, options) {
  options = options || {};

  /* Create an extended JSON Web Signatures object */
  let jws = {
    hash: {
      type: (hashes.indexOf(options.hash) > -1) ? options.hash : 'sha256',
      value: ''
    },
    payload: iou,
    signatures: [
      {
        header: {
          alg: signer.keys.scheme,
          kid: signer.address
        },
        signature: ''
      }
    ]
  };

  /* Generate a cryptogrphic hash of the payload */
  jws.hash.value = crypto.createHash(jws.hash.type)
    .update(JSON.stringify(jws.payload)).digest('hex');

  /* Sign the hash of the payload */
  jws.signatures[0].signature = schemes[signer.keys.scheme]
    .sign(jws.hash.value, signer.keys.private, 'hex').toDER('hex');

  return jws;
}

const protocols = ['http', 'https', 'http:', 'https:'];
/** Resolves a URL given a path
 * @param {string} url - URL to resolve
 * @param {string} path - Path to append to base URL
 * @return {string} resolvedUrl - A valid URL
 */
function resolveURL(url, path) {
  if (typeof url !== 'string' || typeof path !== 'string') {
    return new Error('url-and-path-required');
  }

  /* Remove leading and duplicate slashes */
  url = url.replace(/\/{2,}/g, '/').replace(/^\//, '').replace(':/','://');

  let parsedUrl = urlModule.parse(url);
  if (protocols.indexOf(parsedUrl.protocol) < 0 || !parsedUrl.host) {
    return new Error('invalid-url');
  }

  let resolvedUrl = urlModule.resolve(parsedUrl.href, path);
  return resolvedUrl;
}
