'use strict';

var crypto    = require('crypto');
var elliptic  = require('elliptic');
var ripemd160 = require('ripemd160');
var request   = require('request');
var bs58check = require('bs58check');
var P         = require('bluebird');

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

function generateWalletAddress(options) {
  options = options || {};

  var keys = generateKeyPair(options.scheme || 'ed25519');
  var address = deriveWalletAddress(keys.public, options.type);
  var statement = createAddressRegistrationStatement(address, keys, options);

  return {
    address: address,
    keys: keys,
    statement: statement
  }
}

function generateCurrencyIssuer(options) {
  options = options || {};
  options.type = 'issuer';

  return generateWalletAddress(options);
}

function generateTransactionRequest(signer, transaction, options) {
  var iou = {
    amt: transaction.amount,
    cur: transaction.currency,
    sub: signer.address,
    aud: transaction.destination,
    nce: Math.floor(Math.random() * 1000000000) + ''
  };

  return createTransactionRequestStatement(signer, iou, options);
}

function registerWalletAddress(url, body, options) {
  options = options || {};
  url += '/address';

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

function registerCurrencyIssuer(url, body, options) {
  options = options || {};
  url += '/currency';

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

function registerTransactionRequest(url, body, options) {
  options = options || {};
  url += '/transaction';

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

function checkAddressBalance(url, address, options) {
  options = options || {};
  url += '/address/.../balance'.replace('...', address);
  console.log(url)

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

var hashes = ['sha256', 'sha512'];
var schemes = {
  'ed25519': new elliptic.ec('ed25519'),
  'secp256k1': new elliptic.ec('secp256k1')
};

function generateKeyPair(scheme) {
  var keypair;
  var keys;

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
      return P.reject('invalid-scheme');
      break;
  }

  return keys;
}

function deriveWalletAddress(publicKey, type) {
  var keyBuffer = new Buffer(publicKey, 'hex');
  var firstHash = crypto.createHash('sha256').update(keyBuffer).digest();
  var secondHash = ripemd160(firstHash);
  var extendedHash = (type === 'issuer' ? '57' : '87') + secondHash.toString('hex');
  var base58Public = bs58check.encode(new Buffer(extendedHash, 'hex'));

  return base58Public;
}

function createAddressRegistrationStatement(address, keys, options) {
  options = options || {};

  var jws = {
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

  jws.hash.value = crypto.createHash(jws.hash.type)
    .update(JSON.stringify(jws.payload)).digest('hex');

  jws.signatures[0].signature = schemes[keys.scheme]
    .sign(jws.hash.value, keys.private, 'hex').toDER('hex');

  return jws;
}

function createTransactionRequestStatement(signer, iou, options) {
  options = options || {};

  var jws = {
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

  jws.hash.value = crypto.createHash(jws.hash.type)
    .update(JSON.stringify(jws.payload)).digest('hex');

  jws.signatures[0].signature = schemes[signer.keys.scheme]
    .sign(jws.hash.value, signer.keys.private, 'hex').toDER('hex');

  return jws;
}
