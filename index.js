/* jshint node: true */

'use strict';

var bufferEq = require('buffer-equal-constant-time');
var crypto = require('crypto');
var url = require('url');

module.exports = HmacAuth;
HmacAuth.AuthenticationError = AuthenticationError;

function HmacAuth(digestName, key, signatureHeader, headers) {
  this.digestName = digestName.toLowerCase();
  try {
    crypto.createHash(digestName);
  } catch (_) {
    throw new Error(
      'HMAC authentication digest is not supported: ' + digestName);
  }

  this.key = key;
  this.signatureHeader = signatureHeader.toLowerCase();
  this.headers = headers.map(function(h) { return h.toLowerCase(); });
}

HmacAuth.NO_SIGNATURE = 1;
HmacAuth.INVALID_FORMAT = 2;
HmacAuth.UNSUPPORTED_ALGORITHM = 3;
HmacAuth.MATCH = 4;
HmacAuth.MISMATCH = 5;

var resultStrings = [
  'NO_SIGNATURE',
  'INVALID_FORMAT',
  'UNSUPPORTED_ALGORITHM',
  'MATCH',
  'MISMATCH'
];

HmacAuth.resultCodeToString = function(code) {
  return resultStrings[code - 1];
};

function signedHeaders(req, headers) {
  return headers.map(function(header) {
    var value = req.headers[header];
    if (Array.isArray(value)) { value = value.join(','); }
    return value || '';
  });
}

HmacAuth.prototype.stringToSign = function(req) {
  var parsedUrl = url.parse(req.url);
  var hashUrl = parsedUrl.path + (parsedUrl.hash || '');
  return [
    req.method, signedHeaders(req, this.headers).join('\n'), hashUrl
  ].join('\n') + '\n';
};

HmacAuth.prototype.signRequest = function(req, rawBody) {
  req.headers[this.signatureHeader] = this.requestSignature(req, rawBody);
};

HmacAuth.prototype.requestSignature = function(req, rawBody) {
  return requestSignature(this, req, rawBody, this.digestName);
};

function requestSignature(auth, req, rawBody, digestName) {
  var hmac = crypto.createHmac(digestName, auth.key);
  hmac.update(auth.stringToSign(req));
  hmac.update(rawBody || '');
  return digestName + ' ' + hmac.digest('base64');
}

HmacAuth.prototype.signatureFromHeader = function(req) {
  return req.headers[this.signatureHeader];
};

// Replace bufferEq() once https://github.com/nodejs/node/issues/3043 is
// resolved and the standard library implementation is available.
function compareSignatures(lhs, rhs) {
  var lbuf = new Buffer(lhs);
  var rbuf = new Buffer(rhs);
  return bufferEq(lbuf, rbuf) ? HmacAuth.MATCH : HmacAuth.MISMATCH;
}

HmacAuth.prototype.authenticateRequest = function(req, rawBody) {
  var header = this.signatureFromHeader(req);
  if (!header) { return [HmacAuth.NO_SIGNATURE]; }
  var components = header.split(' ');
  if (components.length !== 2) { return [HmacAuth.INVALID_FORMAT, header]; }
  var digestName = components[0];
  try {
    crypto.createHash(digestName); 
  } catch (e) {
    return [HmacAuth.UNSUPPORTED_ALGORITHM, header];
  }
  var computed = requestSignature(this, req, rawBody, digestName);
  return [compareSignatures(header, computed), header, computed];
};

function AuthenticationError(signatureHeader, result, header, computed) {
  this.name = 'AuthenticationError';
  this.signatureHeader = signatureHeader;
  this.result = result;
  this.header = header;
  this.computed = computed;
  this.message = signatureHeader + ' authentication failed: ' +
    HmacAuth.resultCodeToString(result);
  if (header) { this.message += ' header: "' + header + '"'; }
  if (computed) { this.message += ' computed: "' + computed + '"'; }
  this.stack = (new Error()).stack;
}
AuthenticationError.prototype = Object.create(Error.prototype);
AuthenticationError.prototype.constructor = AuthenticationError;

HmacAuth.middlewareAuthenticator = function(
  secretKey, signatureHeader, headers) {
  // Since the object is only used for authentication, the digestName can be
  // anything valid. The actual digest function used during authentication
  // depends on the digest name used as a prefix to the signature header.
  var auth = new HmacAuth('sha1', secretKey, signatureHeader, headers);

  return function(req, res, buf, encoding) {
    var rawBody = buf.toString(encoding);
    var authenticationResult = auth.authenticateRequest(req, rawBody);
    var result = authenticationResult[0];

    if (result != HmacAuth.MATCH) {
      var header = authenticationResult[1];
      var computed = authenticationResult[2];
      throw new AuthenticationError(signatureHeader, result, header, computed);
    }
  };
};
