/* jshint node: true */

'use strict';

var crypto = require('crypto');
var url = require('url');

module.exports = HmacAuth;
HmacAuth.ValidationError = ValidationError;

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
  '',
  'NO_SIGNATURE',
  'INVALID_FORMAT',
  'UNSUPPORTED_ALGORITHM',
  'MATCH',
  'MISMATCH'
];

HmacAuth.resultCodeToString = function(code) {
  if (code < 1 || code >= resultStrings.length) { return; }
  return resultStrings[code];
};

function signedHeaders(req, headers) {
  return headers.map(function(header) {
    var value = req.headers[header];
    if (typeof value === Array) { value = value.join(','); }
    return value || '';
  });
}

HmacAuth.prototype.stringToSign = function(req) {
  var parsedUrl = url.parse(req.url);
  var hashUrl = parsedUrl.path + (parsedUrl.hash || '');
  return [
    req.method, signedHeaders(req, this.headers).join('\n'), hashUrl
  ].join('\n');
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

HmacAuth.prototype.validateRequest = function(req, rawBody) {
  var header = this.signatureFromHeader(req);
  if (!header) { return [HmacAuth.NO_SIGNATURE]; }
  var components = header.split(' ');
  if (components.length != 2) { return [HmacAuth.INVALID_FORMAT, header]; }
  var digestName = components[0];
  try {
    crypto.createHash(digestName); 
  } catch (e) {
    return [HmacAuth.UNSUPPORTED_ALGORITHM, header];
  }
  var computed = requestSignature(this, req, rawBody, digestName);
  var result = (header == computed) ? HmacAuth.MATCH : HmacAuth.MISMATCH;
  return [result, header, computed];
};

function ValidationError(signatureHeader, result, header, computed) {
  this.name = 'ValidationError';
  this.signatureHeader = signatureHeader;
  this.result = result;
  this.header = header;
  this.computed = computed;
  this.message = signatureHeader + ' validation failed: ' +
    HmacAuth.resultCodeToString(result);
  if (header) { this.message += ' header: "' + header + '"'; }
  if (computed) { this.message += ' computed: "' + computed + '"'; }
  this.stack = (new Error()).stack;
}
ValidationError.prototype = Object.create(Error.prototype);
ValidationError.prototype.constructor = ValidationError;

HmacAuth.middlewareValidator = function(secretKey, signatureHeader, headers) {
  // Since the object is only used for validation, the digestName can be
  // anything valid. The actual digest function used during validation depends
  // on the digest name used as a prefix to the signature header.
  var auth = new HmacAuth('sha1', secretKey, signatureHeader, headers);

  return function(req, res, buf, encoding) {
    var rawBody = buf.toString(encoding);
    var validationResult = auth.validateRequest(req, rawBody);
    var result = validationResult[0];

    if (result != HmacAuth.MATCH) {
      var header = validationResult[1];
      var computed = validationResult[2];
      throw new ValidationError(signatureHeader, result, header, computed);
    }
  };
};
