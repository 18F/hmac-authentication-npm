/* jshint node: true */

'use strict';

var crypto = require('crypto');
var url = require('url');

var exports = module.exports = {};

exports.NO_SIGNATURE = 1;
exports.INVALID_FORMAT = 2;
exports.UNSUPPORTED_ALGORITHM = 3;
exports.MATCH = 4;
exports.MISMATCH = 5;

var resultStrings = [
  '',
  'NO_SIGNATURE',
  'INVALID_FORMAT',
  'UNSUPPORTED_ALGORITHM',
  'MATCH',
  'MISMATCH'
];

exports.resultCodeToString = function(code) {
  if (code < 1 || code >= resultStrings.length) { return; }
  return resultStrings[code];
};

function signedHeaders(req, headers) {
  return headers.map(function(header) {
    var value = req.get(header);
    if (typeof value === Array) { value = value.join(','); }
    return value || '';
  });
}

exports.stringToSign = function(req, headers) {
  var parsedUrl = url.parse(req.url);
  var hashUrl = parsedUrl.path + (parsedUrl.hash || '');
  return [
    req.method, signedHeaders(req, headers).join('\n'), hashUrl
  ].join('\n');
};

exports.requestSignature = function(
  req, rawBody, digestName, headers, secretKey) {
  var hmac = crypto.createHmac(digestName, secretKey);
  hmac.update(exports.stringToSign(req, headers));
  hmac.update(rawBody || '');
  return digestName + ' ' + hmac.digest('base64');
};

exports.validateRequest = function(req, rawBody, signatureHeader, headers,
  secretKey) {
  var header = req.get(signatureHeader);
  if (!header) { return [exports.NO_SIGNATURE]; }
  var components = header.split(' ');
  if (components.length != 2) { return [exports.INVALID_FORMAT, header]; }
  var digestName = components[0];
  try {
    crypto.createHash(digestName); 
  } catch (e) {
    return [exports.UNSUPPORTED_ALGORITHM, header];
  }
  var computed = exports.requestSignature(
    req, rawBody, digestName, headers, secretKey);
  var result = (header == computed) ? exports.MATCH : exports.MISMATCH;
  return [result, header, computed];
};

function ValidationError(signatureHeader, result, header, computed) {
  this.name = 'ValidationError';
  this.signatureHeader = signatureHeader;
  this.result = result;
  this.header = header;
  this.computed = computed;
  this.message = signatureHeader + ' validation failed: ' +
    exports.resultCodeToString(result);
  if (header) { this.message += ' header: "' + header + '"'; }
  if (computed) { this.message += ' computed: "' + computed + '"'; }
  this.stack = (new Error()).stack;
}
ValidationError.prototype = Object.create(Error.prototype);
ValidationError.prototype.constructor = ValidationError;
exports.ValidationError = ValidationError;

exports.middlewareValidator = function(signatureHeader, headers, secretKey) {
  return function(req, res, buf, encoding) {
    var rawBody = buf.toString(encoding);
    var validationResult = exports.validateRequest(
      req, rawBody, signatureHeader, headers, secretKey);
    var result = validationResult[0];

    if (result != exports.MATCH) {
      var header = validationResult[1];
      var computed = validationResult[2];
      throw new ValidationError(signatureHeader, result, header, computed);
    }
  };
};
