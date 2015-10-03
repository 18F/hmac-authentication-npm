# hmac-authentication npm

Signs and validates HTTP requests based on a shared-secret HMAC signature.

## Installation

```sh
$ npm install hmac-authentication --save
```

## Validating incoming requests

Assuming you're using [Express](https://www.npmjs.com/package/express), during
initialization of your application, where `config.signatureHeader` identifies
the header containing the message signature, `config.headers` is a list of
headers factored into the signature, and `config.secretKey` is the shared
secret between your application and the service making the request:

```js
var express = require('express');
var bodyParser = require('bodyParser');
var hmacAuthentication = require('hmac-authentication');

function doLaunch(config) {
  var middlewareOptions = {
    verify: hmacAuthentication.middlewareValidator(
      config.signatureHeader, config.headers, config.secretKey)
  };
  var server = express();
  server.use(bodyParser.raw(middlewareOptions));

  // Continue server initialization...
}
```

If you're not using Express, you can use the function `validateRequest(req,
rawBody, headers, secretKey)` directly, where `rawBody` has already been
converted to a string.

## Signing outgoing requests

Call `requestSignature(request, rawBody, digestName, headers, secretKey)` to
sign a request before sending. `rawBody` and `digestName` must be strings.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0
>dedication. By submitting a pull request, you are agreeing to comply
>with this waiver of copyright interest.
