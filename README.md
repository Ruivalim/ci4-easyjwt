# Easy JWT Code Igniter 4

Library for JWT generation in Code Igniter 4

## Avaliable algorithms

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

## .env file

- easyjwt.alg                  = "RS256"
- easyjwt.private_key          = "openssl/private.pem"
- easyjwt.private_key_password = "password"
- easyjwt.public_key           = "openssl/public.pem"
- easyjwt.iss                  = "http://localhost"

## Usage

```php

$jwt = new \App\Libraries\EasyJWT();

$payload = array(
    "key1" => "value1",
    "key2" => 2,
    "key3" => "value3"
);

$extraHeader = array(
    "key1" => "value1"
);

// iss, exp and iat are automatic created by the function
$token = $jwt->generate($payload, "+5 minutes", $extraHeader);

$extraVerification = array(
    "header" => array(
        "key1" => array(
            "method"           => "equal", // equal more less equal-more equal-less
            "value"            => "value1",
            "on_error_message" => "Wrong key value"
        )
    ),
    "payload" => array(
        "key2" => array(
            "method"           => "less",
            "value"            => 1,
            "on_error_message" => "Wrong key value"
        )
    )
);

$jwt->decodeToken($token, true, $extraVerification);
```
