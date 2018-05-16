# CakePHP SOAP Authenticate plugin

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE.txt)

Plugin containing AuthComponent's authenticate class for authenticating using headers.

## Requirements

* CakePHP 3.4+

## Installation

```sh
composer require dynweb-org/cakephp-soap-auth
```

## Usage

In your app's `config/bootstrap.php` add:

```php
// In config/bootstrap.php
Plugin::load('Dynweb/SoapAuth');
```

or using cake's console:

```sh
./bin/cake plugin load Dynweb/SoapAuth
```

## Configuration:

Setup `AuthComponent`:

```php
    // In your controller, for e.g. src/Api/AppController.php
```

## Working

The authentication class checks for the token in two locations:

- `HTTP_AUTHORIZATION` environment variable:

  It first checks if token is passed using `Authorization` request header.
  The value should be of form `Bearer <token>`. The `Authorization` header name
  and token prefix `Bearer` can be customzied using options `header` and `prefix`
  respectively.

  **Note:** Some servers don't populate `$_SERVER['HTTP_AUTHORIZATION']` when
  `Authorization` header is set. So it's upto you to ensure that either
  `$_SERVER['HTTP_AUTHORIZATION']` or `$_ENV['HTTP_AUTHORIZATION']` is set.

  For e.g. for apache you could use the following:

  ```
  RewriteEngine On
  RewriteCond %{HTTP:Authorization} ^(.*)
  RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
  ```

- The query string variable specified using `parameter` config:

  Next it checks if the token is present in query string. The default variable
  name is `token` and can be customzied by using the `parameter` config shown
  above.
