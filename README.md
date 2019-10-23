eIDAS Specific Node
===================

An implementation of **eIDAS-Node 2.3.x** Specific **Connector** and **Proxy Service** for Django.

Requirements
------------

- [Django](https://docs.djangoproject.com) 2.2.x
- [Django AppSettings](https://pypi.org/project/django-app-settings/) >= 0.5
- [lxml](https://pypi.org/project/lxml/)
- [xmlsec](https://pypi.org/project/xmlsec/)
- [Apache Ignite Python client](https://pypi.org/project/pyignite/) (optional)

Specific Proxy Service
----------------------

Sample settings are provided in [`samples/proxy_service_settings.py`](samples/proxy_service_settings.py).

### Usage

To use eIDAS Proxy Service, adjust Django settings:

* Set up  Django template engine and static files.
* Add `'eidas_node.proxy_service.apps.ProxyServiceConfig'` to `INSTALLED_APPS`.
* Set `ROOT_URLCONF` to `'eidas_node.proxy_service.urls'` or include it in your URL configuration.
* Provide mandatory configuration options `PROXY_SERVICE_REQUEST_TOKEN`, `PROXY_SERVICE_RESPONSE_TOKEN`, `PROXY_SERVICE_LIGHT_STORAGE`, and `PROXY_SERVICE_IDENTITY_PROVIDER` (see below).

### Settings

#### `PROXY_SERVICE_REQUEST_TOKEN`

Settings of **a light token corresponding to an incoming light request**.
A dictionary with following items:

* `HASH_ALGORITHM` (optional, default `'sha256'`): A hash algorithm used for token digest.
* `SECRET` (required): A token secret shared with eIDAS node.
* `ISSUER` (required): An issuer of the light token.
* `LIFETIME` (optional, default `10`): A lifetime of the light token in minutes until is its considered expired.
   Set to `0` for unlimited lifetime.
* `PARAMETER_NAME` (optional, default `'token'`): The name of the HTTP POST parameter to provide encoded light token.

#### `PROXY_SERVICE_RESPONSE_TOKEN`

Settings of **a light token corresponding to an outgoing light response**.
A dictionary with following items:

* `HASH_ALGORITHM` (optional, default `'sha256'`): A hash algorithm used for token digest.
* `SECRET` (required): A token secret shared with eIDAS node.
* `ISSUER` (required): An issuer of the light token.
* `PARAMETER_NAME` (optional, default `'token'`): The name of the HTTP POST parameter to provide encoded light token.

#### `PROXY_SERVICE_LIGHT_STORAGE`

Settings for **a storage of light requests and responses**.
A dictionary with following items:

* `BACKEND` (optional, default `'eidas_node.storage.ignite.IgniteStorage'`): The backend class for communication with the light storage.
* `OPTIONS` (required): A dictionary with configuration of the selected backend.
  The `IgniteStorage` backend expects following options:
  - `host`: Apache Ignite service host.
  - `port`: Apache Ignite service port.
  - `request_cache_name`: The cache to retrieve light requests (e.g., `nodeSpecificProxyserviceRequestCache`).
  - `response_cache_name`: The cache to store light responses (e.g., `specificNodeProxyserviceResponseCache`).
  - `timeout`: A timeout for socket operations.

#### `PROXY_SERVICE_IDENTITY_PROVIDER`

Settings for **the interaction with Identity Provider**.
A dictionary with following items:

* `ENDPOINT` (required): The URL where the Identity Provider expects authentication requests.
* `REQUEST_ISSUER` (required): The issuer of the authentication request registered at Identity Provider.
* `KEY_FILE` (optional, default `None`): The path of a key to decrypt Identity Provider's authentication response.
* `CERT_FILE` (optional, default `None`): The path of a certificate to verify the signature of Identity Provider's authentication response.
* `REQUEST_SIGNATURE` (dictionary, optional): Options for signing SAML requests sent to Service Provider:
  * `KEY_FILE` (required, string): The path to a signing key.
  * `CERT_FILE`: (required, string): The path to the corresponding certificate.
  * `SIGNATURE_METHOD` (optional, string, default `RSA_SHA512`): XML signature method.
  * `DIGEST_METHOD` (optional, string, default `SHA512`): XML digest method.

#### `PROXY_SERVICE_EIDAS_NODE`

Settings for **the interaction with eIDAS Node**.
A dictionary with following items:

* `PROXY_SERVICE_RESPONSE_URL` (required): The URL where eIDAS Node expects authentication responses (e.g.,
  `https://test.example.net/EidasNode/SpecificProxyServiceResponse`).
* `RESPONSE_ISSUER` (required): The issuer for light responses specified in eIDAS Node configuration.

### Customization

You can customize the authorization flow by subclassing view classes in [`eidas_node.proxy_service.views`](eidas_node/proxy_service/views.py), overriding necessary methods and adjusting URL configuration.

### CZ NIA

[`eidas_node.proxy_service.cznia`](eidas_node/proxy_service/cznia) (`ROOT_URLCONF =
'eidas_node.proxy_service.cznia.urls'`) contains modifications required for CZ NIA (the official identity provider of the Czech Republic) with following settings:

* `PROXY_SERVICE_STRIP_PREFIX` (boolean, optional, default `False`): If the *Subject ID* starts with a `'CZ/CZ/'` prefix, it is stripped.

Specific Connector
------------------

Sample settings are provided in [`samples/connector_settings.py`](samples/connector_settings.py).

### Usage

To use eIDAS Connector, adjust Django settings:

* Set up  Django template engine and static files.
* Add `'eidas_node.connector.apps.ConnectorConfig'` to `INSTALLED_APPS`.
* Set `ROOT_URLCONF` to `'eidas_node.connector.urls'` or include it in your URL configuration.
* Provide mandatory configuration options `CONNECTOR_REQUEST_TOKEN`, `CONNECTOR_RESPONSE_TOKEN`, `CONNECTOR_LIGHT_STORAGE`, and `CONNECTOR_SERVICE_PROVIDER` (see below).

### Views

Setting `ROOT_URLCONF` to `eidas_node.connector.urls` will provide you with three main views:

* `/CountrySelector`:
  Accepts a *SAML Request* and *Relay State* from Service Provider and lets user select his/her *country* unless it has already been provided.
  The SAML Request is then forwarded to `/ServiceProviderRequest` endpoint.
  - Method: HTTP POST.
  - POST Parameters:
    - `SAMLRequest` (required): A SAML request to forward to eIDAS Network.
    - `RelayState` (required): A relay state.
    - `country` or the value set in `CONNECTOR_SERVICE_PROVIDER['COUNTRY_PARAMETER']` (optional): Citizen country code.

* `/ServiceProviderRequest`:
  Accepts a *SAML Request*, *Relay State* and *citizen country code* from Service Provider and forwards the request to eIDAS Network.
  - Method: HTTP POST.
  - POST Parameters:
    - `SAMLRequest` (required): A SAML request to forward to eIDAS Network.
    - `RelayState` (required): A relay state.
    - `country` or the value set in `CONNECTOR_SERVICE_PROVIDER['COUNTRY_PARAMETER']` (required): Citizen country code.

* `/ConnectorResponse`:
  Accepts a light token from eIDAS Network and forwards corresponding light response to Service Provider.
  - Method: HTTP POST.
  - POST Parameters:
    - `token` or the value set in `CONNECTOR_RESPONSE_TOKEN['PARAMETER_NAME']`(required): A light token corresponding to a light response.

Setting `ROOT_URLCONF` to `eidas_node.connector.demo.urls` will provide you with two additional views:

* `/DemoServiceProviderRequest`:
  A demo service provider page for sending preset SAML requests to Specific Connector.
* `/DemoServiceProviderResponse`:
  A demo service provider page for displaying SAML responses from Specific Connector.

### Settings

#### `CONNECTOR_REQUEST_TOKEN`

Settings of **a light token corresponding to an outgoing light request**.
A dictionary with following items:

* `HASH_ALGORITHM` (optional, default `'sha256'`): A hash algorithm used for token digest.
* `SECRET` (required): A token secret shared with eIDAS node.
* `ISSUER` (required): An issuer of the light token.
* `PARAMETER_NAME` (optional, default `'token'`): The name of the HTTP POST parameter to provide encoded light token.

#### `CONNECTOR_RESPONSE_TOKEN`

Settings of **a light token corresponding to an incoming light response**.
A dictionary with following items:

* `HASH_ALGORITHM` (optional, default `'sha256'`): A hash algorithm used for token digest.
* `SECRET` (required): A token secret shared with eIDAS node.
* `ISSUER` (required): An issuer of the light token.
* `PARAMETER_NAME` (optional, default `'token'`): The name of the HTTP POST parameter to provide encoded light token.
* `LIFETIME` (optional, default `10`): A lifetime of the light token in minutes until is its considered expired.
   Set to `0` for unlimited lifetime.

#### `CONNECTOR_LIGHT_STORAGE`

Settings for **a storage of light requests and responses**.
A dictionary with following items:

* `BACKEND` (optional, default `'eidas_node.storage.ignite.IgniteStorage'`): The backend class for communication with the light storage.
* `OPTIONS` (required): A dictionary with configuration of the selected backend.
  The `IgniteStorage` backend expects following options:
  - `host`: Apache Ignite service host.
  - `port`: Apache Ignite service port.
  - `request_cache_name`: The cache to retrieve light requests (e.g., `specificNodeConnectorRequestCache`).
  - `response_cache_name`: The cache to store light responses (e.g., `nodeSpecificConnectorResponseCache`).
  - `timeout`: A timeout for socket operations in seconds.

#### `CONNECTOR_SERVICE_PROVIDER`

Settings for **the interaction with Service Provider**.
A dictionary with following items:

* `ENDPOINT` (required): The URL where the Service Provider expects authentication responses.
* `CERT_FILE` (optional, default `None`): The path of a certificate to verify the signature of Service Provider's authentication requests.
* `REQUEST_ISSUER` (required): The expected issuer of the Service Provider's authentication request.
* `RESPONSE_ISSUER` (required): The issuer of the authentication response registered at Service Provider.
* `COUNTRY_PARAMETER` (optional, default `country`): The name of a POST parameter containing citizen country code for `/CitizenCountrySelector` and `/ServiceProviderRequest` views.
* `RESPONSE_SIGNATURE` (dictionary, optional): Options for signing SAML responses returned to Service Provider:
  * `KEY_FILE` (required, string): The path to a signing key.
  * `CERT_FILE`: (required, string): The path to the corresponding certificate.
  * `SIGNATURE_METHOD` (optional, string, default `RSA_SHA512`): XML signature method.
  * `DIGEST_METHOD` (optional, string, default `SHA512`): XML digest method.
* `RESPONSE_VALIDITY` (int, optional, default 10): The validity of the SAML response in minutes.

#### `CONNECTOR_EIDAS_NODE`

Settings for **the interaction with eIDAS Node**.
A dictionary with following items:

* `CONNECTOR_REQUEST_URL` (required): The URL where eIDAS Node expects authentication requests (e.g., `https://test.example.net/EidasNode/SpecificConnectorRequest`).
* `REQUEST_ISSUER` (required): The issuer for light requests specified in eIDAS Node configuration.

#### `CONNECTOR_ALLOWED_ATTRIBUTES`

A set containing URI names (strings, e.g. `'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'`) of attributes that a service provider can request.
Other attributes are dropped from the authentication request.
All eIDAS natural and legal person attributes are enabled by default.
An empty set disables the filter.

#### `CONNECTOR_SELECTOR_COUNTRIES`

A list of pairs with country code and name to be displayed in citizen country selector (`/CitizenCountrySelector`).
Default is all 28 countries of EU.

### Customization

You can customize the authorization flow by subclassing view classes in [`eidas_node.connector.views`](eidas_node/connector/views.py), overriding necessary methods and adjusting URL configuration.

Copyright
---------

* The django-eidas-specific-node project:
  * Copyright 2019 CZ.NIC, z. s. p. o.
  * License: [GPL-3+](COPYRIGHT)
* [Country flags](eidas_node/connector/static/eidas_node/connector/img/flags):
  * Copyright 2013 Panayiotis Lipiridis
  * License: [MIT](eidas_node/connector/static/eidas_node/connector/img/flags/LICENSE)
