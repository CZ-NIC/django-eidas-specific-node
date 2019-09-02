eIDAS Specific Node
===================

An implementation of **eIDAS-Node 2.3.x** Specific **Connector** and **Proxy Service** for Django.

Requirements
------------

- [Django](https://docs.djangoproject.com) 2.2.x
- [Django AppSettings](https://pypi.org/project/django-app-settings/)
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

Not yet implemented.
