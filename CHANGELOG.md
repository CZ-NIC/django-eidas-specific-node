CHANGELOG
=========

UNRELEASED
----------

### Breaking changes

* `django-app-settings >=0.7.1` is required.
* Settings `PROXY_SERVICE_IDENTITY_PROVIDER['REQUEST_SIGNATURE']`, `CONNECTOR_SERVICE_PROVIDER['RESPONSE_SIGNATURE']` and `CONNECTOR_SERVICE_PROVIDER['RESPONSE_ENCRYPTION']` are required.
  However, you can use an empty dict `{}` to disable these features.
