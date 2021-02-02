CHANGELOG
=========

UNRELEASED
----------

0.8.0 [2021-02-02]
------------------

### New features

* Alligning with CEF eIDAS Node 2.5
    * Include namespaces in LightRequest/LightResponse
    * Add RequesterId to LightRequest
    * Add Consent to LightResponse
    * Rename originCountryCode to spCountryCode in LightRequest/LightResponse

0.7.0 [2020-07-08]
------------------

### Breaking changes

* `django-app-settings >=0.7.1` is required.
* Settings `PROXY_SERVICE_IDENTITY_PROVIDER['REQUEST_SIGNATURE']`, `CONNECTOR_SERVICE_PROVIDER['RESPONSE_SIGNATURE']` and `CONNECTOR_SERVICE_PROVIDER['RESPONSE_ENCRYPTION']` are required.
  However, you can use an empty dict `{}` to disable these features.

### New features

* A workaround to support *the transient name ID format* even though it isn't supported by the Identity Provider.
  See the `PROXY_SERVICE_TRANSIENT_NAME_ID_FALLBACK` setting.
* The country code of the request may be logged when the corresponding response is received.
  See the `CONNECTOR_TRACK_COUNTRY_CODE` and `PROXY_SERVICE_TRACK_COUNTRY_CODE` settings.
* New settings `CONNECTOR_AUXILIARY_STORAGE` and `PROXY_SERVICE_AUXILIARY_STORAGE`.

### Bug fixes

* Fixed bug when light token was created with a local creation date but compared with UTC time.
