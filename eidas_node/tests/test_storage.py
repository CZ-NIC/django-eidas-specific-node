from typing import BinaryIO, Callable, TextIO, cast
from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase

from eidas_node.models import LightRequest, LightResponse
from eidas_node.storage import get_auxiliary_storage
from eidas_node.storage.ignite import AuxiliaryIgniteStorage, IgniteStorage
from eidas_node.tests.test_models import DATA_DIR
from eidas_node.xml import parse_xml


class IgniteMockMixin:
    cache_mock:  MagicMock
    client_mock:  MagicMock
    client_class_mock:  MagicMock

    def mock_ignite_cache(self) -> Callable[[], None]:
        """Mock Apache Ignite cache and return a callback to stop the patcher."""
        self.cache_mock = MagicMock(spec_set=['get_and_remove', 'put'])
        self.client_mock = MagicMock(spec_set=['connect', 'get_cache'])
        self.client_mock.get_cache.return_value = self.cache_mock
        client_class_patcher = patch('eidas_node.storage.ignite.Client', return_value=self.client_mock)
        self.client_class_mock = client_class_patcher.start()
        return client_class_patcher.stop


class TestIgniteStorage(IgniteMockMixin, SimpleTestCase):
    HOST = 'localhost.example.net'
    PORT = 12345
    REQUEST_CACHE_NAME = 'RequestCacheTest'
    RESPONSE_CACHE_NAME = 'ResponseCacheTest'

    def setUp(self):
        self.addCleanup(self.mock_ignite_cache())
        self.storage = IgniteStorage(self.HOST, self.PORT, self.REQUEST_CACHE_NAME, self.RESPONSE_CACHE_NAME, 33)

    def test_get_cache_single_client_created(self):
        self.assertIs(self.storage.get_cache(self.REQUEST_CACHE_NAME), self.cache_mock)
        self.assertIs(self.storage.get_cache(self.RESPONSE_CACHE_NAME), self.cache_mock)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.REQUEST_CACHE_NAME),
                          call.get_cache(self.RESPONSE_CACHE_NAME)])

    def test_pop_light_request_not_found(self):
        self.cache_mock.get_and_remove.return_value = None
        self.assertIsNone(self.storage.pop_light_request('abc'))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.REQUEST_CACHE_NAME),
                          call.get_cache().get_and_remove('abc')])

    def test_pop_light_request_found(self):
        with cast(BinaryIO, (DATA_DIR / 'light_request.xml').open('rb')) as f:
            data = f.read()

        self.cache_mock.get_and_remove.return_value = data.decode('utf-8')
        self.assertEqual(LightRequest.load_xml(parse_xml(data)), self.storage.pop_light_request('abc'))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.REQUEST_CACHE_NAME),
                          call.get_cache().get_and_remove('abc')])

    def test_pop_light_response_not_found(self):
        self.cache_mock.get_and_remove.return_value = None
        self.assertIsNone(self.storage.pop_light_response('abc'))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.RESPONSE_CACHE_NAME),
                          call.get_cache().get_and_remove('abc')])

    def test_pop_light_response_found(self):
        with cast(BinaryIO, (DATA_DIR / 'light_response.xml').open('rb')) as f:
            data = f.read()

        self.cache_mock.get_and_remove.return_value = data.decode('utf-8')
        self.assertEqual(LightResponse.load_xml(parse_xml(data)), self.storage.pop_light_response('abc'))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.RESPONSE_CACHE_NAME),
                          call.get_cache().get_and_remove('abc')])

    def test_put_light_request(self):
        with cast(TextIO, (DATA_DIR / 'light_request.xml').open('r')) as f:
            data = f.read()

        request = LightRequest.load_xml(parse_xml(data))
        self.storage.put_light_request('abc', request)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.REQUEST_CACHE_NAME),
                          call.get_cache().put('abc', data)])

    def test_put_light_response(self):
        with cast(TextIO, (DATA_DIR / 'light_response.xml').open('r')) as f:
            data = f.read()

        response = LightResponse.load_xml(parse_xml(data))
        self.storage.put_light_response('abc', response)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.RESPONSE_CACHE_NAME),
                          call.get_cache().put('abc', data)])


class TestAuxiliaryIgniteStorage(IgniteMockMixin, SimpleTestCase):
    HOST = 'localhost.example.net'
    PORT = 12345
    CACHE_NAME = 'CacheTest'
    PREFIX = 'test-prefix-'

    def setUp(self):
        self.addCleanup(self.mock_ignite_cache())

    def test_get_cache_single_client_created(self):
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33, self.PREFIX)
        self.assertIs(storage.get_cache("cache1"), self.cache_mock)
        self.assertIs(storage.get_cache("cache2"), self.cache_mock)
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache("cache1"),
                          call.get_cache("cache2")])

    def test_pop_not_found(self):
        self.cache_mock.get_and_remove.return_value = None
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33, self.PREFIX)
        self.assertIsNone(storage.pop('abc'))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.CACHE_NAME),
                          call.get_cache().get_and_remove('test-prefix-abc')])

    def test_pop_found(self):
        self.cache_mock.get_and_remove.return_value = '{"foo": true}'
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33, self.PREFIX)
        self.assertEqual(storage.pop('abc'), {"foo": True})
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.CACHE_NAME),
                          call.get_cache().get_and_remove('test-prefix-abc')])

    def test_pop_without_prefix(self):
        self.cache_mock.get_and_remove.return_value = '{"foo": true}'
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33)
        self.assertEqual(storage.pop('abc'), {"foo": True})
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.CACHE_NAME),
                          call.get_cache().get_and_remove('abc')])

    def test_put(self):
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33, self.PREFIX)
        storage.put('abc', {"foo": True})
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.CACHE_NAME),
                          call.get_cache().put('test-prefix-abc', '{"foo": true}')])

    def test_put_without_prefix(self):
        storage = AuxiliaryIgniteStorage(self.HOST, self.PORT, self.CACHE_NAME, 33)
        storage.put('abc', {"foo": True})
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.CACHE_NAME),
                          call.get_cache().put('abc', '{"foo": true}')])


class TestGetAuxiliaryStorage(IgniteMockMixin, SimpleTestCase):
    @patch('eidas_node.storage.ignite.IgniteStorage')
    def test_ignite(self, storage_mock):
        storage = get_auxiliary_storage(
            'eidas_node.storage.ignite.IgniteStorage',
            {
                'host': 'example.org',
                'port': 1234,
                'cache_name': 'nodeSpecificProxyserviceRequestCache',
            })
        self.assertIsInstance(storage, MagicMock)
        self.assertSequenceEqual(storage_mock.mock_calls, [
            call(
                host='example.org', port=1234,
                cache_name='nodeSpecificProxyserviceRequestCache'
            )
        ])

    def test_import_error(self):
        self.assertRaises(
            ImportError, get_auxiliary_storage,
            'eidas_node.storage.none.NullStorage',
            {
                'host': 'example.org',
                'port': 1234,
            })
