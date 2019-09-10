from typing import BinaryIO, Callable, TextIO, cast
from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase

from eidas_node.models import LightRequest, LightResponse
from eidas_node.storage.ignite import IgniteStorage
from eidas_node.tests.test_models import DATA_DIR
from eidas_node.utils import parse_xml


class IgniteMockMixin:
    cache_mock = None  # type:  MagicMock
    client_mock = None  # type:  MagicMock
    client_class_mock = None  # type:  MagicMock

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
        self.assertIsNone(self.storage.put_light_request('abc', request))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.REQUEST_CACHE_NAME),
                          call.get_cache().put('abc', data)])

    def test_put_light_response(self):
        with cast(TextIO, (DATA_DIR / 'light_response.xml').open('r')) as f:
            data = f.read()

        response = LightResponse.load_xml(parse_xml(data))
        self.assertIsNone(self.storage.put_light_response('abc', response))
        self.assertEqual(self.client_class_mock.mock_calls, [call(timeout=33)])
        self.assertEqual(self.client_mock.mock_calls,
                         [call.connect(self.HOST, self.PORT),
                          call.get_cache(self.RESPONSE_CACHE_NAME),
                          call.get_cache().put('abc', data)])
