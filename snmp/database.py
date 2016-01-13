import asyncio

import aiopg
from snmp.pdus import Object, ObjectIdentifier

class Database:
    def __init__(self):
        self.connection_pool = None

    @asyncio.coroutine
    def connect(self, **kwargs):
        self.connection_pool = yield from aiopg.create_pool(**kwargs)

    def close(self):
        self.connection_pool.close()

    @asyncio.coroutine
    def save_get_response(self, host, oid, response):
        # assert isinstance(host, str)
        assert isinstance(oid, ObjectIdentifier)
        assert isinstance(response, Object)
        with (yield from self.connection_pool.cursor()) as cursor:
            yield from cursor.execute(
                    "INSERT INTO getresponse (host, object_identifier, tag, value) VALUES (%s, %s, %s, %s)",
                    (host, bytes(oid), bytes(response.tag), bytes(response.value)))

    @asyncio.coroutine
    def save_get_responses(self, host, responses):
        # assert isinstance(host, str)
        assert isinstance(responses, list)
        for oid, response in responses:
            assert isinstance(oid, ObjectIdentifier)
            assert isinstance(response, Object)
        with (yield from self.connection_pool.cursor()) as cursor:
            # ret = yield from cursor.execute("WITH walk AS (INSERT INTO walks (host) VALUES (%s) RETURNING id) SELECT id from walk", (host,))
            yield from cursor.executemany(
                    "INSERT INTO getresponse (host, object_identifier, tag, value) VALUES (%s, %s, %s, %s)",
                    [(host, bytes(oid), bytes(response.tag), bytes(response.value)) for oid, response in responses])
