import asyncio

import aiopg


# from snmp.pdus import Object, ObjectIdentifier

class Database:
    def __init__(self):
        self.connection = None

    @asyncio.coroutine
    def connect(self, **kwargs):
        self.connection = yield from aiopg.connect(**kwargs)

    @asyncio.coroutine
    def save_get_response(self, host, oid, response):
        # for oid, response in responses:
        #     assert isinstance(oid, ObjectIdentifier)
        #     assert isinstance(response, Object)
        cursor = yield from self.connection.cursor()
        # ret = yield from cursor.execute("WITH walk AS (INSERT INTO walks (host) VALUES (%s) RETURNING id) SELECT id from walk", (host,))
        yield from cursor.execute(
                "INSERT INTO getresponse (host, object_identifier, tag, value) VALUES (%s, %s, %s, %s)",
                (host, bytes(oid), bytes(response.tag), bytes(response.value)))
        cursor.close()
