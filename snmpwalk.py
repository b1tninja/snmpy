import argparse
import asyncio
import logging

import asynqp

from config import bind_host, bind_port
from config import db_user, db_password, db_name, db_host, db_port
from config import mq_user, mq_password, mq_exchange, mq_host, mq_port
from snmp.database import Database
from snmp.datagram import SNMPDatagram
from snmp.pdus import GetNextRequest, GetResponse
from snmp.protocol import SNMPProtocol

# logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.DEBUG)


# logging.basicConfig(filename='/tmp/snmpy.log',level=logging.DEBUG)

class MessageQueue:
    def __init__(self):
        self.connection = None
        self.channel = None
        self.exchange = None
        self.task_queue = None

    @asyncio.coroutine
    def setup(self, user=None, password=None, exchange=None, host=None, port=None, queue_size=None):
        if host is None:
            host = 'localhost'
        if port is None:
            port = 5672
        if user is None:
            user = 'guest'
        if password is None:
            password = 'guest'
        if exchange is None:
            exchange = 'snmp'

        self.connection = yield from asynqp.connect(host, port, username=user, password=password)
        self.channel = yield from self.connection.open_channel()
        if queue_size:
            yield from self.channel.set_qos(prefetch_count=queue_size)
        self.exchange = yield from self.channel.declare_exchange(exchange, 'direct', durable=True)
        self.task_queue = yield from self.channel.declare_queue('tasks')
        yield from self.task_queue.bind(self.exchange, 'pending_task')

    @asyncio.coroutine
    def close(self):
        yield from self.channel.close()
        yield from self.connection.close()

    def queue_task(self, coro, *args, **kwargs):
        # TODO: decorator + coro.__name__ map?
        logging.debug("Queing %s(args=%s,kwargs=%s)" % (coro, args, kwargs))
        message = asynqp.Message({'coro': coro, 'args': args, 'kwargs': kwargs})
        self.exchange.publish(message, 'pending_task')

    @asyncio.coroutine
    def get_tasks(self, n):
        tasks = []
        for m in range(n):
            message = yield from self.task_queue.get()
            if message:
                tasks.append(message)
            else:
                break
        return tasks


class ExceededRetries(Exception):
    pass


class SNMPWalk(object):
    def __init__(self, snmp_protocol, mq, db):
        assert isinstance(snmp_protocol, SNMPProtocol)
        self.snmp_protocol = snmp_protocol
        assert isinstance(mq, MessageQueue)
        self.mq = mq
        assert isinstance(db, Database)
        self.db = db

    @asyncio.coroutine
    def walk(self, host, oid=None, port=161, timeout=2, retries=3):
        # TODO: decouple the db, perhaps a callback for each GetResponse?
        datagram = SNMPDatagram(pdu=GetNextRequest.from_oid(oid))
        while retries > 0:
            future = self.snmp_protocol.sendto(datagram, host, port)
            try:
                response = yield from asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                retries -= 1
            else:
                assert isinstance(response.pdu, GetResponse)
                logging.debug("Response from host %s: %s=%s", host, response.pdu.oid, response.pdu.response)
                if datagram.pdu.oid == response.pdu.oid:
                    # end of mib condition
                    return
                else:
                    yield from self.db.save_get_response(host, response.pdu.oid, response.pdu.response)
                    pdu = GetNextRequest.from_oid(response.pdu.oid)
                    datagram = SNMPDatagram(pdu=pdu)
        else:
            raise ExceededRetries('Maximum retries exceeded')

    @asyncio.coroutine
    def run(self, microthreads):
        tasks = {}
        try:
            messages = yield from mq.get_tasks(microthreads)
            while messages or tasks:
                for message in messages:
                    task_json = message.json()
                    # TODO: support other coros
                    assert task_json['coro'] == 'walk'
                    (coro, args, kwargs) = self.walk, task_json['args'], task_json['kwargs']
                    task = loop.create_task(asyncio.wait_for(coro(*args, **kwargs), timeout=600))
                    tasks[task] = message

                (done, pending) = yield from asyncio.wait(list(tasks), return_when=asyncio.FIRST_COMPLETED)
                # loop.run_forever()
                for task in done:
                    try:
                        message = tasks.pop(task)
                        result = task.result()
                    except asyncio.TimeoutError:
                        logging.warning("Task timed out: %s" % message.json())
                    except ExceededRetries:
                        logging.warning("Task exceeded maximum retry count:  %s" % message.json())
                    else:
                        logging.info("Finished task: %s" % message.json())
                        message.ack()

                messages = yield from mq.get_tasks(microthreads - len(tasks))

        finally:
            transport.close()


if __name__ == '__main__':
    simultaneous_hosts = 1000
    loop = asyncio.get_event_loop()
    mq = MessageQueue()
    loop.run_until_complete(
            mq.setup(user=mq_user, password=mq_password, exchange=mq_exchange, host=mq_host, port=mq_port,
                     queue_size=simultaneous_hosts))

    parser = argparse.ArgumentParser(description='Walks SNMP MIB for multiple hosts asynchrously, and saves responses.')
    parser.add_argument('--queue', action='store', help="File containing list of ip addresses.")

    args = parser.parse_args()
    if args.queue:
        # Queue tasks
        for line in open(args.queue, 'r'):
            host = line.strip()
            mq.queue_task('walk', host)
    else:
        # Do tasks
        snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=(bind_host, bind_port))
        transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)

        db = Database()
        loop.run_until_complete(
                db.connect(user=db_user, password=db_password, database=db_name, host=db_host, port=db_port))

        snmpwalk = SNMPWalk(protocol, mq, db)
        loop.run_until_complete(snmpwalk.run(simultaneous_hosts))

        # Clean-up
        db.close()
        transport.close()
        # loop.run_until_complete(mq.close())
    loop.close()
