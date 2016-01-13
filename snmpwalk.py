import argparse
import asyncio
import logging

import asynqp
from config import bind_host, bind_port
from config import db_user, db_password, db_name, db_host, db_port
from config import mq_user, mq_password, mq_exchange, mq_host, mq_port
from snmp.database import Database
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
        self.task_queue = yield from self.channel.declare_queue('tasks', durable=True)
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
            try:
                message = yield from self.task_queue.get()
            except ConnectionError:
                logging.error("Message queue is not connected!")
                yield from asyncio.sleep(1)
            else:
                if message:
                    tasks.append(message)
                else:
                    break
        return tasks


class SNMPWalk(object):
    def __init__(self, snmp_protocol, mq, db):
        assert isinstance(snmp_protocol, SNMPProtocol)
        self.snmp_protocol = snmp_protocol
        assert isinstance(mq, MessageQueue)
        self.mq = mq
        assert isinstance(db, Database)
        self.db = db

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
                    (coro, args, kwargs) = self.snmp_protocol.walk, task_json['args'], task_json['kwargs']
                    task = loop.create_task(asyncio.wait_for(coro(*args, **kwargs), timeout=3))
                    task.add_done_callback(lambda result: message.ack())
                    tasks[task] = (coro, args, kwargs)

                (done, pending) = yield from asyncio.wait(list(tasks), return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    (coro, args, kwargs) = tasks.pop(task)
                    (host,) = args
                    try:
                        result = task.result()
                    except asyncio.TimeoutError:
                        logging.warning("Task timed out: %s" % host)
                    except Exception as e:
                        logging.error(e)
                    # except ExceededRetries:
                    #     # TODO: probably should just log the responses we did rx if any
                    #     logging.warning("Task exceeded maximum retry count:  %s" % host)
                    else:
                        if result:
                            self.db.save_get_response(host, result)
                        logging.info("Task finished: %s, %d responses." % (host, len(result)))
                try:
                    messages = yield from mq.get_tasks(microthreads - len(tasks))
                except:
                    messages = []

        finally:
            transport.close()


if __name__ == '__main__':
    simultaneous_hosts = 100
    loop = asyncio.get_event_loop()
    logging.debug("Connecting to message queue")
    mq = MessageQueue()
    loop.run_until_complete(
            mq.setup(user=mq_user, password=mq_password, exchange=mq_exchange, host=mq_host, port=mq_port,
                     queue_size=simultaneous_hosts))

    logging.debug("Connected to message queue")
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
