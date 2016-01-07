import asyncio

from snmp.database import Database
from snmp.protocol import SNMPProtocol

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    db = Database()
    loop.run_until_complete(db.connect(user='snmp', password='public', database='snmp', host='localhost'))
    snmp_protocol_startup_task = loop.create_datagram_endpoint(lambda: SNMPProtocol(db), local_addr=('127.0.0.1', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    try:
        assert isinstance(protocol, SNMPProtocol)
        try:
            task = asyncio.wait_for(protocol.walk('127.0.0.1'), timeout=120)
            loop.run_until_complete(task)
        except asyncio.TimeoutError:
            print("Task timed out...")
        else:
            print("Done")
            loop.run_until_complete(db.connection.close())
            # loop.run_forever()

    finally:
        transport.close()
        loop.close()
