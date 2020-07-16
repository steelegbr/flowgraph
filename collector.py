'''
    NetFlow Collector for data ingestion.
    Based on the reference collector from https://github.com/bitkeks/python-netflow-v9-softflowd
'''

import argparse
import netflow
import ipaddress
import logging
import queue
import socket
import socketserver
import threading
import time
from collections import namedtuple
from datetime import datetime

RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
logger = logging.getLogger("collector")

class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        self.server.queue.put(RawPacket(time.time(), self.client_address, data))
        (address, port) = self.client_address
        logger.info(f"Received {len(data)} bytes of data from {address}:{port}")


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """

    def __init__(self, interface, queue):
        self.queue = queue
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6

        super().__init__(interface, QueuingRequestHandler)


class Collector(threading.Thread):
    '''
        The NetFlow collector.
    '''

    port = 0
    input = None
    server = None
    TIMEOUT = 3600
    PROTOCOL_MAP = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        58: 'IPv6-ICMP'
    }

    def _check_port(self, value):

        # Make sure it's a number

        try:
            intvalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f'{value} is not a valid UDP port number.')

        # And in the right range

        if intvalue < 1 or intvalue > 65535:
            raise argparse.ArgumentTypeError(f'{value} is not a valid UDP port number.')

        return intvalue

    def _parse_command_line(self):
        '''
            Parses the command line arguments.
        '''

        parser = argparse.ArgumentParser(description='FlowGraph NetFlow collector.')
        parser.add_argument(
            '--port',
            type=self._check_port,
            help='The port to run the NetFlow collector on.',
            required=True
        )

        args = parser.parse_args()
        self.port = args.port

    def __init__(self):
        '''
            Initialises the collector.
        '''

        # Setup the collector

        self._parse_command_line()
        self.output = queue.Queue
        self.input = queue.Queue()
        self.server = QueuingUDPListener(('0.0.0.0', self.port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def _protocol_to_friendly(self, protocol):
        '''
            Changes a protocol number into a friendly string
        '''

        if protocol in self.PROTOCOL_MAP.keys():
            return self.PROTOCOL_MAP[protocol]
        else:
            return protocol

    def _process_export(self, export):
        '''
            Processess a frame exported to our collector
        '''

        # Calculate the boot time (used for flow start/end)

        boot_time = export.header.timestamp - export.header.uptime

        # Process the child flows

        for flow in export.flows:
                #print(flow)

                # Pull out our source and destination

                if not hasattr(flow, 'IP_PROTOCOL_VERSION') or flow.IP_PROTOCOL_VERSION is 4:
                    src_ip = ipaddress.ip_address(flow.IPV4_SRC_ADDR)
                    dst_ip = ipaddress.ip_address(flow.IPV4_DST_ADDR)
                else:
                    src_ip = ipaddress.ip_address(flow.IPV6_SRC_ADDR)
                    dst_ip = ipaddress.ip_address(flow.IPV6_DST_ADDR)

                # Calculate the flow start time

                start_time = datetime.fromtimestamp(flow.FIRST_SWITCHED + boot_time)
                end_time = datetime.fromtimestamp(flow.LAST_SWITCHED + boot_time)

                # Shunt to storage

                print(f'{src_ip}:{flow.L4_SRC_PORT} -> {dst_ip}:{flow.L4_DST_PORT} [{self._protocol_to_friendly(flow.PROTOCOL)}] {start_time} -> {end_time}')
        

    def run(self):
        '''
            Runs the collector
        '''

        # Templates we build out from the NetFlow v9 or IPFIX source

        templates = {"netflow": {} , "ipfix": {}}
        to_retry = []

        # Process packets forever

        while True:

            # Read from the input queue

            try:
                payload = self.input.get(block=True, timeout=0.5)
            except queue.Empty:
                continue

            try:
                export = netflow.parse_packet(payload.data, templates)
            except netflow.utils.UnknownExportVersion as e:
                logger.error(f"Unknown version: {e}")
                continue
            except (netflow.v9.V9TemplateNotRecognized, netflow.ipfix.IPFIXTemplateNotRecognized) as e:
                if (time.time() - payload.ts) > self.TIMEOUT:
                    logger.error("Dropping timed out packet.")
                else:
                    to_retry.append(payload)
                    logger.warning("Adding to queue to retry later (as templates update).")
                continue

            # Process the flows

            self._process_export(export)

            # Look for templates to re-process flows with

            if export.header.version in [9, 10] and export.contains_new_templates and to_retry:
                logger.info(f"New templates recieved! Reprocessing {len(to_retry)} frames.")
                for retry_payload in to_retry:
                    retry_export = netflow.parse_packet(retry_payload.data, templates)
                    self._process_export(retry_export)
                to_retry.clear()

if __name__ == "__main__":
    Collector().start()