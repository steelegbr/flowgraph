'''
    Provides the tools to find interesting flows and build graphs.
'''

import argparse
import logging
import networkx as nx
import sys
from store import AnalyticsFlowStore, DatabaseSettings

# Rough and ready logging

logger = logging.getLogger("analytics")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


class FlowFinder:
    '''
        Tries to locate interesting flows in the datastore.
    '''

    store = None
    logger = None

    INTERESTING_PROTOCOLS = [
        (6, 22, 'SSH'),
        (6, 3389, 'RDP (TCP)'),
        (17, 3389, 'RDP (UDP)'),
        (6, 5985, 'WinRM'),
        (6, 5986, 'WinRM (TLS)')
    ]

    def __init__(self, logger, database_settings):
        '''
            Creates a new instance of the flow finder.
        '''

        self.logger = logger
        self.store = AnalyticsFlowStore(logger, database_settings)

    def _find_child_flows(self, parent, graph, start, end, seen_nodes):
        '''
            Attempts to find child flows and add them to our graph.
        '''

        # Check we've not already been visited
        # Make a note so we don't loop ;)

        if (parent in seen_nodes):
            return
        else:
            seen_nodes.add(parent)

        # Perform the search

        for protocol, port, label in self.INTERESTING_PROTOCOLS:
            logger.info(f"Attempting to find child flows matching protocol {protocol} port {port} on {parent}.")
            for flow in self.store.get_interseting_flows_deep(protocol, port, parent, start, end):

                # Add the child flows to the graph

                logger.debug(f"Found child flow for {parent}: {flow}")
                graph.add_nodes_from([flow.source_address, flow.destination_address])
                graph.add_edge(flow.source_address, flow.destination_address, object=label)

                # Iterate down

                self._find_child_flows(flow.destination_address, graph, start, end, seen_nodes)

    def build_graphs(self):
        '''
            Builds the interesting flow graphs.
        '''

        graphs = []

        for protocol, port, label in self.INTERESTING_PROTOCOLS:
            logger.info(f"Attempting to find flows matching protocol {protocol} port {port}...")
            for flow in self.store.get_interseting_flows(protocol, port):

                # Make a note of the nodes we've seen

                logger.debug(f"Found starting flow: {flow}")
                seen_nodes = {flow.source_address}

                # Start building our graph with our root node

                graph = nx.Graph()
                graph.add_nodes_from([flow.source_address, flow.destination_address])
                graph.add_edge(flow.source_address, flow.destination_address, object=label)

                # Work our way down the children finding more matches

                self._find_child_flows(flow.destination_address, graph, flow.start, flow.end, seen_nodes)

                # Punt our graph out

                nx.write_graphml(graph, f"{flow.source_address}_{flow.destination_address}_{flow.destination_port}_{flow.protocol}_{flow.start.timestamp()}.graphml")
                graphs.append(graph)

        return graphs
            

class Analytics:
    '''
        Ties the analytics functions together.
    '''

    database_settings = None
    finder = None

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
            Parses the command line properties.
        '''

        parser = argparse.ArgumentParser(description='FlowGraph analytics.')
        parser.add_argument(
            '--sql-server',
            help='The SQL server name.',
            required=True
        )
        parser.add_argument(
            '--sql-port',
            type=self._check_port,
            help='The port to connect to the SQL server on.',
            required=True
        )
        parser.add_argument(
            '--sql-username',
            help='The username to connect to the SQL server with.',
            required=True
        )
        parser.add_argument(
            '--sql-password',
            help='The password to connect to the SQL server with.',
            required=True
        )
        parser.add_argument(
            '--sql-database',
            help='The database to use on the SQL server.',
            required=True
        )

        args = parser.parse_args()
        self.database_settings = DatabaseSettings(
            args.sql_server,
            args.sql_port,
            args.sql_username,
            args.sql_password,
            args.sql_database
        )

    def __init__(self):
        '''
            Initialises the analytics system.
        '''

        # Read in the settings from the CLI

        self._parse_command_line()

        # Setup our flow finder

        self.finder = FlowFinder(logger, self.database_settings)

    def run(self):
        '''
            Main analytics logic.
        '''

        # Generate the graphs

        graphs = self.finder.build_graphs()

if __name__ == "__main__":
    Analytics().run()