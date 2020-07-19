'''
    Simple(-ish) data store for flows.
'''

import queue
import threading
import uuid
from sqlalchemy import Column, Integer, DateTime, create_engine, or_, and_, MetaData
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote

Base = declarative_base()

class Flow(Base):
    '''
        Represents a flow in the database.
    '''

    __tablename__ = 'flows'

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False
    )

    source_address = Column(
        INET,
        nullable=False
    )

    destination_address = Column(
        INET,
        nullable=False
    )

    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(Integer)
    start = Column(DateTime)
    end = Column(DateTime)

    def __repr__(self):
        return f"{self.source_address}:{self.source_port} -> {self.destination_address}:{self.destination_port} [{self.protocol}]"

class DatabaseSettings:
    '''
        Stores the settings for the database.
    '''

    server = None
    port = 0
    username = None
    password = None
    database = None

    def __init__(self, server, port, username, password, database):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.database = database

class InboundFlowStore(threading.Thread):
    '''
        Store for handling inbound flows.
    '''

    queue = None
    session = None
    logger = None

    def __init__(self, logger, database_settings):

        # Setup the inbound queue and logging

        self.queue = queue.Queue()
        self.logger = logger

        # Connect to the database

        engine = create_engine(
            f"postgres://{database_settings.username}:{quote(database_settings.password)}@{database_settings.server}:{database_settings.port}/{database_settings.database}",
            echo=False
        )

        SessionBase = sessionmaker(bind=engine)
        self.session = SessionBase()

        super().__init__()

    def run(self):

        # Run forever

        while True:

            # Read from the input queue

            try:
                flow = self.queue.get(block=True, timeout=0.5)
            except queue.Empty:
                continue

            # Check for an existing flow to update

            for existing_flow in self.session.query(Flow).filter(
                or_(
                    and_(
                        Flow.source_address == flow.source_address,
                        Flow.destination_address == flow.destination_address,
                        Flow.source_port == flow.source_port,
                        Flow.destination_port == flow.destination_port,
                        Flow.protocol == flow.protocol,
                        Flow.start == flow.start
                    ),
                    and_(
                        Flow.source_address == flow.destination_address,
                        Flow.destination_address == flow.source_address,
                        Flow.source_port == flow.destination_port,
                        Flow.destination_port == flow.source_port,
                        Flow.protocol == flow.protocol,
                        Flow.start == flow.start
                    )
                )
            ):
                existing_flow.end = flow.end
                self.logger.debug(f"Updated flow {existing_flow.source_address} -> {existing_flow.destination_address}:{existing_flow.destination_port}")
                self.session.commit()
                continue

            # Write our new flow back to the database

            self.session.add(flow)
            self.logger.debug(f"Created flow {flow.source_address} -> {flow.destination_address}:{flow.destination_port}")
            self.session.commit()

class AnalyticsFlowStore:

    logger = None
    session = None

    def __init__(self, logger, database_settings):
        '''
            Creates a new instance of the store
        '''

        self.logger = logger

        # Connect to the database

        engine = create_engine(
            f"postgres://{database_settings.username}:{quote(database_settings.password)}@{database_settings.server}:{database_settings.port}/{database_settings.database}",
            echo=False
        )

        SessionBase = sessionmaker(bind=engine)
        self.session = SessionBase()

    def get_interseting_flows(self, protocol, port):
        '''
            The initial (wide) search for interesting flows.
        '''

        return self.session.query(Flow).filter(
            and_(
                Flow.protocol == protocol,
                Flow.destination_port == port
            )
        )

    def get_interseting_flows_deep(self, protocol, port, source_address, start, end):
        '''
            Deeper searches of interesting flows.
        '''

        return self.session.query(Flow).filter(
            and_(
                Flow.protocol == protocol,
                Flow.destination_port == port,
                Flow.source_address == source_address,
                Flow.start >= start#,
                #Flow.end <= end
            )
        )