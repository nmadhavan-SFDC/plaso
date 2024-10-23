# -*- coding: utf-8 -*-
"""An output module that saves events to OpenSearch for Timesketch."""
import os
import json
from plaso.output import logger
from plaso.output import manager
from plaso.output import shared_opensearch

class OpenSearchTimesketchOutputModule(
    shared_opensearch.SharedOpenSearchOutputModule):
  """Output module for Timesketch OpenSearch."""

  NAME = 'opensearch_ts'
  DESCRIPTION = (
      'Saves the events into an OpenSearch database for use '
      'with Timesketch.')

  MAPPINGS_FILENAME = 'plaso.mappings'
  MAPPINGS_PATH = '/etc/timesketch'

  def __init__(self):
    """Initializes an output module."""
    super(OpenSearchTimesketchOutputModule, self).__init__()
    self._timeline_identifier = None

  def SetOutputMediator(self, output_mediator):
    """Sets the output mediator.
    
    Args:
        output_mediator (OutputMediator): mediates interactions between output
            modules and other components, such as storage and dfVFS.
    """
    self._output_mediator = output_mediator


  def GetMissingArguments(self):
    """Retrieves a list of arguments that are missing from the input.

    Returns:
      list[str]: names of arguments that are required by the module and have
          not been specified.
    """
    if not self._timeline_identifier:
      return ['timeline_id']
    return []

  def SetTimelineIdentifier(self, timeline_identifier):
    """Sets the timeline identifier.

    Args:
      timeline_identifier (int): timeline identifier.
    """
    self._timeline_identifier = timeline_identifier
    logger.info('Timeline identifier: {0:d}'.format(self._timeline_identifier))

  def _LoadMappings(self):
    """Loads the OpenSearch mappings.

    Returns:
      dict: OpenSearch mappings.

    Raises:
      BadConfigOption: if the mappings file cannot be loaded.
    """
    mappings_path = os.path.join(self.MAPPINGS_PATH, self.MAPPINGS_FILENAME)
    if not os.path.exists(mappings_path):
        raise errors.BadConfigOption(
            f'Mappings file not found at {mappings_path}')

    with open(mappings_path, 'r') as mappings_file:
        mappings = json.load(mappings_file)
    return mappings

  def WriteHeader(self, output_mediator):
    """Connects to the OpenSearch server and creates the index.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
    """
    # Set mappings before connecting
    #self._mappings = self._LoadMappings()
    self._Connect()
    self._CreateIndexIfNotExists(self._index_name, self._mappings)

  def WriteFieldValues(self, output_mediator, field_values):
    """Writes field values to the output.

    Events are buffered in the form of documents and inserted to OpenSearch
    when the flush interval (threshold) has been reached.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      field_values (dict[str, str]): output field values per name.
    """
    event_document = {'index': {'_index': self._index_name}}

    # Add timeline_id on the event level. It is used in Timesketch to
    # support shared indices.
    field_values['__ts_timeline_id'] = self._timeline_identifier

    self._event_documents.append(event_document)
    self._event_documents.append(field_values)
    self._number_of_buffered_events += 1

    if self._number_of_buffered_events > self._flush_interval:
      self._FlushEvents()

        
  def SetUp(self, options):
    """Sets up the output module.

    Args:
      options (argparse.Namespace): parser options.

    Raises:
      BadConfigOption: when required parameters are missing.
    """
    super(OpenSearchTimesketchOutputModule, self).SetUp(options)

    # Set the index name
    index_name = getattr(options, 'index_name', None)
    if not index_name:
        raise errors.BadConfigOption('Output index name was not provided.')
    self.SetIndexName(index_name)

    # Set the timeline identifier
    timeline_identifier = getattr(options, 'timeline_id', None)
    if not timeline_identifier:
        raise errors.BadConfigOption('Timeline identifier was not provided.')
    self.SetTimelineIdentifier(int(timeline_identifier))

    # Set the server and port
    server = getattr(options, 'opensearch_server', None)
    if not server:
        raise errors.BadConfigOption('OpenSearch server was not provided.')

    port = getattr(options, 'opensearch_port', None)
    if not port:
        raise errors.BadConfigOption('OpenSearch port was not provided.')

    self.SetServerInformation(server, int(port))

    # Set use_ssl
    use_ssl = getattr(options, 'use_ssl', True)
    self.SetUseSSL(use_ssl)

    # Set AWS authentication
    use_aws_auth = getattr(options, 'use_aws_auth', True)
    self.SetUseAWSAuth(use_aws_auth)

    aws_region = getattr(options, 'aws_region', 'us-west-2')
    self.SetAWSRegion(aws_region)

manager.OutputManager.RegisterOutput(
    OpenSearchTimesketchOutputModule,
    disabled=shared_opensearch.opensearchpy is None)
