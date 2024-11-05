# -*- coding: utf-8 -*-
"""An output module that saves events to OpenSearch for Timesketch."""

import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

from plaso.output import logger
from plaso.output import manager
from plaso.output import shared_opensearch
import numpy
import json

class OpenSearchTimesketchOutputModule(
    shared_opensearch.SharedOpenSearchOutputModule):
  """Output module for Timesketch OpenSearch."""

  NAME = 'opensearch_ts'
  DESCRIPTION = (
      'Saves the events into an OpenSearch database for use '
      'with Timesketch.')

  MAPPINGS_FILENAME = 'plaso.mappings'
  MAPPINGS_PATH = '/etc/timesketch'

  def _FlushEvents(self):
    """Inserts buffered event documents into OpenSearch with detailed logging."""
    if not self._event_documents:
        return

    # Prepare bulk body
    bulk_body = ''
    for doc in self._event_documents:
        bulk_body += json.dumps(doc, default=self._JSONSerializeHelper) + '\n'

    bulk_arguments = {
        'body': bulk_body,
        'index': self._index_name,
        'refresh': False,
        'request_timeout': self._request_timeout
    }

    try:
        response = self._client.bulk(**bulk_arguments)
        if response.get('errors'):
            logger.error(f"Bulk insert encountered errors: {response}")
        else:
            logger.info(f"Successfully inserted {len(self._event_documents)//2} events.")
    except Exception as e:
        logger.error(f"Failed to insert events into OpenSearch: {e}")
        logger.error("Exception details:", exc_info=True)
        # Optionally, raise the exception or handle it appropriately.

    # Reset the buffer and counter
    self._event_documents = []
    self._number_of_buffered_events = 0

  def _JSONSerializeHelper(self, obj):
      """Helper function for JSON serialization of unsupported data types."""
      if isinstance(obj, numpy.generic):
          return obj.item()
      elif isinstance(obj, numpy.ndarray):
          return obj.tolist()
      elif isinstance(obj, bytes):
          return obj.decode('utf-8', errors='replace')
      else:
          return str(obj)

  def __init__(self):
    """Initializes an output module."""
    super(OpenSearchTimesketchOutputModule, self).__init__()
    self._timeline_identifier = None
    self._request_timeout = 300

  def _Connect(self):
    """Connects to the OpenSearch server."""
    # Use AWS authentication
    host = self._host
    port = self._port
    use_ssl = self._use_ssl

    # Get AWS credentials
    session = boto3.Session()
    credentials = session.get_credentials()
    region = session.region_name or 'us-west-2'  # Update with your region

    aws_auth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        region,
        'es',
        session_token=credentials.token
    )

    self._client = OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_auth=aws_auth,
        use_ssl=use_ssl,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )

  def WriteEventBody(self, output_mediator, event, event_data, event_data_stream, event_tag):
    """Writes the body of an event to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.
    """
    # Create a dictionary to hold all event field values
    event_values = event_data.CopyToDict()
    # Log the event values for debugging

    # Add event-specific attributes
    event_values['timestamp'] = event.timestamp
    event_values['timestamp_desc'] = event.timestamp_desc

    # Get the message formatter for the event data type
    message_formatter = output_mediator.GetMessageFormatter(event_data.data_type)

    if message_formatter:
        # Format the event values using the formatter's helpers
        message_formatter.FormatEventValues(output_mediator, event_values)

        # Get formatted message strings
        message = message_formatter.GetMessage(event_values)
        message_short = message_formatter.GetMessageShort(event_values)
        event_values['message'] = message
        event_values['message_short'] = message_short

        # Get formatted source strings
        source_short, source_long = output_mediator.GetSourceMapping(event_data.data_type)
        event_values['source_short'] = source_short or ''
        event_values['source_long'] = source_long or ''
    else:
        # If no formatter is found, use defaults
        event_values['message'] = ''
        event_values['message_short'] = ''
        event_values['source_short'] = ''
        event_values['source_long'] = ''

    # Include event tag if available
    if event_tag:
        event_values['tag'] = event_tag.labels

    # Add timeline identifier for Timesketch
    event_values['__ts_timeline_id'] = self._timeline_identifier

    # Sanitize event_values to convert unsupported data types
    event_values = self._SanitizeEventValues(event_values)

    event_document = {'index': {'_index': self._index_name}}

    self._event_documents.append(event_document)
    self._event_documents.append(event_values)
    self._number_of_buffered_events += 1

    if self._number_of_buffered_events > self._flush_interval:
        self._FlushEvents()

  def _SanitizeEventValues(self, event_values):
    """Sanitize event values to ensure they are serializable."""
    sanitized_values = {}
    for key, value in event_values.items():
        if isinstance(value, numpy.generic):
            sanitized_values[key] = value.item()
        elif isinstance(value, numpy.ndarray):
            sanitized_values[key] = value.tolist()
        elif isinstance(value, bytes):
            sanitized_values[key] = value.decode('utf-8', errors='replace')
        elif isinstance(value, dict):
            sanitized_values[key] = self._SanitizeEventValues(value)
        elif isinstance(value, list):
            sanitized_values[key] = [self._SanitizeEventValues(v) if isinstance(v, dict) else v for v in value]
        else:
            sanitized_values[key] = value
    return sanitized_values

  def WriteFieldValuesOfMACBGroup(self, output_mediator, event_macb_group):
    """Writes field values of a group of events with identical timestamps."""
    for event, event_data, event_data_stream, event_tag in event_macb_group:
        self.WriteEventBody(output_mediator, event, event_data, event_data_stream, event_tag)

  def GetMissingArguments(self):
    """Retrieves a list of arguments that are missing from the input."""
    if not self._timeline_identifier:
      return ['timeline_id']
    return []

  def SetTimelineIdentifier(self, timeline_identifier):
    """Sets the timeline identifier."""
    self._timeline_identifier = timeline_identifier
    logger.info('Timeline identifier: {0:d}'.format(self._timeline_identifier))

  def WriteHeader(self, output_mediator):
    """Connects to the OpenSearch server and creates the index."""
    self._Connect()
    self._CreateIndexIfNotExists(self._index_name, self._mappings)


manager.OutputManager.RegisterOutput(
    OpenSearchTimesketchOutputModule,
    disabled=shared_opensearch.opensearchpy is None)
