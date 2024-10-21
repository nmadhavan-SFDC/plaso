# -*- coding: utf-8 -*-
"""Shared functionality for OpenSearch output modules."""

import logging
import syslog
import os
import boto3
from requests_aws4auth import AWS4Auth
from opensearchpy import RequestsHttpConnection

from acstore.containers import interface as containers_interface

from dfdatetime import interface as dfdatetime_interface
from dfdatetime import posix_time as dfdatetime_posix_time

from dfvfs.serializer.json_serializer import JsonPathSpecSerializer

try:
  import opensearchpy
except ImportError:
  opensearchpy = None

from plaso.lib import errors
from plaso.output import formatting_helper
from plaso.output import interface
from plaso.output import logger

from logging.handlers import SysLogHandler

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all logs

# Add syslog handler
syslog_handler = SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(name)s: %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

# Configure logging
logging.basicConfig()
logging.getLogger('opensearchpy').setLevel(logging.DEBUG)
logging.getLogger('requests_aws4auth').setLevel(logging.DEBUG)
logging.getLogger('botocore').setLevel(logging.DEBUG)


# Configure the OpenSearch logger.
if opensearchpy:
  opensearch_logger = logging.getLogger('opensearchpy.trace')
  opensearch_logger.setLevel(logging.DEBUG)


class SharedOpenSearchFieldFormattingHelper(
    formatting_helper.FieldFormattingHelper):
  """Shared OpenSearch output module field formatting helper."""

  # Maps the name of a fields to a a callback function that formats
  # the field value.
  _FIELD_FORMAT_CALLBACKS = {
      'datetime': '_FormatDateTime',
      'display_name': '_FormatDisplayName',
      'inode': '_FormatInode',
      'message': '_FormatMessage',
      'source_long': '_FormatSource',
      'source_short': '_FormatSourceShort',
      'tag': '_FormatTag',
      'timestamp': '_FormatTimestamp',
      'timestamp_desc': '_FormatTimestampDescription',
      'yara_match': '_FormatYaraMatch'}

  # The field format callback methods require specific arguments hence
  # the check for unused arguments is disabled here.
  # pylint: disable=unused-argument

  def _FormatDateTime(
      self, output_mediator, event, event_data, event_data_stream):
    """Formats a date and time field in ISO 8601 format.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.

    Returns:
      str: date and time field.
    """
    date_time = dfdatetime_posix_time.PosixTimeInMicroseconds(
        timestamp=event.timestamp)
    return date_time.CopyToDateTimeStringISO8601()

  def _FormatTag(self, output_mediator, event_tag):
    """Formats an event tag field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event_tag (EventTag): event tag or None if not set.

    Returns:
      list[str]: event tag labels.
    """
    return getattr(event_tag, 'labels', None) or []

  def _FormatInode(self, output_mediator, event, event_data, event_data_stream):
    """Formats an inode field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.

    Returns:
      str: inode field.
    """
    inode = getattr(event_data, 'inode', None)
    if isinstance(inode, int):
      inode = f'{inode:d}'

    return inode

  def _FormatTimestamp(
      self, output_mediator, event, event_data, event_data_stream):
    """Formats a timestamp field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.

    Returns:
      int: timestamp field.
    """
    return event.timestamp

  def _FormatTimestampDescription(
      self, output_mediator, event, event_data, event_data_stream):
    """Formats a timestamp description field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.

    Returns:
      str: timestamp description field.
    """
    return event.timestamp_desc

  def _FormatYaraMatch(
      self, output_mediator, event, event_data, event_data_stream):
    """Formats a Yara match field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.

    Returns:
      list[str]: Yara match field.
    """
    return getattr(event_data_stream, 'yara_match', None) or []

  # pylint: enable=unused-argument

  def GetFormattedField(
      self, output_mediator, field_name, event, event_data, event_data_stream,
      event_tag):
    """Formats the specified field.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      field_name (str): name of the field.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.

    Returns:
      object: value of the field or None if not set.
    """
    callback_name = self._FIELD_FORMAT_CALLBACKS.get(field_name, None)
    if callback_name == '_FormatTag':
      return self._FormatTag(output_mediator, event_tag)

    callback_function = None
    if callback_name:
      callback_function = getattr(self, callback_name, None)

    if callback_function:
      output_value = callback_function(
          output_mediator, event, event_data, event_data_stream)
    elif hasattr(event_data_stream, field_name):
      output_value = getattr(event_data_stream, field_name, None)
    else:
      output_value = getattr(event_data, field_name, None)

    return output_value


class SharedOpenSearchOutputModule(interface.OutputModule):
  """Shared functionality for an OpenSearch output module."""

  # pylint: disable=abstract-method

  NAME = 'opensearch_shared'

  SUPPORTS_ADDITIONAL_FIELDS = True
  SUPPORTS_CUSTOM_FIELDS = True

  _DEFAULT_FLUSH_INTERVAL = 1000

  # Number of seconds to wait before a request to OpenSearch is timed out.
  _DEFAULT_REQUEST_TIMEOUT = 300

  _DEFAULT_FIELD_NAMES = [
      'datetime',
      'display_name',
      'message',
      'source_long',
      'source_short',
      'tag',
      'timestamp',
      'timestamp_desc']

  def __init__(self):
    """Initializes an output module."""
    super(SharedOpenSearchOutputModule, self).__init__()
    self._client = None
    self._custom_fields = {}
    self._event_documents = []
    self._field_names = self._DEFAULT_FIELD_NAMES
    self._field_formatting_helper = SharedOpenSearchFieldFormattingHelper()
    self._flush_interval = self._DEFAULT_FLUSH_INTERVAL
    self._host = None
    self._index_name = None
    self._mappings = None
    self._number_of_buffered_events = 0
    self._password = None
    self._port = None
    self._username = None
    self._use_ssl = None
    self._url_prefix = None
    self._aws_region = 'us-west-2'
    self._aws_auth = True
    self._verify_certs = True  # Default to verifying SSL certificates
    self._ca_certs = None      # Path to CA certificate bundle, if any

  def SetUp(self, config):
    """Sets up the output module.
    Args:
    config (dict): Configuration dictionary.
    """
    self._host = config.get('OPENSEARCH_HOST')
    self._port = config.get('OPENSEARCH_PORT')
    self._use_ssl = config.get('OPENSEARCH_SSL', True)
    self._verify_certs = config.get('OPENSEARCH_VERIFY_CERTS', True)
    self._aws_auth = config.get('OPENSEARCH_AWS_AUTH', True)
    self._aws_region = config.get('OPENSEARCH_AWS_REGION', 'us-west-2')
    self._index_name = config.get('OPENSEARCH_INDEX_NAME')
    self._flush_interval = config.get('OPENSEARCH_FLUSH_INTERVAL', self._DEFAULT_FLUSH_INTERVAL)

  def SetAWSRegion(self, aws_region):
    """Sets the AWS region.

    Args:
      aws_region (str): AWS region where the OpenSearch cluster is located.
    """
    self._aws_region = aws_region
    logger.debug(f'AWS region: {aws_region}')

  def SetUseAWSAuth(self, aws_auth):
      """Sets whether to use AWS authentication.

      Args:
        _aws_auth (bool): True if AWS authentication should be used.
      """
      self._aws_auth = aws_auth
      logger.debug(f'Use AWS Auth: {aws_auth}')

  @classmethod
  def AddArguments(cls, argument_group):
      """Adds command-line arguments to the argument group.

      Args:
        argument_group (argparse._ArgumentGroup|argparse.ArgumentParser):
            argparse group.
      """
      argument_group.add_argument(
        '--use-aws-auth', dest='aws_auth', action='store_true', default=True,
        help='Use AWS authentication for OpenSearch.')
      argument_group.add_argument(
          '--opensearch-server', dest='opensearch_server', type=str,
          help='Hostname or IP address of the OpenSearch server.')
      argument_group.add_argument(
          '--opensearch-port', dest='opensearch_port', type=int, default=9200,
          help='Port number of the OpenSearch server.')
      argument_group.add_argument(
          '--use-ssl', dest='use_ssl', action='store_true', default=True,
          help='Enforce use of SSL/TLS.')
      argument_group.add_argument(
          '--use-aws-auth', dest='aws_auth', action='store_true', default=False,
          help='Use AWS authentication for OpenSearch.')
      argument_group.add_argument(
          '--aws-region', dest='aws_region', type=str, default='us-east-1',
          help='AWS region where the OpenSearch cluster is located.')
      argument_group.add_argument(
          '--index-name', dest='index_name', type=str, required=True,
          help='Name of the OpenSearch index to write to.')
      argument_group.add_argument(
          '--timeline_id', dest='timeline_id', type=int, required=True,
          help='Timeline identifier.')

  def _Connect(self):
      """Connects to an OpenSearch server."""
      logger.debug(f"Connecting to OpenSearch: Host={self._host}, Port={self._port}, AWS Auth={self._aws_auth}")
      opensearch_host = {'host': self._host, 'port': self._port}

      client_params = {
          'hosts': [opensearch_host],
          'use_ssl': self._use_ssl,
          'verify_certs': self._verify_certs
      }

      if self._aws_auth:
          syslog.syslog(f"Using AWS Auth with region: {self._aws_region}")
          syslog.syslog(f"Using AWS Auth with region: {self._aws_region}")
          session = boto3.Session(region_name=self._aws_region)
          credentials = session.get_credentials()
          syslog.syslog(f"Session credentials: {credentials.access_key}, {credentials.secret_key}, {credentials.token}")
          awsauth = AWS4Auth(
              credentials.access_key,
              credentials.secret_key,
              self._aws_region,
              'es',
              session_token=credentials.token,
          )
          client_params['http_auth'] = awsauth
          client_params['connection_class'] = RequestsHttpConnection

      try:
          self._client = opensearchpy.OpenSearch(**client_params)
          info = self._client.info()
          logger.debug(f"Successfully connected to OpenSearch. Cluster info: {info}")
      except Exception as e:
          logger.info(f"Failed to connect to OpenSearch: {str(e)}")
          raise

      logger.info(f'Connected to OpenSearch server: {self._host} port: {self._port}')

  def _CreateIndexIfNotExists(self, index_name, mappings):
    """Creates an OpenSearch index if it does not exist.

    Args:
      index_name (str): mame of the index.
      mappings (dict[str, object]): mappings of the index.

    Raises:
      RuntimeError: if the OpenSearch index cannot be created.
    """
    try:
      if not self._client.indices.exists(index_name):
        self._client.indices.create(
            body={'mappings': mappings}, index=index_name)

    except opensearchpy.exceptions.ConnectionError as exception:
      raise RuntimeError(
          f'Unable to create OpenSearch index with error: {exception!s}')

  def _FlushEvents(self):
    """Inserts the buffered event documents into OpenSearch."""
    try:
      # pylint: disable=unexpected-keyword-arg
      bulk_arguments = {
          'body': self._event_documents,
          'index': self._index_name,
          'request_timeout': self._DEFAULT_REQUEST_TIMEOUT}

      self._client.bulk(**bulk_arguments)

    except (ValueError,
            opensearchpy.exceptions.OpenSearchException) as exception:
      # Ignore problematic events
      logger.warning(f'Unable to bulk insert with error: {exception!s}')

    logger.debug(
        'Inserted {self._number_of_buffered_events:d} events into OpenSearch')

    self._event_documents = []
    self._number_of_buffered_events = 0

  def _SanitizeField(self, data_type, attribute_name, field):
    """Sanitizes a field for output.

    Args:
      data_type (str): event data type.
      attribute_name (str): name of the event attribute.
      field (object): value of the field to sanitize.

    Returns:
      object: sanitized value of the field.
    """
    # Some parsers have written bytes values to storage.
    if isinstance(field, bytes):
      field = field.decode('utf-8', 'replace')
      logger.warning((
          f'Found bytes value for attribute: {attribute_name:s} of data type: '
          f'{data_type!s}. Value was converted to UTF-8: "{field:s}"'))

    return field

  def Close(self):
    """Closes connection to OpenSearch.

    Inserts any remaining buffered event documents.
    """
    self._FlushEvents()

    self._client = None

  def GetFieldValues(
      self, output_mediator, event, event_data, event_data_stream, event_tag):
    """Retrieves the output field values.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.

    Returns:
      dict[str, str]: output field values per name.
    """
    event_values = {}

    if event_data:
      for attribute_name, attribute_value in event_data.GetAttributes():
        # Ignore attribute container identifier and date and time values.
        if isinstance(attribute_value, (
            containers_interface.AttributeContainerIdentifier,
            dfdatetime_interface.DateTimeValues)):
          continue

        if (isinstance(attribute_value, list) and attribute_value and
            isinstance(attribute_value[0],
                       dfdatetime_interface.DateTimeValues)):
          continue

        # Ignore protected internal only attributes.
        if attribute_name[0] == '_' and attribute_name != '_parser_chain':
          continue

        # Output _parser_chain as parser for backwards compatibility.
        if attribute_name == '_parser_chain':
          attribute_name = 'parser'

        event_values[attribute_name] = attribute_value

    if event_data_stream:
      for attribute_name, attribute_value in event_data_stream.GetAttributes():
        event_values[attribute_name] = attribute_value

    for attribute_name in self._field_names:
      if attribute_name not in event_values:
        event_values[attribute_name] = None

    field_values = {}
    for attribute_name, attribute_value in event_values.items():
      if attribute_name == 'path_spec':
        try:
          field_value = JsonPathSpecSerializer.WriteSerialized(attribute_value)
        except TypeError:
          continue

      else:
        field_value = self._field_formatting_helper.GetFormattedField(
            output_mediator, attribute_name, event, event_data,
            event_data_stream, event_tag)

      if field_value is None and attribute_name in self._custom_fields:
        field_value = self._custom_fields.get(attribute_name, None)

      if field_value is None:
        field_value = '-'

      field_values[attribute_name] = self._SanitizeField(
          event_data.data_type, attribute_name, field_value)

    return field_values

  def SetAdditionalFields(self, field_names):
    """Sets the names of additional fields to output.

    Args:
      field_names (list[str]): names of additional fields to output.
    """
    self._field_names.extend(field_names)

  def SetCustomFields(self, field_names_and_values):
    """Sets the names and values of custom fields to output.

    Args:
      field_names_and_values (list[tuple[str, str]]): names and values of
          custom fields to output.
    """
    self._custom_fields = dict(field_names_and_values)
    self._field_names.extend(self._custom_fields.keys())

  def SetFlushInterval(self, flush_interval):
    """Sets the flush interval.

    Args:
      flush_interval (int): number of events to buffer before doing a bulk
          insert.
    """
    self._flush_interval = flush_interval
    logger.debug(f'OpenSearch flush interval: {flush_interval:d}')

  def SetIndexName(self, index_name):
    """Sets the index name.

    Args:
      index_name (str): name of the index.
    """
    self._index_name = index_name
    logger.debug(f'OpenSearch index name: {index_name:s}')

  def SetMappings(self, mappings):
    """Sets the mappings.

    Args:
      mappings (dict[str, object]): mappings of the index.
    """
    self._mappings = mappings

  def SetPassword(self, password):
    """Sets the password.

    Args:
      password (str): password to authenticate with.
    """
    self._password = password
    logger.debug('OpenSearch password: ********')

  def SetServerInformation(self, server, port):
    """Sets the server information.

    Args:
      server (str): IP address or hostname of the server.
      port (int): Port number of the server.
    """
    self._host = server
    self._port = port
    logger.debug(f'OpenSearch server: {server!s} port: {port:d}')

  def SetUsername(self, username):
    """Sets the username.

    Args:
      username (str): username to authenticate with.
    """
    self._username = username
    logger.debug(f'OpenSearch username: {username!s}')

  def SetUseSSL(self, use_ssl):
    """Sets the use of ssl.

    Args:
      use_ssl (bool): enforces use of ssl.
    """
    self._use_ssl = use_ssl
    logger.debug(f'OpenSearch use SSL/TLS: {use_ssl!s}')

  def SetCACertificatesPath(self, ca_certificates_path):
      """Sets the path to the CA certificates.

      Args:
        ca_certificates_path (str): path to file containing a list of root
          certificates to trust.

      Raises:
        BadConfigOption: if the CA certificates file does not exist.
      """
      if not ca_certificates_path:
          return

      if not os.path.exists(ca_certificates_path):
          raise errors.BadConfigOption(
              f'No such certificate file: {ca_certificates_path:s}')

      self._ca_certs = ca_certificates_path  # Correct assignment
      logger.debug(f'OpenSearch certificate file: {ca_certificates_path:s}')


  def SetURLPrefix(self, url_prefix):
    """Sets the URL prefix.

    Args:
      url_prefix (str): URL prefix.
    """
    self._url_prefix = url_prefix
    logger.debug('OpenSearch URL prefix: {0!s}')
