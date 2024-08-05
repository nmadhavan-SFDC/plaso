# -*- coding: utf-8 -*-
"""An output module that saves events to OpenSearch for Timesketch."""

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

  def WriteFieldValues(self, output_mediator, field_values, event=None, event_data=None, event_data_stream=None, event_tag=None):
    """Writes field values to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      field_values (dict[str, str]): output field values per name.
      event (Optional[EventObject]): event.
      event_data (Optional[EventData]): event data.
      event_data_stream (Optional[EventDataStream]): event data stream.
      event_tag (Optional[EventTag]): event tag.

    Raises:
      RuntimeError: when the timeline identifier is not set.
    """
    if self._timeline_identifier is None:
      raise RuntimeError("Timeline identifier is not set.")

    event_document = {'index': {'_index': self._index_name}}
    # Add timeline_id on the event level. It is used in Timesketch to
    # support shared indices.
    field_values['__ts_timeline_id'] = self._timeline_identifier
    self._event_documents.append(event_document)
    self._event_documents.append(field_values)
    self._number_of_buffered_events += 1
    if self._number_of_buffered_events > self._flush_interval:
      self._FlushEvents()

  def WriteFieldValuesOfMACBGroup(self, output_mediator, macb_group):
    """Writes field values of a MACB group to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      macb_group (list[tuple[EventObject, EventData, EventDataStream, EventTag]]):
          group of MACB events to write.
    """
    for event, event_data, event_data_stream, event_tag in macb_group:
      field_values = self.GetFieldValues(
          output_mediator, event, event_data, event_data_stream, event_tag)
      self.WriteFieldValues(output_mediator, field_values)

  def GetFieldValues(self, output_mediator, event, event_data, event_data_stream, event_tag):
    """Retrieves the field values for an event.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.

    Returns:
      dict[str, str]: field values.
    """
    # Implement the logic to extract field values from the event
    # This is just a placeholder, you'll need to implement the actual logic
    field_values = {}
    for attribute_name, attribute_value in event_data.GetAttributes():
      field_values[attribute_name] = attribute_value
    
    # Add any necessary transformations or additional fields
    field_values['timestamp'] = event.timestamp
    field_values['timestamp_desc'] = event.timestamp_desc

    return field_values
    
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

  def WriteHeader(self, output_mediator):
    """Connects to the OpenSearch server and creates the index.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
    """
    self._Connect()

    self._CreateIndexIfNotExists(self._index_name, self._mappings)


manager.OutputManager.RegisterOutput(
    OpenSearchTimesketchOutputModule,
    disabled=shared_opensearch.opensearchpy is None)
