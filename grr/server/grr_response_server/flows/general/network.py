#!/usr/bin/env python
"""These are network related flows."""
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

from grr_response_core.lib.rdfvalues import structs as rdf_structs
from grr_response_core.lib.rdfvalues import standard as rdf_standard
from grr_response_proto import flows_pb2
from grr_response_server import flow
from grr_response_server import flow_base
from grr_response_server import server_stubs


class NetstatArgs(rdf_structs.RDFProtoStruct):
  protobuf = flows_pb2.NetstatArgs
  rdf_deps = [
      rdf_standard.RegularExpression,
  ]


@flow_base.DualDBFlow
class NetstatMixin(object):
  """List active network connections on a system."""

  category = "/Network/"
  behaviours = flow.GRRFlow.behaviours + "BASIC"
  args_type = NetstatArgs

  def Start(self):
    """Start processing."""
    self.CallClient(
        server_stubs.ListNetworkConnections,
        listening_only=self.args.listening_only,
        next_state="ValidateListNetworkConnections")

  def _ConnectionRemoteIpMatch(self, netstat):
    if not self.args.ip_regex:
      return True
    self.Log('Matching %s with %s', netstat.remote_address.ip, self.args.ip_regex)
    ip = netstat.remote_address.ip
    # FIXME: hack for ipv4 addr in ipv6 format
    if ip.startswith('::ffff:'):
      ip = ip.replace('::ffff:', '')
    res = self.args.ip_regex.Match(ip)
    self.Log('Match result: %s', res)
    return res

  def ValidateListNetworkConnections(self, responses):
    if not responses.success:
      # Most likely the client is old and doesn't have ListNetworkConnections.
      self.Log(responses.status)

      # Fallback to Netstat.
      self.CallClient(server_stubs.Netstat, next_state="StoreNetstat")
    else:
      self.CallStateInline(next_state="StoreNetstat", responses=responses)


  def StoreNetstat(self, responses):
    """Collects the connections.

    Args:
      responses: A list of rdf_client_network.NetworkConnection objects.

    Raises:
      flow.FlowError: On failure to get retrieve the connections.
    """
    if not responses.success:
      raise flow.FlowError("Failed to get connections. Err: {0}".format(
          responses.status))

    self.skipped = 0
    for response in responses:
      if self.args.listening_only and response.state != "LISTEN":
        continue

      if not self._ConnectionRemoteIpMatch(response):
        self.skipped += 1
        continue

      self.SendReply(response)

    self.state.conn_count = len(responses)


  def End(self, responses):
    del responses
    self.Log("Successfully wrote %d connections. Skipped %s connections, no match.", self.state.conn_count, self.skipped)
