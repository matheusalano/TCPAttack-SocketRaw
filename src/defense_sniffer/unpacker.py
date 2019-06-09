import socket, struct, binascii

class unpack:
 def __init__(self):
  self.data=None

 # Ethernet Header
 def eth_header(self, data):
  data_header          = struct.unpack("!6s6sH",data)
  destination_mac   = binascii.hexlify(data_header[0])
  source_mac        = binascii.hexlify(data_header[1])
  eth_protocol      = data_header[2]

  data = {
    "Destination Mac":destination_mac,
    "Source Mac":source_mac,
    "Protocol":eth_protocol
    }
  return data


 # IP Header Extraction
 def ip_header(self, data):
  data_header           = struct.unpack("!4sHBB16s16s", data)
  _version              = data_header[0]
  _traffic_class        = data_header[1]
  _flow_level           = data_header[2]
  _payload_length       = data_header[3]
  _next_header          = data_header[4]
  _hop_limit            = data_header[5]
  _source_address       = socket.inet_ntop(socket.AF_INET6, data[22:][:16])
  _destination_address  = socket.inet_ntoa(socket.AF_INET, data[38:][:16])

  data = {
    'Version':_version,
    "Traffic Class":_traffic_class,
    "Flow Lever":_flow_level,
    "Payload Length":_payload_length,
    "Next Header":_next_header,
    "Hop Limit":_hop_limit,
    "Source Address":_source_address,
    "Destination Address":_destination_address
    }
  return data

 # Tcp Header Extraction
 def tcp_header(self, data):
  data_header           = struct.unpack('!HHLLBBHHH',data)
  _source_port          = data_header[0] 
  _destination_port     = data_header[1]
  _sequence_number      = data_header[2]
  _acknowledge_number   = data_header[3]
  _offset_reserved      = data_header[4]
  _tcp_flag             = data_header[5]
  _window               = data_header[6]
  _checksum             = data_header[7]
  _urgent_pointer       = data_header[8]

  data = {
    "Source Port":_source_port,
    "Destination Port":_destination_port,
    "Sequence Number":_sequence_number,
    "Acknowledge Number":_acknowledge_number,
    "Offset & Reserved":_offset_reserved,
    "Tcp Flag":_tcp_flag,
    "Window":_window,
    "CheckSum":_checksum,
    "Urgent Pointer":_urgent_pointer
  }
  return data 
