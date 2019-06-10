import socket, struct, binascii

class unpack:
 def __init__(self):
  self.data=None

 # Ethernet Header
 def eth_header(self, data):
    data_header = struct.unpack("!6s6s2s", data)
    data = {
        "dest_mac": binascii.hexlify(data_header[0]),
        "source_mac": binascii.hexlify(data_header[1]),
        "protocol": data_header[2],
    }
    return data

 # IP Header Extraction
 def ip_header(self, data):
    unpackable_data = data[0:8]
    src_ip = data[8:][:16]
    dest_ip = data[24:][:16]

    data_header                         = struct.unpack("!4sHBB", unpackable_data)
    _version_traffic_class_flow_level   =  data_header[0]
    _payload_length                     =  data_header[1]
    _next_header                        =  data_header[2]
    _hop_limit                          =  data_header[3]
    _source_address                     = socket.inet_ntop(socket.AF_INET6, src_ip)
    _destination_address                = socket.inet_ntop(socket.AF_INET6, dest_ip)
    
    data = {
      "version_traffic_class_flow_level":_version_traffic_class_flow_level,
      "payload_length":_payload_length,
      "next_header":_next_header,
      "hop_limit":_hop_limit,
      "src_ip":_source_address,
      "dest_ip":_destination_address
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
    "src_port":_source_port,
    "dest_port":_destination_port,
    "sequence_number":_sequence_number,
    "ack_number":_acknowledge_number,
    "offset_and_reserved":_offset_reserved,
    "tcp_flag":_tcp_flag,
    "window":_window,
    "checkSum":_checksum,
    "urgent_pointer":_urgent_pointer
  }
  return data 
