# msg-fabric-packet-stream

Underlying packet framing implementations for [msg-fabric](https://github.com/shanewholloway/msg-fabric).

### Details

#### Packet Framing

- N-byte packet header, including byte length of packet and msg header
- msg header – byte length specified in packet header
- msg body — byte length as remainder of packet

| pos | len | bytes              | type   | purpose
|-----|-----|--------------------|--------|---------
|   0 |   2 | `01..............` | uint16 | signature = 0xFE 0xED
|   2 |   2 | `..23 ...........` | uint16 | packet length
|   4 |   1 | `....4...........` | uint8  | ttl hops
|   5 |   1 | `.....5..........` | uint8  | header type
|   6 |   2 | `......67........` | uint8  | header length
|   8 |   4 | `........89ab....` | uint32 | `id_router`; see packet types
|  12 |   4 | `............cdef` | uint32 | `id_targets`, when `id_router !== 0`; see packet types


##### Control-Packet

- 12-byte packet header, including `id_router === 0`
- msg header – byte length specified in packet header
- msg body — byte length as remainder of packet


| pos | len | bytes              | type   | purpose
|-----|-----|--------------------|--------|---------
|   8 |   4 | `........89ab....` | uint32 | `id_router === 0`


##### Routing-Packet

- 16-byte packet header, including `id_router` and `id_target`
- msg header – byte length specified in packet header
- msg body — byte length as remainder of packet


| pos | len | bytes              | type   | purpose
|-----|-----|--------------------|--------|---------
|   8 |   4 | `........89ab....` | uint32 | `id_router !== 0`
|  12 |   4 | `............cdef` | uint32 | `id_target`


##### Notes

- 4-byte random space for `id_router` and `id_target` allows 1 million nodes
  with 0.02% chance of two nodes selecting the same id

