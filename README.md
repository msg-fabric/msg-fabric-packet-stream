# msg-fabric-packet-stream

Underlying packet framing implementations for [msg-fabric](https://github.com/shanewholloway/msg-fabric).

### Packet Framing Details

| pos | len | bytes              | type   | purpose
|-----|-----|--------------------|--------|---------
|   0 |   2 | `01..............` | uint16 | signature = 0xFE 0xED
|   2 |   2 | `..23............` | uint16 | packet length
|   6 |   2 | `....45..........` | uint16 | header length
|   5 |   1 | `......6.........` | uint8  | header type
|   4 |   1 | `.......7........` | uint8  | ttl hops
|   8 |   4 | `........89ab....` | int32  | id router
|  12 |   4 | `............cdef` | int32  | id targets

- N-byte packet header, including byte length of packet and msg header
- msg header – byte length specified in packet header
- msg body — byte length as remainder of packet
- control messages are signaled when `id_router===0` and `id_target===0`
- 4-byte random space for `id_router` and `id_target` allows 1 million nodes
  with 0.02% chance of two nodes selecting the same id

