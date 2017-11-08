/*
  0123456789ab     -- 12-byte packet header (control)
  0123456789abcdef -- 16-byte packet header (routing)
  
  01.............. -- uint16 signature = 0xFE 0xED
  ..23 ........... -- uint16 packet length

  ....4........... -- uint8 ttl hops

  .....5.......... -- uint8 header type
  ......67........ -- uint8 header length

  ........89ab.... -- uint32 id_router
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id

  ............cdef -- uint32 id_target (when id_router !== 0)
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id
 */

import asPacketParserAPI from './basic'

const signature = 0xedfe
const pkt_control_header_size = 12
const pkt_routing_header_size = 16
const default_ttl = 31

export default function createBufferPacketParser(options={}) ::
  return asPacketParserAPI @:
    parseHeader, packMessage
    packId, unpackId, pack_utf8, unpack_utf8

    asBuffer, concatBuffers


  function parseHeader(buf, decrement_ttl) ::
    const sig = buf.readUInt16LE @ 0
    if signature !== sig ::
      throw new Error @ `Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`

    // up to 64k packet length; length includes header
    const packet_len = buf.readUInt16LE @ 2
    let header_len = buf.readUInt16LE @ 4
    const type = buf.readUInt8 @ 6

    let ttl = buf.readUInt8 @ 7
    if decrement_ttl ::
      ttl = Math.max @ 0, ttl - 1
      buf.writeUInt8 @ ttl, 7

    const id_router = buf.readUInt32LE @ 8
    const info = @{} type, ttl, id_router

    if 0 === id_router ::
      return @: info, packet_len, header_len, pkt_header_len: pkt_control_header_size
    else if pkt_routing_header_size > buf.byteLength ::
      return null // this buffer is fragmented before id_target
    else ::
      info.id_target = buf.readUInt32LE @ 12
      return @: info, packet_len, header_len, pkt_header_len: pkt_routing_header_size


  function packMessage(...args) ::
    let {type, ttl, id_router, id_target, header, body} = Object.assign @ {}, ...args
    header = asBuffer(header)
    body = asBuffer(body)

    const pkt_header_size = id_router
      ? pkt_routing_header_size
      : pkt_control_header_size
    const packet_len = pkt_header_size + header.byteLength + body.byteLength
    if packet_len > 0xffff :: throw new Error @ `Packet too large`

    const pkt = Buffer.alloc @ pkt_header_size
    pkt.writeUInt16LE @ signature, 0
    pkt.writeUInt16LE @ packet_len, 2
    pkt.writeUInt16LE @ header.byteLength, 4
    pkt.writeUInt8 @ type || 0, 6
    pkt.writeUInt8 @ ttl || default_ttl, 7
    if ! id_router ::
      pkt.writeUInt32LE @ 0, 8
      if id_target ::
        throw new Error @ `Invalid id_target for control packet`
    else ::
      pkt.writeUInt32LE @ id_router, 8
      pkt.writeUInt32LE @ id_target || 0, 12

    const buf = Buffer.concat @# pkt, header, body
    if packet_len !== buf.byteLength ::
      throw new Error @ `Packed message length mismatch (library error)`
    return buf


  function packId(id, offset) ::
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(id, offset)
    return buf
  function unpackId(buf, offset) ::
    return buf.readUInt32LE(offset)

  function pack_utf8(str) ::
    return Buffer.from(str, 'utf-8')
  function unpack_utf8(buf) ::
    return asBuffer(buf).toString('utf-8')


  function asBuffer(buf) ::
    if Buffer.isBuffer(buf) ::
      return buf

    if 'string' === typeof buf ::
      return pack_utf8(buf)

    if undefined !== buf.byteLength ::
      return Buffer.from(buf) // TypedArray or ArrayBuffer

    if Array.isArray(buf) ::
      if Number.isSafeInteger @ buf[0] ::
        return Buffer.from(buf)
      return Buffer.concat @ buf.map @ asBuffer


  function concatBuffers(lst, len) ::
    if 1 === lst.length :: return lst[0]
    if 0 === lst.length :: return Buffer(0)
    return Buffer.concat(lst)

