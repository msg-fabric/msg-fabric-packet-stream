/*
  0123456789ab     -- 12-byte packet header (control)
  0123456789abcdef -- 16-byte packet header (routing)
  
  01.............. -- uint16 signature = 0xFE 0xED
  ..23 ........... -- uint16 packet length
  ....45.......... -- uint16 header length
  ......6......... -- uint8 header type
  .......7........ -- uint8 ttl hops

  ........89ab.... -- int32 id_router
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id

  ............cdef -- int32 id_target
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id
 */

import asPacketParserAPI from './basic'

const signature = 0xedfe
const pkt_header_len = 16
const default_ttl = 31

export default function createBufferPacketParser(options={}) ::
  return asPacketParserAPI @:
    parseHeader, packPacket, fwdHeader
    packId, unpackId, pack_utf8, unpack_utf8

    asBuffer, concatBuffers


  function parseHeader(buf, decrement_ttl) ::
    if pkt_header_len > buf.byteLength :: return null

    const sig = buf.readUInt16LE @ 0
    if signature !== sig ::
      throw new Error @ `Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`

    // up to 64k packet length; length includes header
    const packet_len = buf.readUInt16LE @ 2
    const header_len = buf.readUInt16LE @ 4
    const type = buf.readUInt8 @ 6

    let ttl = buf.readUInt8 @ 7
    if decrement_ttl ::
      ttl = Math.max @ 0, ttl - 1
      buf.writeUInt8 @ ttl, 7

    const id_router = buf.readInt32LE @ 8
    const id_target = buf.readInt32LE @ 12
    const info = @{} type, ttl, id_router, id_target
    return @{} info, pkt_header_len, packet_len, header_len


  function packPacket(...args) ::
    let {type, ttl, id_router, id_target, header, body} =
      1 === args.length ? args[0] : Object.assign @ {}, ...args

    if Number.isNaN(+id_router) :: throw new Error @ `Invalid id_router`
    if id_target && Number.isNaN(+id_target) :: throw new Error @ `Invalid id_target`
    header = asBuffer(header)
    body = asBuffer(body)

    const packet_len = pkt_header_len + header.byteLength + body.byteLength
    if packet_len > 0xffff :: throw new Error @ `Packet too large`

    const pkthdr = Buffer.alloc @ pkt_header_len
    pkthdr.writeUInt16LE @ signature, 0
    pkthdr.writeUInt16LE @ packet_len, 2
    pkthdr.writeUInt16LE @ header.byteLength, 4
    pkthdr.writeUInt8 @ type || 0, 6
    pkthdr.writeUInt8 @ ttl || default_ttl, 7
    pkthdr.writeInt32LE @ 0 | id_router, 8
    pkthdr.writeInt32LE @ 0 | id_target, 12

    const buf = Buffer.concat @# pkthdr, header, body
    if packet_len !== buf.byteLength ::
      throw new Error @ `Packet length mismatch (library error)`
    return buf


  function fwdHeader(buf, id_router, id_target) ::
    buf = new Buffer(buf)
    if null != id_router :: buf.writeInt32LE @ 0 | id_router, 8
    if null != id_target :: buf.writeInt32LE @ 0 | id_target, 12
    return buf


  function packId(id, offset) ::
    const buf = Buffer.alloc(4)
    buf.writeInt32LE @ 0 | id, offset||0
    return buf
  function unpackId(buf, offset) ::
    return buf.readInt32LE @ offset||0

  function pack_utf8(str) ::
    return Buffer.from(str, 'utf-8')
  function unpack_utf8(buf) ::
    return asBuffer(buf).toString('utf-8')


  function asBuffer(buf) ::
    if null === buf || undefined === buf ::
      return Buffer(0)

    if Buffer.isBuffer(buf) ::
      return buf

    if 'string' === typeof buf ::
      return pack_utf8(buf)

    if undefined !== buf.byteLength ::
      if ArrayBuffer.isView(buf) ::
        return Buffer.from @ buf.buffer // DataView
      else ::
        return Buffer.from @ buf // TypedArray or ArrayBuffer

    if Array.isArray(buf) ::
      if Number.isInteger @ buf[0] ::
        return Buffer.from(buf)
      return Buffer.concat @ buf.map @ asBuffer


  function concatBuffers(lst, len) ::
    if 1 === lst.length :: return lst[0]
    if 0 === lst.length :: return Buffer(0)
    return Buffer.concat(lst)

