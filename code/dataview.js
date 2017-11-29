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

const little_endian = true

export default function createDataViewPacketParser(options={}) ::
  const _TextEncoder_ = options.TextEncoder || TextEncoder
  const _TextDecoder_ = options.TextDecoder || TextDecoder

  return asPacketParserAPI @:
    parseHeader, packPacket, fwdHeader
    packId, unpackId, pack_utf8, unpack_utf8

    asBuffer, concatBuffers


  function parseHeader(buf, decrement_ttl) ::
    if pkt_header_len > buf.byteLength :: return null

    const dv = new DataView @ buf

    const sig = dv.getUint16 @ 0, little_endian
    if signature !== sig ::
      throw new Error @ `Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`

    // up to 64k packet length; length includes header
    const packet_len = dv.getUint16 @ 2, little_endian
    const header_len = dv.getUint16 @ 4, little_endian
    const type = dv.getUint8 @ 6, little_endian

    let ttl = dv.getUint8 @ 7, little_endian
    if decrement_ttl ::
      ttl = Math.max @ 0, ttl - 1
      dv.setUint8 @ 7, ttl, little_endian

    const id_router = dv.getInt32 @ 8, little_endian
    const id_target = dv.getInt32 @ 12, little_endian
    const info = @{} type, ttl, id_router, id_target
    return @{} info, pkt_header_len, packet_len, header_len


  function packPacket(...args) ::
    let {type, ttl, id_router, id_target, header, body} =
      1 === args.length ? args[0] : Object.assign @ {}, ...args

    if Number.isNaN(+id_router) :: throw new Error @ `Invalid id_router`
    if id_target && Number.isNaN(+id_target) :: throw new Error @ `Invalid id_target`
    header = asBuffer(header, 'header')
    body = asBuffer(body, 'body')

    const len = pkt_header_len + header.byteLength + body.byteLength
    if len > 0xffff :: throw new Error @ `Packet too large`

    const pkthdr = new ArrayBuffer(len)
    const dv = new DataView @ pkthdr, 0, pkt_header_len
    dv.setUint16 @  0, signature, little_endian
    dv.setUint16 @  2, len, little_endian
    dv.setUint16 @  4, header.byteLength, little_endian
    dv.setUint8  @  6, type || 0, little_endian
    dv.setUint8  @  7, ttl || default_ttl, little_endian
    dv.setInt32  @  8, 0 | id_router, little_endian
    dv.setInt32  @ 12, 0 | id_target, little_endian

    const u8 = new Uint8Array(pkthdr)
    u8.set @ new Uint8Array(header), pkt_header_len
    u8.set @ new Uint8Array(body), pkt_header_len + header.byteLength
    return pkthdr


  function fwdHeader(buf, id_router, id_target) ::
    buf = new Uint8Array(buf).buffer
    const dv = new DataView @ buf, 0, pkt_header_len
    if null != id_router :: dv.setInt32  @  8, 0 | id_router, little_endian
    if null != id_target :: dv.setInt32  @ 12, 0 | id_target, little_endian
    return buf


  function packId(id, offset) ::
    const buf = new ArrayBuffer(4)
    new DataView(buf).setInt32 @ offset||0, 0 | id, little_endian
    return buf
  function unpackId(buf, offset) ::
    const dv = new DataView @ asBuffer(buf)
    return dv.getInt32 @ offset||0, little_endian

  function pack_utf8(str) ::
    const te = new _TextEncoder_('utf-8')
    return te.encode(str.toString()).buffer
  function unpack_utf8(buf) ::
    const td = new _TextDecoder_('utf-8')
    return td.decode @ asBuffer @ buf


  function asBuffer(buf) ::
    if null === buf || undefined === buf ::
      return new ArrayBuffer(0)

    if undefined !== buf.byteLength ::
      if undefined === buf.buffer ::
        return buf

      if ArrayBuffer.isView(buf) ::
        return buf.buffer

      if 'function' === typeof buf.readInt32LE ::
        return Uint8Array.from(buf).buffer // NodeJS Buffer

      return buf

    if 'string' === typeof buf ::
      return pack_utf8(buf)

    if Array.isArray(buf) ::
      if Number.isInteger @ buf[0] ::
        return Uint8Array.from(buf).buffer
      return concat @ buf.map @ asBuffer


  function concatBuffers(lst, len) ::
    if 1 === lst.length :: return lst[0]
    if 0 === lst.length :: return new ArrayBuffer(0)

    if null == len ::
      len = 0
      for const arr of lst ::
        len += arr.byteLength

    const u8 = new Uint8Array(len)
    let offset = 0
    for const arr of lst ::
      u8.set @ new Uint8Array(arr), offset
      offset += arr.byteLength
    return u8.buffer

