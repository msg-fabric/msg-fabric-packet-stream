
export default function asPacketParserAPI(packet_impl_methods) ::
  const @{}
    parseHeader
    packMessage
    asBuffer
    concatBuffers
    unpackId, unpack_utf8
  = packet_impl_methods

  const msg_obj_proto = @:
    header_buffer() :: return this._raw_.slice @ this.header_offset, this.body_offset
    header_utf8() :: return unpack_utf8 @ this.header_buffer()
    header_json() :: return JSON.parse @ this.header_utf8() || null

    body_buffer() :: return this._raw_.slice @ this.body_offset
    body_utf8() :: return unpack_utf8 @ this.body_buffer()
    body_json() :: return JSON.parse @ this.body_utf8() || null

    unpackId(buf, offset=8) :: return unpackId(buf || this._raw_, offset)

  const packetParserAPI = Object.assign @
    Object.create(null)
    packet_impl_methods
    @{}
      packMessageObj
      packetStream
      asMsgObj
      msg_obj_proto
  return packetParserAPI


  function packMessageObj(...args) ::
    const msg_raw = packMessage @ ...args
    const msg_obj = asMsgObj @ parseHeader @ msg_raw
    Object.defineProperties @ msg_obj, @:
      _raw_: @{} value: msg_raw
    return msg_obj


  function asMsgObj({info, pkt_header_len, packet_len, header_len, _raw_}) ::
    let body_offset = pkt_header_len + header_len
    if body_offset > packet_len ::
      body_offset = null // invalid message construction

    const msg_obj = Object.create @ msg_obj_proto, @:
      header_offset: @{} value: pkt_header_len
      body_offset: @{} value: body_offset
      packet_len: @{} value: packet_len
      _raw_: @{} value: _raw_

    return Object.assign @ msg_obj, info


  function packetStream(options) ::
    if ! options :: options = {}

    const decrement_ttl =
      null == options.decrement_ttl
        ? true : !! options.decrement_ttl

    let tip=null, qByteLen = 0, q = []
    return feed

    function feed(data, complete=[]) ::
      data = asBuffer(data)
      q.push @ data
      qByteLen += data.byteLength

      while 1 ::
        const msg = parseTipMessage()
        if undefined !== msg ::
          complete.push @ msg
        else return complete


    function parseTipMessage() ::
      if null === tip ::
        if 0 === q.length ::
          return
        if 1 < q.length ::
          q = @[] concatBuffers @ q, qByteLen

        tip = parseHeader @ q[0], decrement_ttl
        if null === tip :: return

      const len = tip.packet_len
      if qByteLen < len ::
        return

      let bytes = 0, n = 0
      while bytes < len ::
        bytes += q[n++].byteLength

      const trailingBytes = bytes - len
      if 0 === trailingBytes :: // we have an exact length match
        const parts = q.splice(0, n)
        qByteLen -= len

        tip._raw_ = concatBuffers @ parts, len

      else :: // we have trailing bytes on the last array
        const parts = 1 === q.length ? [] : q.splice(0, n-1)
        const tail = q[0]

        parts.push @ tail.slice(0, -trailingBytes)
        q[0] = tail.slice(-trailingBytes)
        qByteLen -= len

        tip._raw_ = concatBuffers @ parts, len

      ::
        const msg_obj = asMsgObj(tip)
        tip = null
        return msg_obj

