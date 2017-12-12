
export default function asPacketParserAPI(packet_impl_methods) ::
  const @{}
    parseHeader, packPacket, fwdHeader
    asBuffer, concatBuffers
    unpackId, unpack_utf8
  = packet_impl_methods

  const pkt_obj_proto = @{}
    header_buffer() :: return this._raw_.slice @ this.header_offset, this.body_offset
    header_utf8(buf) :: return unpack_utf8 @ buf || this.header_buffer()
    header_json(buf) :: return JSON.parse @ this.header_utf8(buf) || null

    body_buffer() :: return this._raw_.slice @ this.body_offset
    body_utf8(buf) :: return unpack_utf8 @ buf || this.body_buffer()
    body_json(buf) :: return JSON.parse @ this.body_utf8(buf) || null

    fwd_to(fwd_id) :: return asFwdPktObj @ this, fwd_id
    unpackId(buf, offset=8) :: return unpackId(buf || this._raw_, offset)
    unpack_utf8

  const packetParserAPI = Object.assign @
    Object.create(null)
    packet_impl_methods
    @{}
      isPacketParser() :: return true
      packPacketObj
      packetStream
      asPktObj, asFwdPktObj
      pkt_obj_proto

  pkt_obj_proto.packetParser = packetParserAPI
  return packetParserAPI


  function packPacketObj(pkt_info) ::
    const pkt_raw = packPacket @ pkt_info
    const pkt = parseHeader @ pkt_raw
    pkt._raw_ = pkt_raw
    return asPktObj(pkt)


  function asPktObj({info, pkt_header_len, packet_len, header_len, _raw_}) ::
    let body_offset = pkt_header_len + header_len
    if body_offset > packet_len ::
      body_offset = null // invalid packet construction

    const pkt_obj = Object.create @ pkt_obj_proto, @{}
      header_offset: @{} value: pkt_header_len
      body_offset: @{} value: body_offset
      packet_len: @{} value: packet_len
      _raw_: @{} value: _raw_

    return Object.assign @ pkt_obj, info

  function asFwdPktObj(pkt_obj, {id_router, id_target}) ::
    if null == id_target :: throw new Error @ 'id_target required'
    const raw = fwdHeader @ pkt_obj._raw_, id_router, id_target
    const fwd_obj = Object.create @ pkt_obj, @{} _raw_: @{} value: _raw_
    if null != id_router :: fwd_obj.id_router = id_router
    if null != id_target :: fwd_obj.id_target = id_target
    fwd_obj.is_fwd = true
    return fwd_obj


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
        const pkt = parseTipPacket()
        if undefined !== pkt ::
          complete.push @ pkt
        else return complete


    function parseTipPacket() ::
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
        const pkt_obj = asPktObj(tip)
        tip = null
        return pkt_obj

