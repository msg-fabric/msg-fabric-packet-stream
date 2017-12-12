function asPacketParserAPI(packet_impl_methods) {
  const {
    parseHeader, packPacket, fwdHeader,
    asBuffer, concatBuffers,
    unpackId, unpack_utf8 } = packet_impl_methods;

  const pkt_obj_proto = {
    header_buffer() {
      return this._raw_.slice(this.header_offset, this.body_offset);
    },
    header_utf8(buf) {
      return unpack_utf8(buf || this.header_buffer());
    },
    header_json(buf) {
      return JSON.parse(this.header_utf8(buf) || null);
    },

    body_buffer() {
      return this._raw_.slice(this.body_offset);
    },
    body_utf8(buf) {
      return unpack_utf8(buf || this.body_buffer());
    },
    body_json(buf) {
      return JSON.parse(this.body_utf8(buf) || null);
    },

    fwd_to(fwd_id) {
      return asFwdPktObj(this, fwd_id);
    },
    unpackId(buf, offset = 8) {
      return unpackId(buf || this._raw_, offset);
    },
    unpack_utf8 };

  const packetParserAPI = Object.assign(Object.create(null), packet_impl_methods, {
    isPacketParser() {
      return true;
    },
    packPacketObj,
    packetStream,
    asPktObj, asFwdPktObj,
    pkt_obj_proto });

  pkt_obj_proto.packetParser = packetParserAPI;
  return packetParserAPI;

  function packPacketObj(pkt_info) {
    const pkt_raw = packPacket(pkt_info);
    const pkt = parseHeader(pkt_raw);
    pkt._raw_ = pkt_raw;
    return asPktObj(pkt);
  }

  function asPktObj({ info, pkt_header_len, packet_len, header_len, _raw_ }) {
    let body_offset = pkt_header_len + header_len;
    if (body_offset > packet_len) {
      body_offset = null; // invalid packet construction
    }const pkt_obj = Object.create(pkt_obj_proto, {
      header_offset: { value: pkt_header_len },
      body_offset: { value: body_offset },
      packet_len: { value: packet_len },
      _raw_: { value: _raw_ } });

    return Object.assign(pkt_obj, info);
  }

  function asFwdPktObj(pkt_obj, { id_router, id_target }) {
    if (null == id_target) {
      throw new Error('id_target required');
    }
    const raw = fwdHeader(pkt_obj._raw_, id_router, id_target);
    const fwd_obj = Object.create(pkt_obj, { _raw_: { value: _raw_ } });
    if (null != id_router) {
      fwd_obj.id_router = id_router;
    }
    if (null != id_target) {
      fwd_obj.id_target = id_target;
    }
    fwd_obj.is_fwd = true;
    return fwd_obj;
  }

  function packetStream(options) {
    if (!options) {
      options = {};
    }

    const decrement_ttl = null == options.decrement_ttl ? true : !!options.decrement_ttl;

    let tip = null,
        qByteLen = 0,
        q = [];
    return feed;

    function feed(data, complete = []) {
      data = asBuffer(data);
      q.push(data);
      qByteLen += data.byteLength;

      while (1) {
        const pkt = parseTipPacket();
        if (undefined !== pkt) {
          complete.push(pkt);
        } else return complete;
      }
    }

    function parseTipPacket() {
      if (null === tip) {
        if (0 === q.length) {
          return;
        }
        if (1 < q.length) {
          q = [concatBuffers(q, qByteLen)];
        }

        tip = parseHeader(q[0], decrement_ttl);
        if (null === tip) {
          return;
        }
      }

      const len = tip.packet_len;
      if (qByteLen < len) {
        return;
      }

      let bytes = 0,
          n = 0;
      while (bytes < len) {
        bytes += q[n++].byteLength;
      }

      const trailingBytes = bytes - len;
      if (0 === trailingBytes) {
        // we have an exact length match
        const parts = q.splice(0, n);
        qByteLen -= len;

        tip._raw_ = concatBuffers(parts, len);
      } else {
        // we have trailing bytes on the last array
        const parts = 1 === q.length ? [] : q.splice(0, n - 1);
        const tail = q[0];

        parts.push(tail.slice(0, -trailingBytes));
        q[0] = tail.slice(-trailingBytes);
        qByteLen -= len;

        tip._raw_ = concatBuffers(parts, len);
      }

      {
        const pkt_obj = asPktObj(tip);
        tip = null;
        return pkt_obj;
      }
    }
  }
}

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

const signature = 0xedfe;
const pkt_header_len = 16;
const default_ttl = 31;

function createBufferPacketParser$1(options = {}) {
  return asPacketParserAPI({
    parseHeader, packPacket, fwdHeader,
    packId, unpackId, pack_utf8, unpack_utf8,

    asBuffer, concatBuffers });

  function parseHeader(buf, decrement_ttl) {
    if (pkt_header_len > buf.byteLength) {
      return null;
    }

    const sig = buf.readUInt16LE(0);
    if (signature !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`);
    }

    // up to 64k packet length; length includes header
    const packet_len = buf.readUInt16LE(2);
    const header_len = buf.readUInt16LE(4);
    const type = buf.readUInt8(6);

    let ttl = buf.readUInt8(7);
    if (decrement_ttl) {
      ttl = Math.max(0, ttl - 1);
      buf.writeUInt8(ttl, 7);
    }

    const id_router = buf.readInt32LE(8);
    const id_target = buf.readInt32LE(12);
    const info = { type, ttl, id_router, id_target };
    return { info, pkt_header_len, packet_len, header_len };
  }

  function packPacket(pkt_info) {
    let { type, ttl, id_router, id_target, header, body } = pkt_info;

    if (Number.isNaN(+id_router)) {
      throw new Error(`Invalid id_router`);
    }
    if (id_target && Number.isNaN(+id_target)) {
      throw new Error(`Invalid id_target`);
    }
    header = asBuffer(header);
    body = asBuffer(body);

    const packet_len = pkt_header_len + header.byteLength + body.byteLength;
    if (packet_len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const pkthdr = Buffer.alloc(pkt_header_len);
    pkthdr.writeUInt16LE(signature, 0);
    pkthdr.writeUInt16LE(packet_len, 2);
    pkthdr.writeUInt16LE(header.byteLength, 4);
    pkthdr.writeUInt8(type || 0, 6);
    pkthdr.writeUInt8(ttl || default_ttl, 7);
    pkthdr.writeInt32LE(0 | id_router, 8);
    pkthdr.writeInt32LE(0 | id_target, 12);

    const buf = Buffer.concat([pkthdr, header, body]);
    if (packet_len !== buf.byteLength) {
      throw new Error(`Packet length mismatch (library error)`);
    }
    return buf;
  }

  function fwdHeader(buf, id_router, id_target) {
    buf = new Buffer(buf);
    if (null != id_router) {
      buf.writeInt32LE(0 | id_router, 8);
    }
    if (null != id_target) {
      buf.writeInt32LE(0 | id_target, 12);
    }
    return buf;
  }

  function packId(id, offset) {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(0 | id, offset || 0);
    return buf;
  }
  function unpackId(buf, offset) {
    return buf.readInt32LE(offset || 0);
  }

  function pack_utf8(str) {
    return Buffer.from(str, 'utf-8');
  }
  function unpack_utf8(buf) {
    return asBuffer(buf).toString('utf-8');
  }

  function asBuffer(buf) {
    if (null === buf || undefined === buf) {
      return Buffer(0);
    }

    if (Buffer.isBuffer(buf)) {
      return buf;
    }

    if ('string' === typeof buf) {
      return pack_utf8(buf);
    }

    if (undefined !== buf.byteLength) {
      if (ArrayBuffer.isView(buf)) {
        return Buffer.from(buf.buffer // DataView
        );
      } else {
        return Buffer.from(buf // TypedArray or ArrayBuffer
        );
      }
    }

    if (Array.isArray(buf)) {
      if (Number.isInteger(buf[0])) {
        return Buffer.from(buf);
      }
      return Buffer.concat(buf.map(asBuffer));
    }
  }

  function concatBuffers(lst, len) {
    if (1 === lst.length) {
      return lst[0];
    }
    if (0 === lst.length) {
      return Buffer(0);
    }
    return Buffer.concat(lst);
  }
}

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

const signature$1 = 0xedfe;
const pkt_header_len$1 = 16;
const default_ttl$1 = 31;

const little_endian = true;

function createDataViewPacketParser(options = {}) {
  const _TextEncoder_ = options.TextEncoder || TextEncoder;
  const _TextDecoder_ = options.TextDecoder || TextDecoder;

  return asPacketParserAPI({
    parseHeader, packPacket, fwdHeader,
    packId, unpackId, pack_utf8, unpack_utf8,

    asBuffer, concatBuffers });

  function parseHeader(buf, decrement_ttl) {
    if (pkt_header_len$1 > buf.byteLength) {
      return null;
    }

    const dv = new DataView(buf);

    const sig = dv.getUint16(0, little_endian);
    if (signature$1 !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature$1.toString(16)})`);
    }

    // up to 64k packet length; length includes header
    const packet_len = dv.getUint16(2, little_endian);
    const header_len = dv.getUint16(4, little_endian);
    const type = dv.getUint8(6, little_endian);

    let ttl = dv.getUint8(7, little_endian);
    if (decrement_ttl) {
      ttl = Math.max(0, ttl - 1);
      dv.setUint8(7, ttl, little_endian);
    }

    const id_router = dv.getInt32(8, little_endian);
    const id_target = dv.getInt32(12, little_endian);
    const info = { type, ttl, id_router, id_target };
    return { info, pkt_header_len: pkt_header_len$1, packet_len, header_len };
  }

  function packPacket(pkt_info) {
    let { type, ttl, id_router, id_target, header, body } = pkt_info;

    if (Number.isNaN(+id_router)) {
      throw new Error(`Invalid id_router`);
    }
    if (id_target && Number.isNaN(+id_target)) {
      throw new Error(`Invalid id_target`);
    }
    header = asBuffer(header, 'header');
    body = asBuffer(body, 'body');

    const len = pkt_header_len$1 + header.byteLength + body.byteLength;
    if (len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const pkthdr = new ArrayBuffer(len);
    const dv = new DataView(pkthdr, 0, pkt_header_len$1);
    dv.setUint16(0, signature$1, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl$1, little_endian);
    dv.setInt32(8, 0 | id_router, little_endian);
    dv.setInt32(12, 0 | id_target, little_endian);

    const u8 = new Uint8Array(pkthdr);
    u8.set(new Uint8Array(header), pkt_header_len$1);
    u8.set(new Uint8Array(body), pkt_header_len$1 + header.byteLength);
    return pkthdr;
  }

  function fwdHeader(buf, id_router, id_target) {
    buf = new Uint8Array(buf).buffer;
    const dv = new DataView(buf, 0, pkt_header_len$1);
    if (null != id_router) {
      dv.setInt32(8, 0 | id_router, little_endian);
    }
    if (null != id_target) {
      dv.setInt32(12, 0 | id_target, little_endian);
    }
    return buf;
  }

  function packId(id, offset) {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setInt32(offset || 0, 0 | id, little_endian);
    return buf;
  }
  function unpackId(buf, offset) {
    const dv = new DataView(asBuffer(buf));
    return dv.getInt32(offset || 0, little_endian);
  }

  function pack_utf8(str) {
    const te = new _TextEncoder_('utf-8');
    return te.encode(str.toString()).buffer;
  }
  function unpack_utf8(buf) {
    const td = new _TextDecoder_('utf-8');
    return td.decode(asBuffer(buf));
  }

  function asBuffer(buf) {
    if (null === buf || undefined === buf) {
      return new ArrayBuffer(0);
    }

    if (undefined !== buf.byteLength) {
      if (undefined === buf.buffer) {
        return buf;
      }

      if (ArrayBuffer.isView(buf)) {
        return buf.buffer;
      }

      if ('function' === typeof buf.readInt32LE) {
        return Uint8Array.from(buf).buffer; // NodeJS Buffer
      }return buf;
    }

    if ('string' === typeof buf) {
      return pack_utf8(buf);
    }

    if (Array.isArray(buf)) {
      if (Number.isInteger(buf[0])) {
        return Uint8Array.from(buf).buffer;
      }
      return concat(buf.map(asBuffer));
    }
  }

  function concatBuffers(lst, len) {
    if (1 === lst.length) {
      return lst[0];
    }
    if (0 === lst.length) {
      return new ArrayBuffer(0);
    }

    if (null == len) {
      len = 0;
      for (const arr of lst) {
        len += arr.byteLength;
      }
    }

    const u8 = new Uint8Array(len);
    let offset = 0;
    for (const arr of lst) {
      u8.set(new Uint8Array(arr), offset);
      offset += arr.byteLength;
    }
    return u8.buffer;
  }
}

export { asPacketParserAPI, createBufferPacketParser$1 as createBufferPacketParser, createDataViewPacketParser };
export default createBufferPacketParser$1;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG4gICAgdW5wYWNrSWQsIHVucGFja191dGY4XG4gID0gcGFja2V0X2ltcGxfbWV0aG9kc1xuXG4gIGNvbnN0IHBrdF9vYmpfcHJvdG8gPSBAe31cbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGZ3ZF90byhmd2RfaWQpIDo6IHJldHVybiBhc0Z3ZFBrdE9iaiBAIHRoaXMsIGZ3ZF9pZFxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tQYWNrZXRPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNQa3RPYmosIGFzRndkUGt0T2JqXG4gICAgICBwa3Rfb2JqX3Byb3RvXG5cbiAgcGt0X29ial9wcm90by5wYWNrZXRQYXJzZXIgPSBwYWNrZXRQYXJzZXJBUElcbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldE9iaihwa3RfaW5mbykgOjpcbiAgICBjb25zdCBwa3RfcmF3ID0gcGFja1BhY2tldCBAIHBrdF9pbmZvXG4gICAgY29uc3QgcGt0ID0gcGFyc2VIZWFkZXIgQCBwa3RfcmF3XG4gICAgcGt0Ll9yYXdfID0gcGt0X3Jhd1xuICAgIHJldHVybiBhc1BrdE9iaihwa3QpXG5cblxuICBmdW5jdGlvbiBhc1BrdE9iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIHBhY2tldCBjb25zdHJ1Y3Rpb25cblxuICAgIGNvbnN0IHBrdF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29ial9wcm90bywgQHt9XG4gICAgICBoZWFkZXJfb2Zmc2V0OiBAe30gdmFsdWU6IHBrdF9oZWFkZXJfbGVuXG4gICAgICBib2R5X29mZnNldDogQHt9IHZhbHVlOiBib2R5X29mZnNldFxuICAgICAgcGFja2V0X2xlbjogQHt9IHZhbHVlOiBwYWNrZXRfbGVuXG4gICAgICBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuXG4gICAgcmV0dXJuIE9iamVjdC5hc3NpZ24gQCBwa3Rfb2JqLCBpbmZvXG5cbiAgZnVuY3Rpb24gYXNGd2RQa3RPYmoocGt0X29iaiwge2lkX3JvdXRlciwgaWRfdGFyZ2V0fSkgOjpcbiAgICBpZiBudWxsID09IGlkX3RhcmdldCA6OiB0aHJvdyBuZXcgRXJyb3IgQCAnaWRfdGFyZ2V0IHJlcXVpcmVkJ1xuICAgIGNvbnN0IHJhdyA9IGZ3ZEhlYWRlciBAIHBrdF9vYmouX3Jhd18sIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgY29uc3QgZndkX29iaiA9IE9iamVjdC5jcmVhdGUgQCBwa3Rfb2JqLCBAe30gX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cbiAgICBpZiBudWxsICE9IGlkX3JvdXRlciA6OiBmd2Rfb2JqLmlkX3JvdXRlciA9IGlkX3JvdXRlclxuICAgIGlmIG51bGwgIT0gaWRfdGFyZ2V0IDo6IGZ3ZF9vYmouaWRfdGFyZ2V0ID0gaWRfdGFyZ2V0XG4gICAgZndkX29iai5pc19md2QgPSB0cnVlXG4gICAgcmV0dXJuIGZ3ZF9vYmpcblxuXG4gIGZ1bmN0aW9uIHBhY2tldFN0cmVhbShvcHRpb25zKSA6OlxuICAgIGlmICEgb3B0aW9ucyA6OiBvcHRpb25zID0ge31cblxuICAgIGNvbnN0IGRlY3JlbWVudF90dGwgPVxuICAgICAgbnVsbCA9PSBvcHRpb25zLmRlY3JlbWVudF90dGxcbiAgICAgICAgPyB0cnVlIDogISEgb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG5cbiAgICBsZXQgdGlwPW51bGwsIHFCeXRlTGVuID0gMCwgcSA9IFtdXG4gICAgcmV0dXJuIGZlZWRcblxuICAgIGZ1bmN0aW9uIGZlZWQoZGF0YSwgY29tcGxldGU9W10pIDo6XG4gICAgICBkYXRhID0gYXNCdWZmZXIoZGF0YSlcbiAgICAgIHEucHVzaCBAIGRhdGFcbiAgICAgIHFCeXRlTGVuICs9IGRhdGEuYnl0ZUxlbmd0aFxuXG4gICAgICB3aGlsZSAxIDo6XG4gICAgICAgIGNvbnN0IHBrdCA9IHBhcnNlVGlwUGFja2V0KClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBwa3QgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgcGt0XG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwUGFja2V0KCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBwa3Rfb2JqID0gYXNQa3RPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBwa3Rfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3Qgc2lnID0gYnVmLnJlYWRVSW50MTZMRSBAIDBcbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDJcbiAgICBjb25zdCBoZWFkZXJfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDRcbiAgICBjb25zdCB0eXBlID0gYnVmLnJlYWRVSW50OCBAIDZcblxuICAgIGxldCB0dGwgPSBidWYucmVhZFVJbnQ4IEAgN1xuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgYnVmLndyaXRlVUludDggQCB0dGwsIDdcblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGJ1Zi5yZWFkSW50MzJMRSBAIDhcbiAgICBjb25zdCBpZF90YXJnZXQgPSBidWYucmVhZEludDMyTEUgQCAxMlxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAe30gaW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW5cblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXQocGt0X2luZm8pIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gcGt0X2luZm9cblxuICAgIGlmIE51bWJlci5pc05hTigraWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmIE51bWJlci5pc05hTigraWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5KVxuXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBwYWNrZXRfbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgcGt0aGRyID0gQnVmZmVyLmFsbG9jIEAgcGt0X2hlYWRlcl9sZW5cbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIHNpZ25hdHVyZSwgMFxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgcGFja2V0X2xlbiwgMlxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgaGVhZGVyLmJ5dGVMZW5ndGgsIDRcbiAgICBwa3RoZHIud3JpdGVVSW50OCBAIHR5cGUgfHwgMCwgNlxuICAgIHBrdGhkci53cml0ZVVJbnQ4IEAgdHRsIHx8IGRlZmF1bHRfdHRsLCA3XG4gICAgcGt0aGRyLndyaXRlSW50MzJMRSBAIDAgfCBpZF9yb3V0ZXIsIDhcbiAgICBwa3RoZHIud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3RhcmdldCwgMTJcblxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5jb25jYXQgQCMgcGt0aGRyLCBoZWFkZXIsIGJvZHlcbiAgICBpZiBwYWNrZXRfbGVuICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBCdWZmZXIoYnVmKVxuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZCwgb2Zmc2V0fHwwXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRJbnQzMkxFIEAgb2Zmc2V0fHwwXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBCdWZmZXIoMClcblxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20gQCBidWYuYnVmZmVyIC8vIERhdGFWaWV3XG4gICAgICBlbHNlIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbSBAIGJ1ZiAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZilcbiAgICAgIHJldHVybiBCdWZmZXIuY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIEJ1ZmZlcigwKVxuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KGxzdClcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldEludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGR2LmdldEludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KHBrdF9pbmZvKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IHBrdF9pbmZvXG5cbiAgICBpZiBOdW1iZXIuaXNOYU4oK2lkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiBOdW1iZXIuaXNOYU4oK2lkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3RoZHIgPSBuZXcgQXJyYXlCdWZmZXIobGVuKVxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgcGt0aGRyLCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KHBrdGhkcilcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShoZWFkZXIpLCBwa3RfaGVhZGVyX2xlblxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGJvZHkpLCBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHBrdGhkclxuXG5cbiAgZnVuY3Rpb24gZndkSGVhZGVyKGJ1ZiwgaWRfcm91dGVyLCBpZF90YXJnZXQpIDo6XG4gICAgYnVmID0gbmV3IFVpbnQ4QXJyYXkoYnVmKS5idWZmZXJcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZiwgMCwgcGt0X2hlYWRlcl9sZW5cbiAgICBpZiBudWxsICE9IGlkX3JvdXRlciA6OiBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGlmIG51bGwgIT0gaWRfdGFyZ2V0IDo6IGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0SW50MzIgQCBvZmZzZXR8fDAsIDAgfCBpZCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhc0J1ZmZlcihidWYpXG4gICAgcmV0dXJuIGR2LmdldEludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRJbnQzMkxFIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXIgLy8gTm9kZUpTIEJ1ZmZlclxuXG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwicGFja1BhY2tldCIsImZ3ZEhlYWRlciIsImNvbmNhdEJ1ZmZlcnMiLCJ1bnBhY2tfdXRmOCIsInBrdF9vYmpfcHJvdG8iLCJfcmF3XyIsInNsaWNlIiwiaGVhZGVyX29mZnNldCIsImJvZHlfb2Zmc2V0IiwiYnVmIiwiaGVhZGVyX2J1ZmZlciIsIkpTT04iLCJwYXJzZSIsImhlYWRlcl91dGY4IiwiYm9keV9idWZmZXIiLCJib2R5X3V0ZjgiLCJmd2RfaWQiLCJhc0Z3ZFBrdE9iaiIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja2V0UGFyc2VyIiwicGFja1BhY2tldE9iaiIsInBrdF9pbmZvIiwicGt0X3JhdyIsInBrdCIsInBhcnNlSGVhZGVyIiwiYXNQa3RPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBrdF9vYmoiLCJ2YWx1ZSIsImlkX3JvdXRlciIsImlkX3RhcmdldCIsIkVycm9yIiwicmF3IiwiZndkX29iaiIsImlzX2Z3ZCIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcFBhY2tldCIsInVuZGVmaW5lZCIsImxlbmd0aCIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsInRvU3RyaW5nIiwidHlwZSIsInJlYWRVSW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJ3cml0ZVVJbnQ4IiwicmVhZEludDMyTEUiLCJoZWFkZXIiLCJib2R5IiwiTnVtYmVyIiwiaXNOYU4iLCJwa3RoZHIiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZUludDMyTEUiLCJjb25jYXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsImZyb20iLCJpc0J1ZmZlciIsIkFycmF5QnVmZmVyIiwiaXNWaWV3IiwiYnVmZmVyIiwiQXJyYXkiLCJpc0FycmF5IiwiaXNJbnRlZ2VyIiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRJbnQzMiIsInNldFVpbnQxNiIsInNldEludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJ0ZCIsImRlY29kZSIsImFyciJdLCJtYXBwaW5ncyI6IkFBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBLEVBQ1NDLFVBRFQsRUFDcUJDLFNBRHJCO1lBQUEsRUFFTUMsYUFGTjtZQUFBLEVBR01DLFdBSE4sS0FJSkosbUJBSkY7O1FBTU1LLGdCQUFnQjtvQkFDSjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREM7Z0JBRVJDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGQTtnQkFHUkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FBeUIsSUFBdEMsQ0FBUDtLQUhBOztrQkFLTjthQUFVLEtBQUtKLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEc7Y0FNVkMsR0FBVixFQUFlO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0ssV0FBTCxFQUFyQixDQUFQO0tBTkU7Y0FPVkwsR0FBVixFQUFlO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLRyxTQUFMLENBQWVOLEdBQWYsS0FBdUIsSUFBcEMsQ0FBUDtLQVBFOztX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
