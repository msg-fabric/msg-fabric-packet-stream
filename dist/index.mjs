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

  function packPacketObj(...args) {
    const pkt_raw = packPacket(...args);
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

  function packPacket(...args) {
    let { type, ttl, id_router, id_target, header, body } = 1 === args.length ? args[0] : Object.assign({}, ...args);

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

  function packPacket(...args) {
    let { type, ttl, id_router, id_target, header, body } = 1 === args.length ? args[0] : Object.assign({}, ...args);

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG4gICAgdW5wYWNrSWQsIHVucGFja191dGY4XG4gID0gcGFja2V0X2ltcGxfbWV0aG9kc1xuXG4gIGNvbnN0IHBrdF9vYmpfcHJvdG8gPSBAe31cbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGZ3ZF90byhmd2RfaWQpIDo6IHJldHVybiBhc0Z3ZFBrdE9iaiBAIHRoaXMsIGZ3ZF9pZFxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tQYWNrZXRPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNQa3RPYmosIGFzRndkUGt0T2JqXG4gICAgICBwa3Rfb2JqX3Byb3RvXG5cbiAgcGt0X29ial9wcm90by5wYWNrZXRQYXJzZXIgPSBwYWNrZXRQYXJzZXJBUElcbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldE9iaiguLi5hcmdzKSA6OlxuICAgIGNvbnN0IHBrdF9yYXcgPSBwYWNrUGFja2V0IEAgLi4uYXJnc1xuICAgIGNvbnN0IHBrdCA9IHBhcnNlSGVhZGVyIEAgcGt0X3Jhd1xuICAgIHBrdC5fcmF3XyA9IHBrdF9yYXdcbiAgICByZXR1cm4gYXNQa3RPYmoocGt0KVxuXG5cbiAgZnVuY3Rpb24gYXNQa3RPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBwYWNrZXQgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBwa3Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmpfcHJvdG8sIEB7fVxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgcGt0X29iaiwgaW5mb1xuXG4gIGZ1bmN0aW9uIGFzRndkUGt0T2JqKHBrdF9vYmosIHtpZF9yb3V0ZXIsIGlkX3RhcmdldH0pIDo6XG4gICAgaWYgbnVsbCA9PSBpZF90YXJnZXQgOjogdGhyb3cgbmV3IEVycm9yIEAgJ2lkX3RhcmdldCByZXF1aXJlZCdcbiAgICBjb25zdCByYXcgPSBmd2RIZWFkZXIgQCBwa3Rfb2JqLl9yYXdfLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIGNvbnN0IGZ3ZF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29iaiwgQHt9IF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZndkX29iai5pZF9yb3V0ZXIgPSBpZF9yb3V0ZXJcbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBmd2Rfb2JqLmlkX3RhcmdldCA9IGlkX3RhcmdldFxuICAgIGZ3ZF9vYmouaXNfZndkID0gdHJ1ZVxuICAgIHJldHVybiBmd2Rfb2JqXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBwa3QgPSBwYXJzZVRpcFBhY2tldCgpXG4gICAgICAgIGlmIHVuZGVmaW5lZCAhPT0gcGt0IDo6XG4gICAgICAgICAgY29tcGxldGUucHVzaCBAIHBrdFxuICAgICAgICBlbHNlIHJldHVybiBjb21wbGV0ZVxuXG5cbiAgICBmdW5jdGlvbiBwYXJzZVRpcFBhY2tldCgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgcGt0X29iaiA9IGFzUGt0T2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gcGt0X29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZEludDMyTEUgQCA4XG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gYnVmLnJlYWRJbnQzMkxFIEAgMTJcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID1cbiAgICAgIDEgPT09IGFyZ3MubGVuZ3RoID8gYXJnc1swXSA6IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuXG4gICAgaWYgTnVtYmVyLmlzTmFOKCtpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgTnVtYmVyLmlzTmFOKCtpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHkpXG5cbiAgICBjb25zdCBwYWNrZXRfbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3RoZHIgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX2xlblxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0aGRyLndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0aGRyLndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdGhkci53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0aGRyLndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBwa3RoZHIud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIHBrdGhkci53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuXG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmNvbmNhdCBAIyBwa3RoZHIsIGhlYWRlciwgYm9keVxuICAgIGlmIHBhY2tldF9sZW4gIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IGxlbmd0aCBtaXNtYXRjaCAobGlicmFyeSBlcnJvcilgXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gZndkSGVhZGVyKGJ1ZiwgaWRfcm91dGVyLCBpZF90YXJnZXQpIDo6XG4gICAgYnVmID0gbmV3IEJ1ZmZlcihidWYpXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZF9yb3V0ZXIsIDhcbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBidWYud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3RhcmdldCwgMTJcbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBCdWZmZXIuYWxsb2MoNClcbiAgICBidWYud3JpdGVJbnQzMkxFIEAgMCB8IGlkLCBvZmZzZXR8fDBcbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIHJldHVybiBidWYucmVhZEludDMyTEUgQCBvZmZzZXR8fDBcblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIHJldHVybiBCdWZmZXIuZnJvbShzdHIsICd1dGYtOCcpXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICByZXR1cm4gYXNCdWZmZXIoYnVmKS50b1N0cmluZygndXRmLTgnKVxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlcigwKVxuXG4gICAgaWYgQnVmZmVyLmlzQnVmZmVyKGJ1ZikgOjpcbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbSBAIGJ1Zi5idWZmZXIgLy8gRGF0YVZpZXdcbiAgICAgIGVsc2UgOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tIEAgYnVmIC8vIFR5cGVkQXJyYXkgb3IgQXJyYXlCdWZmZXJcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKVxuICAgICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gQnVmZmVyKDApXG4gICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQobHN0KVxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja1BhY2tldCwgZndkSGVhZGVyXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0SW50MzIgQCA4LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gZHYuZ2V0SW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAe30gaW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW5cblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXQoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPVxuICAgICAgMSA9PT0gYXJncy5sZW5ndGggPyBhcmdzWzBdIDogT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG5cbiAgICBpZiBOdW1iZXIuaXNOYU4oK2lkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiBOdW1iZXIuaXNOYU4oK2lkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3RoZHIgPSBuZXcgQXJyYXlCdWZmZXIobGVuKVxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgcGt0aGRyLCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KHBrdGhkcilcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShoZWFkZXIpLCBwa3RfaGVhZGVyX2xlblxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGJvZHkpLCBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHBrdGhkclxuXG5cbiAgZnVuY3Rpb24gZndkSGVhZGVyKGJ1ZiwgaWRfcm91dGVyLCBpZF90YXJnZXQpIDo6XG4gICAgYnVmID0gbmV3IFVpbnQ4QXJyYXkoYnVmKS5idWZmZXJcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZiwgMCwgcGt0X2hlYWRlcl9sZW5cbiAgICBpZiBudWxsICE9IGlkX3JvdXRlciA6OiBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGlmIG51bGwgIT0gaWRfdGFyZ2V0IDo6IGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0SW50MzIgQCBvZmZzZXR8fDAsIDAgfCBpZCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhc0J1ZmZlcihidWYpXG4gICAgcmV0dXJuIGR2LmdldEludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRJbnQzMkxFIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXIgLy8gTm9kZUpTIEJ1ZmZlclxuXG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwicGFja1BhY2tldCIsImZ3ZEhlYWRlciIsImNvbmNhdEJ1ZmZlcnMiLCJ1bnBhY2tfdXRmOCIsInBrdF9vYmpfcHJvdG8iLCJfcmF3XyIsInNsaWNlIiwiaGVhZGVyX29mZnNldCIsImJvZHlfb2Zmc2V0IiwiYnVmIiwiaGVhZGVyX2J1ZmZlciIsIkpTT04iLCJwYXJzZSIsImhlYWRlcl91dGY4IiwiYm9keV9idWZmZXIiLCJib2R5X3V0ZjgiLCJmd2RfaWQiLCJhc0Z3ZFBrdE9iaiIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja2V0UGFyc2VyIiwicGFja1BhY2tldE9iaiIsImFyZ3MiLCJwa3RfcmF3IiwicGt0IiwicGFyc2VIZWFkZXIiLCJhc1BrdE9iaiIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwicGt0X29iaiIsInZhbHVlIiwiaWRfcm91dGVyIiwiaWRfdGFyZ2V0IiwiRXJyb3IiLCJyYXciLCJmd2Rfb2JqIiwiaXNfZndkIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsInBhcnNlVGlwUGFja2V0IiwidW5kZWZpbmVkIiwibGVuZ3RoIiwibGVuIiwiYnl0ZXMiLCJuIiwidHJhaWxpbmdCeXRlcyIsInBhcnRzIiwic3BsaWNlIiwidGFpbCIsInNpZ25hdHVyZSIsImRlZmF1bHRfdHRsIiwiY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIiwicGFja191dGY4Iiwic2lnIiwicmVhZFVJbnQxNkxFIiwidG9TdHJpbmciLCJ0eXBlIiwicmVhZFVJbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsIndyaXRlVUludDgiLCJyZWFkSW50MzJMRSIsImhlYWRlciIsImJvZHkiLCJOdW1iZXIiLCJpc05hTiIsInBrdGhkciIsIkJ1ZmZlciIsImFsbG9jIiwid3JpdGVVSW50MTZMRSIsIndyaXRlSW50MzJMRSIsImNvbmNhdCIsInBhY2tJZCIsImlkIiwic3RyIiwiZnJvbSIsImlzQnVmZmVyIiwiQXJyYXlCdWZmZXIiLCJpc1ZpZXciLCJidWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJpc0ludGVnZXIiLCJtYXAiLCJsc3QiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJkdiIsIkRhdGFWaWV3IiwiZ2V0VWludDE2IiwiZ2V0VWludDgiLCJzZXRVaW50OCIsImdldEludDMyIiwic2V0VWludDE2Iiwic2V0SW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJ0ZSIsImVuY29kZSIsInRkIiwiZGVjb2RlIiwiYXJyIl0sIm1hcHBpbmdzIjoiQUFDZSxTQUFTQSxpQkFBVCxDQUEyQkMsbUJBQTNCLEVBQWdEO1FBQ3ZEO2VBQUEsRUFDU0MsVUFEVCxFQUNxQkMsU0FEckI7WUFBQSxFQUVNQyxhQUZOO1lBQUEsRUFHTUMsV0FITixLQUlKSixtQkFKRjs7UUFNTUssZ0JBQWdCO29CQUNKO2FBQVUsS0FBS0MsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtDLGFBQXhCLEVBQXVDLEtBQUtDLFdBQTVDLENBQVA7S0FEQztnQkFFUkMsR0FBWixFQUFpQjthQUFVTixZQUFjTSxPQUFPLEtBQUtDLGFBQUwsRUFBckIsQ0FBUDtLQUZBO2dCQUdSRCxHQUFaLEVBQWlCO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLQyxXQUFMLENBQWlCSixHQUFqQixLQUF5QixJQUF0QyxDQUFQO0tBSEE7O2tCQUtOO2FBQVUsS0FBS0osS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtFLFdBQXhCLENBQVA7S0FMRztjQU1WQyxHQUFWLEVBQWU7YUFBVU4sWUFBY00sT0FBTyxLQUFLSyxX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
