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

    if (!Number.isInteger(id_router)) {
      throw new Error(`Invalid id_router`);
    }
    if (id_target && !Number.isInteger(id_target)) {
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

    if (!Number.isInteger(id_router)) {
      throw new Error(`Invalid id_router`);
    }
    if (id_target && !Number.isInteger(id_target)) {
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
    return array;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG4gICAgdW5wYWNrSWQsIHVucGFja191dGY4XG4gID0gcGFja2V0X2ltcGxfbWV0aG9kc1xuXG4gIGNvbnN0IHBrdF9vYmpfcHJvdG8gPSBAe31cbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGZ3ZF90byhmd2RfaWQpIDo6IHJldHVybiBhc0Z3ZFBrdE9iaiBAIHRoaXMsIGZ3ZF9pZFxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tQYWNrZXRPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNQa3RPYmosIGFzRndkUGt0T2JqXG4gICAgICBwa3Rfb2JqX3Byb3RvXG5cbiAgcGt0X29ial9wcm90by5wYWNrZXRQYXJzZXIgPSBwYWNrZXRQYXJzZXJBUElcbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldE9iaiguLi5hcmdzKSA6OlxuICAgIGNvbnN0IHBrdF9yYXcgPSBwYWNrUGFja2V0IEAgLi4uYXJnc1xuICAgIGNvbnN0IHBrdCA9IHBhcnNlSGVhZGVyIEAgcGt0X3Jhd1xuICAgIHBrdC5fcmF3XyA9IHBrdF9yYXdcbiAgICByZXR1cm4gYXNQa3RPYmoocGt0KVxuXG5cbiAgZnVuY3Rpb24gYXNQa3RPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBwYWNrZXQgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBwa3Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmpfcHJvdG8sIEB7fVxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgcGt0X29iaiwgaW5mb1xuXG4gIGZ1bmN0aW9uIGFzRndkUGt0T2JqKHBrdF9vYmosIHtpZF9yb3V0ZXIsIGlkX3RhcmdldH0pIDo6XG4gICAgaWYgbnVsbCA9PSBpZF90YXJnZXQgOjogdGhyb3cgbmV3IEVycm9yIEAgJ2lkX3RhcmdldCByZXF1aXJlZCdcbiAgICBjb25zdCByYXcgPSBmd2RIZWFkZXIgQCBwa3Rfb2JqLl9yYXdfLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIGNvbnN0IGZ3ZF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29iaiwgQHt9IF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZndkX29iai5pZF9yb3V0ZXIgPSBpZF9yb3V0ZXJcbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBmd2Rfb2JqLmlkX3RhcmdldCA9IGlkX3RhcmdldFxuICAgIGZ3ZF9vYmouaXNfZndkID0gdHJ1ZVxuICAgIHJldHVybiBmd2Rfb2JqXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBwa3QgPSBwYXJzZVRpcFBhY2tldCgpXG4gICAgICAgIGlmIHVuZGVmaW5lZCAhPT0gcGt0IDo6XG4gICAgICAgICAgY29tcGxldGUucHVzaCBAIHBrdFxuICAgICAgICBlbHNlIHJldHVybiBjb21wbGV0ZVxuXG5cbiAgICBmdW5jdGlvbiBwYXJzZVRpcFBhY2tldCgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgcGt0X29iaiA9IGFzUGt0T2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gcGt0X29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZEludDMyTEUgQCA4XG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gYnVmLnJlYWRJbnQzMkxFIEAgMTJcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID1cbiAgICAgIDEgPT09IGFyZ3MubGVuZ3RoID8gYXJnc1swXSA6IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuXG4gICAgaWYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiAhIE51bWJlci5pc0ludGVnZXIoaWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5KVxuXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBwYWNrZXRfbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgcGt0aGRyID0gQnVmZmVyLmFsbG9jIEAgcGt0X2hlYWRlcl9sZW5cbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIHNpZ25hdHVyZSwgMFxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgcGFja2V0X2xlbiwgMlxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgaGVhZGVyLmJ5dGVMZW5ndGgsIDRcbiAgICBwa3RoZHIud3JpdGVVSW50OCBAIHR5cGUgfHwgMCwgNlxuICAgIHBrdGhkci53cml0ZVVJbnQ4IEAgdHRsIHx8IGRlZmF1bHRfdHRsLCA3XG4gICAgcGt0aGRyLndyaXRlSW50MzJMRSBAIDAgfCBpZF9yb3V0ZXIsIDhcbiAgICBwa3RoZHIud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3RhcmdldCwgMTJcblxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5jb25jYXQgQCMgcGt0aGRyLCBoZWFkZXIsIGJvZHlcbiAgICBpZiBwYWNrZXRfbGVuICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBCdWZmZXIoYnVmKVxuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZCwgb2Zmc2V0fHwwXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRJbnQzMkxFIEAgb2Zmc2V0fHwwXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBCdWZmZXIoMClcblxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20gQCBidWYuYnVmZmVyIC8vIERhdGFWaWV3XG4gICAgICBlbHNlIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbSBAIGJ1ZiAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZilcbiAgICAgIHJldHVybiBCdWZmZXIuY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIEJ1ZmZlcigwKVxuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KGxzdClcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldEludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGR2LmdldEludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID1cbiAgICAgIDEgPT09IGFyZ3MubGVuZ3RoID8gYXJnc1swXSA6IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuXG4gICAgaWYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiAhIE51bWJlci5pc0ludGVnZXIoaWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdGhkciA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBwa3RoZHIsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkocGt0aGRyKVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBVaW50OEFycmF5KGJ1ZikuYnVmZmVyXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWYsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInBhY2tQYWNrZXQiLCJmd2RIZWFkZXIiLCJjb25jYXRCdWZmZXJzIiwidW5wYWNrX3V0ZjgiLCJwa3Rfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4IiwiZndkX2lkIiwiYXNGd2RQa3RPYmoiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tldFBhcnNlciIsInBhY2tQYWNrZXRPYmoiLCJhcmdzIiwicGt0X3JhdyIsInBrdCIsInBhcnNlSGVhZGVyIiwiYXNQa3RPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBrdF9vYmoiLCJ2YWx1ZSIsImlkX3JvdXRlciIsImlkX3RhcmdldCIsIkVycm9yIiwicmF3IiwiZndkX29iaiIsImlzX2Z3ZCIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcFBhY2tldCIsInVuZGVmaW5lZCIsImxlbmd0aCIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsInRvU3RyaW5nIiwidHlwZSIsInJlYWRVSW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJ3cml0ZVVJbnQ4IiwicmVhZEludDMyTEUiLCJoZWFkZXIiLCJib2R5IiwiTnVtYmVyIiwiaXNJbnRlZ2VyIiwicGt0aGRyIiwiQnVmZmVyIiwiYWxsb2MiLCJ3cml0ZVVJbnQxNkxFIiwid3JpdGVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheUJ1ZmZlciIsImlzVmlldyIsImJ1ZmZlciIsIkFycmF5IiwiaXNBcnJheSIsIm1hcCIsImxzdCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsImR2IiwiRGF0YVZpZXciLCJnZXRVaW50MTYiLCJnZXRVaW50OCIsInNldFVpbnQ4IiwiZ2V0SW50MzIiLCJzZXRVaW50MTYiLCJzZXRJbnQzMiIsInU4IiwiVWludDhBcnJheSIsInNldCIsImFycmF5IiwidGUiLCJlbmNvZGUiLCJ0ZCIsImRlY29kZSIsImFyciJdLCJtYXBwaW5ncyI6IkFBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBLEVBQ1NDLFVBRFQsRUFDcUJDLFNBRHJCO1lBQUEsRUFFTUMsYUFGTjtZQUFBLEVBR01DLFdBSE4sS0FJSkosbUJBSkY7O1FBTU1LLGdCQUFnQjtvQkFDSjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREM7Z0JBRVJDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGQTtnQkFHUkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FBeUIsSUFBdEMsQ0FBUDtLQUhBOztrQkFLTjthQUFVLEtBQUtKLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEc7Y0FNVkMsR0FBVixFQUFlO2FBQVVO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
