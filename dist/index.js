'use strict';

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

function createBufferPacketParser(options = {}) {
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

function createPacketParser(...args) {
  return createBufferPacketParser(...args);
}

Object.assign(createPacketParser, {
  asPacketParserAPI,
  createBufferPacketParser,
  createDataViewPacketParser });

module.exports = createPacketParser;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQHt9XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICBmd2RfdG8oZndkX2lkKSA6OiByZXR1cm4gYXNGd2RQa3RPYmogQCB0aGlzLCBmd2RfaWRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrUGFja2V0T2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzUGt0T2JqLCBhc0Z3ZFBrdE9ialxuICAgICAgcGt0X29ial9wcm90b1xuXG4gIHBrdF9vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXRPYmoocGt0X2luZm8pIDo6XG4gICAgY29uc3QgcGt0X3JhdyA9IHBhY2tQYWNrZXQgQCBwa3RfaW5mb1xuICAgIGNvbnN0IHBrdCA9IHBhcnNlSGVhZGVyIEAgcGt0X3Jhd1xuICAgIHBrdC5fcmF3XyA9IHBrdF9yYXdcbiAgICByZXR1cm4gYXNQa3RPYmoocGt0KVxuXG5cbiAgZnVuY3Rpb24gYXNQa3RPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBwYWNrZXQgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBwa3Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmpfcHJvdG8sIEB7fVxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgcGt0X29iaiwgaW5mb1xuXG4gIGZ1bmN0aW9uIGFzRndkUGt0T2JqKHBrdF9vYmosIHtpZF9yb3V0ZXIsIGlkX3RhcmdldH0pIDo6XG4gICAgaWYgbnVsbCA9PSBpZF90YXJnZXQgOjogdGhyb3cgbmV3IEVycm9yIEAgJ2lkX3RhcmdldCByZXF1aXJlZCdcbiAgICBjb25zdCByYXcgPSBmd2RIZWFkZXIgQCBwa3Rfb2JqLl9yYXdfLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIGNvbnN0IGZ3ZF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29iaiwgQHt9IF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZndkX29iai5pZF9yb3V0ZXIgPSBpZF9yb3V0ZXJcbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBmd2Rfb2JqLmlkX3RhcmdldCA9IGlkX3RhcmdldFxuICAgIGZ3ZF9vYmouaXNfZndkID0gdHJ1ZVxuICAgIHJldHVybiBmd2Rfb2JqXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBwa3QgPSBwYXJzZVRpcFBhY2tldCgpXG4gICAgICAgIGlmIHVuZGVmaW5lZCAhPT0gcGt0IDo6XG4gICAgICAgICAgY29tcGxldGUucHVzaCBAIHBrdFxuICAgICAgICBlbHNlIHJldHVybiBjb21wbGV0ZVxuXG5cbiAgICBmdW5jdGlvbiBwYXJzZVRpcFBhY2tldCgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgcGt0X29iaiA9IGFzUGt0T2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gcGt0X29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZEludDMyTEUgQCA4XG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gYnVmLnJlYWRJbnQzMkxFIEAgMTJcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KHBrdF9pbmZvKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IHBrdF9pbmZvXG5cbiAgICBpZiBOdW1iZXIuaXNOYU4oK2lkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiBOdW1iZXIuaXNOYU4oK2lkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlcilcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSlcblxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgcGFja2V0X2xlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdGhkciA9IEJ1ZmZlci5hbGxvYyBAIHBrdF9oZWFkZXJfbGVuXG4gICAgcGt0aGRyLndyaXRlVUludDE2TEUgQCBzaWduYXR1cmUsIDBcbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIHBhY2tldF9sZW4sIDJcbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIGhlYWRlci5ieXRlTGVuZ3RoLCA0XG4gICAgcGt0aGRyLndyaXRlVUludDggQCB0eXBlIHx8IDAsIDZcbiAgICBwa3RoZHIud3JpdGVVSW50OCBAIHR0bCB8fCBkZWZhdWx0X3R0bCwgN1xuICAgIHBrdGhkci53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgcGt0aGRyLndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG5cbiAgICBjb25zdCBidWYgPSBCdWZmZXIuY29uY2F0IEAjIHBrdGhkciwgaGVhZGVyLCBib2R5XG4gICAgaWYgcGFja2V0X2xlbiAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgbGVuZ3RoIG1pc21hdGNoIChsaWJyYXJ5IGVycm9yKWBcbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBmd2RIZWFkZXIoYnVmLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCkgOjpcbiAgICBidWYgPSBuZXcgQnVmZmVyKGJ1ZilcbiAgICBpZiBudWxsICE9IGlkX3JvdXRlciA6OiBidWYud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIGlmIG51bGwgIT0gaWRfdGFyZ2V0IDo6IGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5hbGxvYyg0KVxuICAgIGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWQsIG9mZnNldHx8MFxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgcmV0dXJuIGJ1Zi5yZWFkSW50MzJMRSBAIG9mZnNldHx8MFxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgcmV0dXJuIEJ1ZmZlci5mcm9tKHN0ciwgJ3V0Zi04JylcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIHJldHVybiBhc0J1ZmZlcihidWYpLnRvU3RyaW5nKCd1dGYtOCcpXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gQnVmZmVyKDApXG5cbiAgICBpZiBCdWZmZXIuaXNCdWZmZXIoYnVmKSA6OlxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tIEAgYnVmLmJ1ZmZlciAvLyBEYXRhVmlld1xuICAgICAgZWxzZSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20gQCBidWYgLy8gVHlwZWRBcnJheSBvciBBcnJheUJ1ZmZlclxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpXG4gICAgICByZXR1cm4gQnVmZmVyLmNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBCdWZmZXIoMClcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChsc3QpXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5jb25zdCBsaXR0bGVfZW5kaWFuID0gdHJ1ZVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICBjb25zdCBfVGV4dEVuY29kZXJfID0gb3B0aW9ucy5UZXh0RW5jb2RlciB8fCBUZXh0RW5jb2RlclxuICBjb25zdCBfVGV4dERlY29kZXJfID0gb3B0aW9ucy5UZXh0RGVjb2RlciB8fCBUZXh0RGVjb2RlclxuXG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRJbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpZF90YXJnZXQgPSBkdi5nZXRJbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEB7fSBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldChwa3RfaW5mbykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBwa3RfaW5mb1xuXG4gICAgaWYgTnVtYmVyLmlzTmFOKCtpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgTnVtYmVyLmlzTmFOKCtpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIsICdoZWFkZXInKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5LCAnYm9keScpXG5cbiAgICBjb25zdCBsZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgcGt0aGRyID0gbmV3IEFycmF5QnVmZmVyKGxlbilcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIHBrdGhkciwgMCwgcGt0X2hlYWRlcl9sZW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShwa3RoZHIpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9sZW5cbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBwa3RoZHJcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBVaW50OEFycmF5KGJ1ZikuYnVmZmVyXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWYsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIiwiaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5pbXBvcnQgY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIGZyb20gJy4vYnVmZmVyJ1xuaW1wb3J0IGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIGZyb20gJy4vZGF0YXZpZXcnXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZVBhY2tldFBhcnNlciguLi5hcmdzKSA6OlxuICByZXR1cm4gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKC4uLmFyZ3MpXG5cbk9iamVjdC5hc3NpZ24gQCBjcmVhdGVQYWNrZXRQYXJzZXIsIEB7fVxuICBhc1BhY2tldFBhcnNlckFQSVxuICBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXJcbiAgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInBhY2tQYWNrZXQiLCJmd2RIZWFkZXIiLCJjb25jYXRCdWZmZXJzIiwidW5wYWNrX3V0ZjgiLCJwa3Rfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4IiwiZndkX2lkIiwiYXNGd2RQa3RPYmoiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tldFBhcnNlciIsInBhY2tQYWNrZXRPYmoiLCJwa3RfaW5mbyIsInBrdF9yYXciLCJwa3QiLCJwYXJzZUhlYWRlciIsImFzUGt0T2JqIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJwa3Rfb2JqIiwidmFsdWUiLCJpZF9yb3V0ZXIiLCJpZF90YXJnZXQiLCJFcnJvciIsInJhdyIsImZ3ZF9vYmoiLCJpc19md2QiLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwicGFyc2VUaXBQYWNrZXQiLCJ1bmRlZmluZWQiLCJsZW5ndGgiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwiZGVmYXVsdF90dGwiLCJjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIiLCJwYWNrX3V0ZjgiLCJzaWciLCJyZWFkVUludDE2TEUiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsInJlYWRJbnQzMkxFIiwiaGVhZGVyIiwiYm9keSIsIk51bWJlciIsImlzTmFOIiwicGt0aGRyIiwiQnVmZmVyIiwiYWxsb2MiLCJ3cml0ZVVJbnQxNkxFIiwid3JpdGVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheUJ1ZmZlciIsImlzVmlldyIsImJ1ZmZlciIsIkFycmF5IiwiaXNBcnJheSIsImlzSW50ZWdlciIsIm1hcCIsImxzdCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsImR2IiwiRGF0YVZpZXciLCJnZXRVaW50MTYiLCJnZXRVaW50OCIsInNldFVpbnQ4IiwiZ2V0SW50MzIiLCJzZXRVaW50MTYiLCJzZXRJbnQzMiIsInU4IiwiVWludDhBcnJheSIsInNldCIsInRlIiwiZW5jb2RlIiwidGQiLCJkZWNvZGUiLCJhcnIiLCJjcmVhdGVQYWNrZXRQYXJzZXIiLCJhcmdzIl0sIm1hcHBpbmdzIjoiOztBQUNlLFNBQVNBLGlCQUFULENBQTJCQyxtQkFBM0IsRUFBZ0Q7UUFDdkQ7ZUFBQSxFQUNTQyxVQURULEVBQ3FCQyxTQURyQjtZQUFBLEVBRU1DLGFBRk47WUFBQSxFQUdNQyxXQUhOLEtBSUpKLG1CQUpGOztRQU1NSyxnQkFBZ0I7b0JBQ0o7YUFB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
