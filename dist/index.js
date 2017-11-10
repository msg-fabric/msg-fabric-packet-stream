'use strict';

function asPacketParserAPI(packet_impl_methods) {
  const {
    parseHeader,
    packPacket,
    asBuffer,
    concatBuffers,
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
    asPktObj,
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
    parseHeader, packPacket,
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
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
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

    const pkt = Buffer.alloc(pkt_header_len);
    pkt.writeUInt16LE(signature, 0);
    pkt.writeUInt16LE(packet_len, 2);
    pkt.writeUInt16LE(header.byteLength, 4);
    pkt.writeUInt8(type || 0, 6);
    pkt.writeUInt8(ttl || default_ttl, 7);
    pkt.writeInt32LE(0 | id_router, 8);
    pkt.writeInt32LE(0 | id_target, 12);

    const buf = Buffer.concat([pkt, header, body]);
    if (packet_len !== buf.byteLength) {
      throw new Error(`Packet length mismatch (library error)`);
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
      return Buffer.from(buf); // TypedArray or ArrayBuffer
    }if (Array.isArray(buf)) {
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
    parseHeader, packPacket,
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
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
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

    const array = new ArrayBuffer(len);

    const dv = new DataView(array, 0, pkt_header_len$1);
    dv.setUint16(0, signature$1, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl$1, little_endian);
    dv.setInt32(8, 0 | id_router, little_endian);
    dv.setInt32(12, 0 | id_target, little_endian);

    const u8 = new Uint8Array(array);
    u8.set(new Uint8Array(header), pkt_header_len$1);
    u8.set(new Uint8Array(body), pkt_header_len$1 + header.byteLength);
    return array;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja1BhY2tldFxuICAgIGFzQnVmZmVyXG4gICAgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQDpcbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tQYWNrZXRPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNQa3RPYmpcbiAgICAgIHBrdF9vYmpfcHJvdG9cblxuICBwa3Rfb2JqX3Byb3RvLnBhY2tldFBhcnNlciA9IHBhY2tldFBhcnNlckFQSVxuICByZXR1cm4gcGFja2V0UGFyc2VyQVBJXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0T2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgcGt0X3JhdyA9IHBhY2tQYWNrZXQgQCAuLi5hcmdzXG4gICAgY29uc3QgcGt0ID0gcGFyc2VIZWFkZXIgQCBwa3RfcmF3XG4gICAgcGt0Ll9yYXdfID0gcGt0X3Jhd1xuICAgIHJldHVybiBhc1BrdE9iaihwa3QpXG5cblxuICBmdW5jdGlvbiBhc1BrdE9iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIHBhY2tldCBjb25zdHJ1Y3Rpb25cblxuICAgIGNvbnN0IHBrdF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29ial9wcm90bywgQDpcbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIHBrdF9vYmosIGluZm9cblxuXG4gIGZ1bmN0aW9uIHBhY2tldFN0cmVhbShvcHRpb25zKSA6OlxuICAgIGlmICEgb3B0aW9ucyA6OiBvcHRpb25zID0ge31cblxuICAgIGNvbnN0IGRlY3JlbWVudF90dGwgPVxuICAgICAgbnVsbCA9PSBvcHRpb25zLmRlY3JlbWVudF90dGxcbiAgICAgICAgPyB0cnVlIDogISEgb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG5cbiAgICBsZXQgdGlwPW51bGwsIHFCeXRlTGVuID0gMCwgcSA9IFtdXG4gICAgcmV0dXJuIGZlZWRcblxuICAgIGZ1bmN0aW9uIGZlZWQoZGF0YSwgY29tcGxldGU9W10pIDo6XG4gICAgICBkYXRhID0gYXNCdWZmZXIoZGF0YSlcbiAgICAgIHEucHVzaCBAIGRhdGFcbiAgICAgIHFCeXRlTGVuICs9IGRhdGEuYnl0ZUxlbmd0aFxuXG4gICAgICB3aGlsZSAxIDo6XG4gICAgICAgIGNvbnN0IHBrdCA9IHBhcnNlVGlwUGFja2V0KClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBwa3QgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgcGt0XG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwUGFja2V0KCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBwa3Rfb2JqID0gYXNQa3RPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBwa3Rfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXRcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZEludDMyTEUgQCA4XG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gYnVmLnJlYWRJbnQzMkxFIEAgMTJcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQDogaW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW5cblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXQoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBpZiAhIE51bWJlci5pc0ludGVnZXIoaWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmICEgTnVtYmVyLmlzSW50ZWdlcihpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHkpXG5cbiAgICBjb25zdCBwYWNrZXRfbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3QgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX2xlblxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0LndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBwa3Qud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIHBrdC53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuXG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmNvbmNhdCBAIyBwa3QsIGhlYWRlciwgYm9keVxuICAgIGlmIHBhY2tldF9sZW4gIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IGxlbmd0aCBtaXNtYXRjaCAobGlicmFyeSBlcnJvcilgXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZCwgb2Zmc2V0fHwwXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRJbnQzMkxFIEAgb2Zmc2V0fHwwXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBCdWZmZXIoMClcblxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKSAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZilcbiAgICAgIHJldHVybiBCdWZmZXIuY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIEJ1ZmZlcigwKVxuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KGxzdClcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXRcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRJbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpZF90YXJnZXQgPSBkdi5nZXRJbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEA6IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaWYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiAhIE51bWJlci5pc0ludGVnZXIoaWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IGFycmF5ID0gbmV3IEFycmF5QnVmZmVyKGxlbilcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXJyYXksIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9sZW5cbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBhcnJheVxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0SW50MzIgQCBvZmZzZXR8fDAsIDAgfCBpZCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhc0J1ZmZlcihidWYpXG4gICAgcmV0dXJuIGR2LmdldEludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRJbnQzMkxFIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXIgLy8gTm9kZUpTIEJ1ZmZlclxuXG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iLCJpbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcbmltcG9ydCBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIgZnJvbSAnLi9idWZmZXInXG5pbXBvcnQgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIgZnJvbSAnLi9kYXRhdmlldydcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlUGFja2V0UGFyc2VyKC4uLmFyZ3MpIDo6XG4gIHJldHVybiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIoLi4uYXJncylcblxuT2JqZWN0LmFzc2lnbiBAIGNyZWF0ZVBhY2tldFBhcnNlciwgQHt9XG4gIGFzUGFja2V0UGFyc2VyQVBJXG4gIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlclxuICBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwidW5wYWNrX3V0ZjgiLCJwa3Rfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4Iiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrZXRQYXJzZXIiLCJwYWNrUGFja2V0T2JqIiwiYXJncyIsInBrdF9yYXciLCJwYWNrUGFja2V0IiwicGt0IiwicGFyc2VIZWFkZXIiLCJhc1BrdE9iaiIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwicGt0X29iaiIsInZhbHVlIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsInBhcnNlVGlwUGFja2V0IiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsIkVycm9yIiwidG9TdHJpbmciLCJ0eXBlIiwicmVhZFVJbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsIndyaXRlVUludDgiLCJpZF9yb3V0ZXIiLCJyZWFkSW50MzJMRSIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJOdW1iZXIiLCJpc0ludGVnZXIiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZUludDMyTEUiLCJjb25jYXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsImZyb20iLCJpc0J1ZmZlciIsIkFycmF5IiwiaXNBcnJheSIsIm1hcCIsImxzdCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsImR2IiwiRGF0YVZpZXciLCJnZXRVaW50MTYiLCJnZXRVaW50OCIsInNldFVpbnQ4IiwiZ2V0SW50MzIiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0SW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJ0ZSIsImVuY29kZSIsImJ1ZmZlciIsInRkIiwiZGVjb2RlIiwiaXNWaWV3IiwiYXJyIiwiY3JlYXRlUGFja2V0UGFyc2VyIl0sIm1hcHBpbmdzIjoiOztBQUNlLFNBQVNBLGlCQUFULENBQTJCQyxtQkFBM0IsRUFBZ0Q7UUFDdkQ7ZUFBQTtjQUFBO1lBQUE7aUJBQUE7WUFBQSxFQUtNQyxXQUxOLEtBTUpELG1CQU5GOztRQVFNRSxnQkFBa0I7b0JBQ047YUFBVSxLQUFLQyxLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0MsYUFBeEIsRUFBdUMsS0FBS0MsV0FBNUMsQ0FBUDtLQURHO2dCQUVWQyxHQUFaLEVBQWlCO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0MsYUFBTCxFQUFyQixDQUFQO0tBRkU7Z0JBR1ZELEdBQVosRUFBaUI7YUFBVUUsS0FBS0MsS0FBTCxDQUFhLEtBQUtDLFdBQUwsQ0FBaUJKLEdBQWpCLEtBQXlCLElBQXRDLENBQVA7S0FIRTs7a0JBS1I7YUFBVSxLQUFLSixLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0UsV0FBeEIsQ0FBUDtLQUxLO2NBTVpDLEdBQVYsRUFBZTthQUFVTixZQUFjTSxPQUFPLEtBQUtLLFdBQUwsRUFBckIsQ0FBUDtLQU5JO2NBT1pMLEdBQVYsRUFBZTthQUFVRSxLQUFLQyxLQUFM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
