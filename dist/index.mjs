function asPacketParserAPI(packet_impl_methods) {
  const {
    parseHeader,
    packMessage,
    asBuffer,
    concatBuffers,
    unpackId, unpack_utf8 } = packet_impl_methods;

  const msg_obj_proto = {
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
    packMessageObj,
    packetStream,
    asMsgObj,
    msg_obj_proto });

  msg_obj_proto.packetParser = packetParserAPI;
  return packetParserAPI;

  function packMessageObj(...args) {
    const msg_raw = packMessage(...args);
    const msg = parseHeader(msg_raw);
    msg._raw_ = msg_raw;
    return asMsgObj(msg);
  }

  function asMsgObj({ info, pkt_header_len, packet_len, header_len, _raw_ }) {
    let body_offset = pkt_header_len + header_len;
    if (body_offset > packet_len) {
      body_offset = null; // invalid message construction
    }const msg_obj = Object.create(msg_obj_proto, {
      header_offset: { value: pkt_header_len },
      body_offset: { value: body_offset },
      packet_len: { value: packet_len },
      _raw_: { value: _raw_ } });

    return Object.assign(msg_obj, info);
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
        const msg = parseTipMessage();
        if (undefined !== msg) {
          complete.push(msg);
        } else return complete;
      }
    }

    function parseTipMessage() {
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
        const msg_obj = asMsgObj(tip);
        tip = null;
        return msg_obj;
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
    parseHeader, packMessage,
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

  function packMessage(...args) {
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
      throw new Error(`Packed message length mismatch (library error)`);
    }
    return buf;
  }

  function packId(id, offset) {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(id, offset);
    return buf;
  }
  function unpackId(buf, offset) {
    return buf.readInt32LE(offset);
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
    parseHeader, packMessage,
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

  function packMessage(...args) {
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
    new DataView(buf).setInt32(offset || 0, id, little_endian);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXJcbiAgICBwYWNrTWVzc2FnZVxuICAgIGFzQnVmZmVyXG4gICAgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBtc2dfb2JqX3Byb3RvID0gQDpcbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG5cbiAgbXNnX29ial9wcm90by5wYWNrZXRQYXJzZXIgPSBwYWNrZXRQYXJzZXJBUElcbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2VPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBtc2dfcmF3ID0gcGFja01lc3NhZ2UgQCAuLi5hcmdzXG4gICAgY29uc3QgbXNnID0gcGFyc2VIZWFkZXIgQCBtc2dfcmF3XG4gICAgbXNnLl9yYXdfID0gbXNnX3Jhd1xuICAgIHJldHVybiBhc01zZ09iaihtc2cpXG5cblxuICBmdW5jdGlvbiBhc01zZ09iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIG1lc3NhZ2UgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBtc2dfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIG1zZ19vYmpfcHJvdG8sIEA6XG4gICAgICBoZWFkZXJfb2Zmc2V0OiBAe30gdmFsdWU6IHBrdF9oZWFkZXJfbGVuXG4gICAgICBib2R5X29mZnNldDogQHt9IHZhbHVlOiBib2R5X29mZnNldFxuICAgICAgcGFja2V0X2xlbjogQHt9IHZhbHVlOiBwYWNrZXRfbGVuXG4gICAgICBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuXG4gICAgcmV0dXJuIE9iamVjdC5hc3NpZ24gQCBtc2dfb2JqLCBpbmZvXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBtc2cgPSBwYXJzZVRpcE1lc3NhZ2UoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IG1zZyA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBtc2dcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBNZXNzYWdlKCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBtc2dfb2JqID0gYXNNc2dPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBtc2dfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBzaWcgPSBidWYucmVhZFVJbnQxNkxFIEAgMFxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgMlxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgNFxuICAgIGNvbnN0IHR5cGUgPSBidWYucmVhZFVJbnQ4IEAgNlxuXG4gICAgbGV0IHR0bCA9IGJ1Zi5yZWFkVUludDggQCA3XG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBidWYud3JpdGVVSW50OCBAIHR0bCwgN1xuXG4gICAgY29uc3QgaWRfcm91dGVyID0gYnVmLnJlYWRJbnQzMkxFIEAgOFxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGJ1Zi5yZWFkSW50MzJMRSBAIDEyXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEA6IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlcilcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSlcblxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgcGFja2V0X2xlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdCA9IEJ1ZmZlci5hbGxvYyBAIHBrdF9oZWFkZXJfbGVuXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBzaWduYXR1cmUsIDBcbiAgICBwa3Qud3JpdGVVSW50MTZMRSBAIHBhY2tldF9sZW4sIDJcbiAgICBwa3Qud3JpdGVVSW50MTZMRSBAIGhlYWRlci5ieXRlTGVuZ3RoLCA0XG4gICAgcGt0LndyaXRlVUludDggQCB0eXBlIHx8IDAsIDZcbiAgICBwa3Qud3JpdGVVSW50OCBAIHR0bCB8fCBkZWZhdWx0X3R0bCwgN1xuICAgIHBrdC53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgcGt0LndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG5cbiAgICBjb25zdCBidWYgPSBCdWZmZXIuY29uY2F0IEAjIHBrdCwgaGVhZGVyLCBib2R5XG4gICAgaWYgcGFja2V0X2xlbiAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZWQgbWVzc2FnZSBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5hbGxvYyg0KVxuICAgIGJ1Zi53cml0ZUludDMyTEUoaWQsIG9mZnNldClcbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIHJldHVybiBidWYucmVhZEludDMyTEUob2Zmc2V0KVxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgcmV0dXJuIEJ1ZmZlci5mcm9tKHN0ciwgJ3V0Zi04JylcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIHJldHVybiBhc0J1ZmZlcihidWYpLnRvU3RyaW5nKCd1dGYtOCcpXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gQnVmZmVyKDApXG5cbiAgICBpZiBCdWZmZXIuaXNCdWZmZXIoYnVmKSA6OlxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZikgLy8gVHlwZWRBcnJheSBvciBBcnJheUJ1ZmZlclxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpXG4gICAgICByZXR1cm4gQnVmZmVyLmNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBCdWZmZXIoMClcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChsc3QpXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5jb25zdCBsaXR0bGVfZW5kaWFuID0gdHJ1ZVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICBjb25zdCBfVGV4dEVuY29kZXJfID0gb3B0aW9ucy5UZXh0RW5jb2RlciB8fCBUZXh0RW5jb2RlclxuICBjb25zdCBfVGV4dERlY29kZXJfID0gb3B0aW9ucy5UZXh0RGVjb2RlciB8fCBUZXh0RGVjb2RlclxuXG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldEludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGR2LmdldEludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQDogaW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW5cblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaWYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiAhIE51bWJlci5pc0ludGVnZXIoaWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IGFycmF5ID0gbmV3IEFycmF5QnVmZmVyKGxlbilcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXJyYXksIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9sZW5cbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBhcnJheVxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0SW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0SW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIHVuZGVmaW5lZCA9PT0gYnVmLmJ1ZmZlciA6OlxuICAgICAgICByZXR1cm4gYnVmXG5cbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBidWYuYnVmZmVyXG5cbiAgICAgIGlmICdmdW5jdGlvbicgPT09IHR5cGVvZiBidWYucmVhZEludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJ1bnBhY2tfdXRmOCIsIm1zZ19vYmpfcHJvdG8iLCJfcmF3XyIsInNsaWNlIiwiaGVhZGVyX29mZnNldCIsImJvZHlfb2Zmc2V0IiwiYnVmIiwiaGVhZGVyX2J1ZmZlciIsIkpTT04iLCJwYXJzZSIsImhlYWRlcl91dGY4IiwiYm9keV9idWZmZXIiLCJib2R5X3V0ZjgiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tldFBhcnNlciIsInBhY2tNZXNzYWdlT2JqIiwiYXJncyIsIm1zZ19yYXciLCJwYWNrTWVzc2FnZSIsIm1zZyIsInBhcnNlSGVhZGVyIiwiYXNNc2dPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsIm1zZ19vYmoiLCJ2YWx1ZSIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcE1lc3NhZ2UiLCJ1bmRlZmluZWQiLCJsZW5ndGgiLCJjb25jYXRCdWZmZXJzIiwibGVuIiwiYnl0ZXMiLCJuIiwidHJhaWxpbmdCeXRlcyIsInBhcnRzIiwic3BsaWNlIiwidGFpbCIsInNpZ25hdHVyZSIsImRlZmF1bHRfdHRsIiwiY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIiwicGFja191dGY4Iiwic2lnIiwicmVhZFVJbnQxNkxFIiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsImlkX3JvdXRlciIsInJlYWRJbnQzMkxFIiwiaWRfdGFyZ2V0IiwiaGVhZGVyIiwiYm9keSIsIk51bWJlciIsImlzSW50ZWdlciIsInBrdCIsIkJ1ZmZlciIsImFsbG9jIiwid3JpdGVVSW50MTZMRSIsIndyaXRlSW50MzJMRSIsImNvbmNhdCIsInBhY2tJZCIsImlkIiwic3RyIiwiZnJvbSIsImlzQnVmZmVyIiwiQXJyYXkiLCJpc0FycmF5IiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRJbnQzMiIsImFycmF5IiwiQXJyYXlCdWZmZXIiLCJzZXRVaW50MTYiLCJzZXRJbnQzMiIsInU4IiwiVWludDhBcnJheSIsInNldCIsInRlIiwiZW5jb2RlIiwiYnVmZmVyIiwidGQiLCJkZWNvZGUiLCJpc1ZpZXciLCJhcnIiXSwibWFw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
