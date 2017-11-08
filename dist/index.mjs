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
    header_utf8() {
      return unpack_utf8(this.header_buffer());
    },
    header_json() {
      return JSON.parse(this.header_utf8() || null);
    },

    body_buffer() {
      return this._raw_.slice(this.body_offset);
    },
    body_utf8() {
      return unpack_utf8(this.body_buffer());
    },
    body_json() {
      return JSON.parse(this.body_utf8() || null);
    },

    unpackId(buf, offset = 8) {
      return unpackId(buf || this._raw_, offset);
    } };

  const packetParserAPI = Object.assign(Object.create(null), packet_impl_methods, {
    packMessageObj,
    packetStream,
    asMsgObj,
    msg_obj_proto });
  return packetParserAPI;

  function packMessageObj(...args) {
    const msg_raw = packMessage(...args);
    const msg_obj = asMsgObj(parseHeader(msg_raw));
    Object.defineProperties(msg_obj, {
      _raw_: { value: msg_raw } });
    return msg_obj;
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

  ....4........... -- uint8 ttl hops

  .....5.......... -- uint8 header type
  ......67........ -- uint8 header length

  ........89ab.... -- uint32 id_router
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id

  ............cdef -- uint32 id_target (when id_router !== 0)
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id
 */

const signature = 0xedfe;
const pkt_control_header_size = 12;
const pkt_routing_header_size = 16;
const default_ttl = 31;

function createBufferPacketParser$1(options = {}) {
  return asPacketParserAPI({
    parseHeader, packMessage,
    packId, unpackId, pack_utf8, unpack_utf8,

    asBuffer, concatBuffers });

  function parseHeader(buf, decrement_ttl) {
    const sig = buf.readUInt16LE(0);
    if (signature !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`);
    }

    // up to 64k packet length; length includes header
    const packet_len = buf.readUInt16LE(2);
    let header_len = buf.readUInt16LE(4);
    const type = buf.readUInt8(6);

    let ttl = buf.readUInt8(7);
    if (decrement_ttl) {
      ttl = Math.max(0, ttl - 1);
      buf.writeUInt8(ttl, 7);
    }

    const id_router = buf.readUInt32LE(8);
    const info = { type, ttl, id_router };

    if (0 === id_router) {
      return { info, packet_len, header_len, pkt_header_len: pkt_control_header_size };
    } else if (pkt_routing_header_size > buf.byteLength) {
      return null; // this buffer is fragmented before id_target
    } else {
        info.id_target = buf.readUInt32LE(12);
        return { info, packet_len, header_len, pkt_header_len: pkt_routing_header_size };
      }
  }

  function packMessage(...args) {
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
    header = asBuffer(header);
    body = asBuffer(body);

    const pkt_header_size = id_router ? pkt_routing_header_size : pkt_control_header_size;
    const packet_len = pkt_header_size + header.byteLength + body.byteLength;
    if (packet_len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const pkt = Buffer.alloc(pkt_header_size);
    pkt.writeUInt16LE(signature, 0);
    pkt.writeUInt16LE(packet_len, 2);
    pkt.writeUInt16LE(header.byteLength, 4);
    pkt.writeUInt8(type || 0, 6);
    pkt.writeUInt8(ttl || default_ttl, 7);
    if (!id_router) {
      pkt.writeUInt32LE(0, 8);
      if (id_target) {
        throw new Error(`Invalid id_target for control packet`);
      }
    } else {
      pkt.writeUInt32LE(id_router, 8);
      pkt.writeUInt32LE(id_target || 0, 12);
    }

    const buf = Buffer.concat([pkt, header, body]);
    if (packet_len !== buf.byteLength) {
      throw new Error(`Packed message length mismatch (library error)`);
    }
    return buf;
  }

  function packId(id, offset) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(id, offset);
    return buf;
  }
  function unpackId(buf, offset) {
    return buf.readUInt32LE(offset);
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
      if (Number.isSafeInteger(buf[0])) {
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

  ....4........... -- uint8 ttl hops

  .....5.......... -- uint8 header type
  ......67........ -- uint8 header length

  ........89ab.... -- uint32 id_router
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id

  ............cdef -- uint32 id_target (when id_router !== 0)
                      4-byte random space allows 1 million nodes with
                      0.02% chance of two nodes selecting the same id
 */

const signature$1 = 0xedfe;
const pkt_control_header_size$1 = 12;
const pkt_routing_header_size$1 = 16;
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
    const dv = new DataView(buf);

    const sig = dv.getUint16(0, little_endian);
    if (signature$1 !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature$1.toString(16)})`);
    }

    // up to 64k packet length; length includes header
    const packet_len = dv.getUint16(2, little_endian);
    let header_len = dv.getUint16(4, little_endian);
    const type = dv.getUint8(6, little_endian);

    let ttl = dv.getUint8(7, little_endian);
    if (decrement_ttl) {
      ttl = Math.max(0, ttl - 1);
      dv.setUint8(7, ttl, little_endian);
    }

    const id_router = dv.getUint32(8, little_endian);
    const info = { type, ttl, id_router };

    if (0 === id_router) {
      return { info, packet_len, header_len, pkt_header_len: pkt_control_header_size$1 };
    } else if (pkt_routing_header_size$1 > buf.byteLength) {
      return null; // this buffer is fragmented before id_target
    } else {
        info.id_target = dv.getUint32(12, little_endian);
        return { info, packet_len, header_len, pkt_header_len: pkt_routing_header_size$1 };
      }
  }

  function packMessage(...args) {
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
    header = asBuffer(header, 'header');
    body = asBuffer(body, 'body');

    const pkt_header_size = id_router ? pkt_routing_header_size$1 : pkt_control_header_size$1;
    const len = pkt_header_size + header.byteLength + body.byteLength;
    if (len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const array = new ArrayBuffer(len);

    const dv = new DataView(array, 0, pkt_header_size);
    dv.setUint16(0, signature$1, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl$1, little_endian);
    if (!id_router) {
      dv.setUint32(8, 0, little_endian);
      if (id_target) {
        throw new Error(`Invalid id_target for control packet`);
      }
    } else {
      dv.setUint32(8, id_router, little_endian);
      dv.setUint32(12, id_target || 0, little_endian);
    }

    const u8 = new Uint8Array(array);
    u8.set(new Uint8Array(header), pkt_header_size);
    u8.set(new Uint8Array(body), pkt_header_size + header.byteLength);
    return array;
  }

  function packId(id, offset) {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(offset || 0, id, little_endian);
    return buf;
  }
  function unpackId(buf, offset) {
    const dv = new DataView(asBuffer(buf));
    return dv.getUint32(offset || 0, little_endian);
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

      if ('function' === typeof buf.readUInt32LE) {
        return Uint8Array.from(buf).buffer; // NodeJS Buffer
      }return buf;
    }

    if ('string' === typeof buf) {
      return pack_utf8(buf);
    }

    if (Array.isArray(buf)) {
      if (Number.isSafeInteger(buf[0])) {
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXJcbiAgICBwYWNrTWVzc2FnZVxuICAgIGFzQnVmZmVyXG4gICAgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBtc2dfb2JqX3Byb3RvID0gQDpcbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOCgpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIHRoaXMuaGVhZGVyX2J1ZmZlcigpXG4gICAgaGVhZGVyX2pzb24oKSA6OiByZXR1cm4gSlNPTi5wYXJzZSBAIHRoaXMuaGVhZGVyX3V0ZjgoKSB8fCBudWxsXG5cbiAgICBib2R5X2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5ib2R5X29mZnNldFxuICAgIGJvZHlfdXRmOCgpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbigpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoKSB8fCBudWxsXG5cbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcblxuICBjb25zdCBwYWNrZXRQYXJzZXJBUEkgPSBPYmplY3QuYXNzaWduIEBcbiAgICBPYmplY3QuY3JlYXRlKG51bGwpXG4gICAgcGFja2V0X2ltcGxfbWV0aG9kc1xuICAgIEB7fVxuICAgICAgcGFja01lc3NhZ2VPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNNc2dPYmpcbiAgICAgIG1zZ19vYmpfcHJvdG9cbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2VPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBtc2dfcmF3ID0gcGFja01lc3NhZ2UgQCAuLi5hcmdzXG4gICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqIEAgcGFyc2VIZWFkZXIgQCBtc2dfcmF3XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnRpZXMgQCBtc2dfb2JqLCBAOlxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogbXNnX3Jhd1xuICAgIHJldHVybiBtc2dfb2JqXG5cblxuICBmdW5jdGlvbiBhc01zZ09iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIG1lc3NhZ2UgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBtc2dfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIG1zZ19vYmpfcHJvdG8sIEA6XG4gICAgICBoZWFkZXJfb2Zmc2V0OiBAe30gdmFsdWU6IHBrdF9oZWFkZXJfbGVuXG4gICAgICBib2R5X29mZnNldDogQHt9IHZhbHVlOiBib2R5X29mZnNldFxuICAgICAgcGFja2V0X2xlbjogQHt9IHZhbHVlOiBwYWNrZXRfbGVuXG4gICAgICBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuXG4gICAgcmV0dXJuIE9iamVjdC5hc3NpZ24gQCBtc2dfb2JqLCBpbmZvXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBtc2cgPSBwYXJzZVRpcE1lc3NhZ2UoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IG1zZyA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBtc2dcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBNZXNzYWdlKCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBtc2dfb2JqID0gYXNNc2dPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBtc2dfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG5cbiAgLi4uLjQuLi4uLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uNS4uLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uNjcuLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgbGVuZ3RoXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSB1aW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gdWludDMyIGlkX3RhcmdldCAod2hlbiBpZF9yb3V0ZXIgIT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9jb250cm9sX2hlYWRlcl9zaXplID0gMTJcbmNvbnN0IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgY29uc3Qgc2lnID0gYnVmLnJlYWRVSW50MTZMRSBAIDBcbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDJcbiAgICBsZXQgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZFVJbnQzMkxFIEAgOFxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXJcblxuICAgIGlmIDAgPT09IGlkX3JvdXRlciA6OlxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGVsc2UgaWYgcGt0X3JvdXRpbmdfaGVhZGVyX3NpemUgPiBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIG51bGwgLy8gdGhpcyBidWZmZXIgaXMgZnJhZ21lbnRlZCBiZWZvcmUgaWRfdGFyZ2V0XG4gICAgZWxzZSA6OlxuICAgICAgaW5mby5pZF90YXJnZXQgPSBidWYucmVhZFVJbnQzMkxFIEAgMTJcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5KVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgcGFja2V0X2xlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdCA9IEJ1ZmZlci5hbGxvYyBAIHBrdF9oZWFkZXJfc2l6ZVxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0LndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBpZiAhIGlkX3JvdXRlciA6OlxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCAwLCA4XG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBwa3Qud3JpdGVVSW50MzJMRSBAIGlkX3JvdXRlciwgOFxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCBpZF90YXJnZXQgfHwgMCwgMTJcblxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5jb25jYXQgQCMgcGt0LCBoZWFkZXIsIGJvZHlcbiAgICBpZiBwYWNrZXRfbGVuICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tlZCBtZXNzYWdlIGxlbmd0aCBtaXNtYXRjaCAobGlicmFyeSBlcnJvcilgXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlVUludDMyTEUoaWQsIG9mZnNldClcbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIHJldHVybiBidWYucmVhZFVJbnQzMkxFKG9mZnNldClcblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIHJldHVybiBCdWZmZXIuZnJvbShzdHIsICd1dGYtOCcpXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICByZXR1cm4gYXNCdWZmZXIoYnVmKS50b1N0cmluZygndXRmLTgnKVxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlcigwKVxuXG4gICAgaWYgQnVmZmVyLmlzQnVmZmVyKGJ1ZikgOjpcbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpIC8vIFR5cGVkQXJyYXkgb3IgQXJyYXlCdWZmZXJcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzU2FmZUludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZilcbiAgICAgIHJldHVybiBCdWZmZXIuY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIEJ1ZmZlcigwKVxuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KGxzdClcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcblxuICAuLi4uNC4uLi4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi41Li4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi42Ny4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciBsZW5ndGhcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIHVpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSB1aW50MzIgaWRfdGFyZ2V0ICh3aGVuIGlkX3JvdXRlciAhPT0gMClcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2NvbnRyb2xfaGVhZGVyX3NpemUgPSAxMlxuY29uc3QgcGt0X3JvdXRpbmdfaGVhZGVyX3NpemUgPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5jb25zdCBsaXR0bGVfZW5kaWFuID0gdHJ1ZVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICBjb25zdCBfVGV4dEVuY29kZXJfID0gb3B0aW9ucy5UZXh0RW5jb2RlciB8fCBUZXh0RW5jb2RlclxuICBjb25zdCBfVGV4dERlY29kZXJfID0gb3B0aW9ucy5UZXh0RGVjb2RlciB8fCBUZXh0RGVjb2RlclxuXG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGxldCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRVaW50MzIgQCA4LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlclxuXG4gICAgaWYgMCA9PT0gaWRfcm91dGVyIDo6XG4gICAgICByZXR1cm4gQDogaW5mbywgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgcGt0X2hlYWRlcl9sZW46IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgZWxzZSBpZiBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA+IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICByZXR1cm4gbnVsbCAvLyB0aGlzIGJ1ZmZlciBpcyBmcmFnbWVudGVkIGJlZm9yZSBpZF90YXJnZXRcbiAgICBlbHNlIDo6XG4gICAgICBpbmZvLmlkX3RhcmdldCA9IGR2LmdldFVpbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgICByZXR1cm4gQDogaW5mbywgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgcGt0X2hlYWRlcl9sZW46IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IHBrdF9oZWFkZXJfc2l6ZSA9IGlkX3JvdXRlclxuICAgICAgPyBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZVxuICAgICAgOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgYXJyYXkgPSBuZXcgQXJyYXlCdWZmZXIobGVuKVxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhcnJheSwgMCwgcGt0X2hlYWRlcl9zaXplXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGlmICEgaWRfcm91dGVyIDo6XG4gICAgICBkdi5zZXRVaW50MzIgQCAgOCwgMCwgbGl0dGxlX2VuZGlhblxuICAgICAgaWYgaWRfdGFyZ2V0IDo6XG4gICAgICAgIHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldCBmb3IgY29udHJvbCBwYWNrZXRgXG4gICAgZWxzZSA6OlxuICAgICAgZHYuc2V0VWludDMyIEAgIDgsIGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgICAgZHYuc2V0VWludDMyIEAgMTIsIGlkX3RhcmdldCB8fCAwLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGFycmF5KVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfc2l6ZVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGJvZHkpLCBwa3RfaGVhZGVyX3NpemUgKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBhcnJheVxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0VWludDMyIEAgb2Zmc2V0fHwwLCBpZCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhc0J1ZmZlcihidWYpXG4gICAgcmV0dXJuIGR2LmdldFVpbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkVUludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzU2FmZUludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwidW5wYWNrX3V0ZjgiLCJtc2dfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4IiwiYnVmIiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrTWVzc2FnZU9iaiIsImFyZ3MiLCJtc2dfcmF3IiwicGFja01lc3NhZ2UiLCJtc2dfb2JqIiwiYXNNc2dPYmoiLCJwYXJzZUhlYWRlciIsImRlZmluZVByb3BlcnRpZXMiLCJ2YWx1ZSIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsIm1zZyIsInBhcnNlVGlwTWVzc2FnZSIsInVuZGVmaW5lZCIsImxlbmd0aCIsImNvbmNhdEJ1ZmZlcnMiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwicGt0X2NvbnRyb2xfaGVhZGVyX3NpemUiLCJwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSIsImRlZmF1bHRfdHRsIiwiY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIiwicGFja191dGY4Iiwic2lnIiwicmVhZFVJbnQxNkxFIiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsImlkX3JvdXRlciIsInJlYWRVSW50MzJMRSIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJwa3RfaGVhZGVyX3NpemUiLCJwa3QiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZVVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJOdW1iZXIiLCJpc1NhZmVJbnRlZ2VyIiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRVaW50MzIiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0VWludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJidWZmZXIiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsImFyciJdLCJtYXBwaW5ncyI6IkFBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFBQTtpQkFBQTtZQUFBLEVBS01DLFdBTE4sS0FNSkQsbUJBTkY7O1FBUU1FLGdCQUFr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
