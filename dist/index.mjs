function asPacketParserAPI(packet_impl_methods) {
  const {
    parseHeader,
    packMessage,
    asBuffer,
    concatBuffers,
    unpackId } = packet_impl_methods;

  const msg_obj_proto = {
    sliceBody() {
      return this._raw_.slice(this.body_offset);
    },
    sliceHeader() {
      return this._raw_.slice(this.header_offset, this.body_offset);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubWpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9idWZmZXIuanMiLCIuLi9jb2RlL2RhdGF2aWV3LmpzIl0sInNvdXJjZXNDb250ZW50IjpbIlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gYXNQYWNrZXRQYXJzZXJBUEkocGFja2V0X2ltcGxfbWV0aG9kcykgOjpcbiAgY29uc3QgQHt9XG4gICAgcGFyc2VIZWFkZXJcbiAgICBwYWNrTWVzc2FnZVxuICAgIGFzQnVmZmVyXG4gICAgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkXG4gID0gcGFja2V0X2ltcGxfbWV0aG9kc1xuXG4gIGNvbnN0IG1zZ19vYmpfcHJvdG8gPSBAOlxuICAgIHNsaWNlQm9keSgpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5ib2R5X29mZnNldFxuICAgIHNsaWNlSGVhZGVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcblxuICBjb25zdCBwYWNrZXRQYXJzZXJBUEkgPSBPYmplY3QuYXNzaWduIEBcbiAgICBPYmplY3QuY3JlYXRlKG51bGwpXG4gICAgcGFja2V0X2ltcGxfbWV0aG9kc1xuICAgIEB7fVxuICAgICAgcGFja01lc3NhZ2VPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNNc2dPYmpcbiAgICAgIG1zZ19vYmpfcHJvdG9cbiAgcmV0dXJuIHBhY2tldFBhcnNlckFQSVxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2VPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBtc2dfcmF3ID0gcGFja01lc3NhZ2UgQCAuLi5hcmdzXG4gICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqIEAgcGFyc2VIZWFkZXIgQCBtc2dfcmF3XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnRpZXMgQCBtc2dfb2JqLCBAOlxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogbXNnX3Jhd1xuICAgIHJldHVybiBtc2dfb2JqXG5cblxuICBmdW5jdGlvbiBhc01zZ09iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIG1lc3NhZ2UgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBtc2dfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIG1zZ19vYmpfcHJvdG8sIEA6XG4gICAgICBoZWFkZXJfb2Zmc2V0OiBAe30gdmFsdWU6IHBrdF9oZWFkZXJfbGVuXG4gICAgICBib2R5X29mZnNldDogQHt9IHZhbHVlOiBib2R5X29mZnNldFxuICAgICAgcGFja2V0X2xlbjogQHt9IHZhbHVlOiBwYWNrZXRfbGVuXG4gICAgICBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuXG4gICAgcmV0dXJuIE9iamVjdC5hc3NpZ24gQCBtc2dfb2JqLCBpbmZvXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBtc2cgPSBwYXJzZVRpcE1lc3NhZ2UoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IG1zZyA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBtc2dcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBNZXNzYWdlKCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBtc2dfb2JqID0gYXNNc2dPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBtc2dfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG5cbiAgLi4uLjQuLi4uLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uNS4uLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uNjcuLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgbGVuZ3RoXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSB1aW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gdWludDMyIGlkX3RhcmdldCAod2hlbiBpZF9yb3V0ZXIgIT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9jb250cm9sX2hlYWRlcl9zaXplID0gMTJcbmNvbnN0IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgY29uc3Qgc2lnID0gYnVmLnJlYWRVSW50MTZMRSBAIDBcbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDJcbiAgICBsZXQgaGVhZGVyX2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCA0XG4gICAgY29uc3QgdHlwZSA9IGJ1Zi5yZWFkVUludDggQCA2XG5cbiAgICBsZXQgdHRsID0gYnVmLnJlYWRVSW50OCBAIDdcbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGJ1Zi53cml0ZVVJbnQ4IEAgdHRsLCA3XG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBidWYucmVhZFVJbnQzMkxFIEAgOFxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXJcblxuICAgIGlmIDAgPT09IGlkX3JvdXRlciA6OlxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGVsc2UgaWYgcGt0X3JvdXRpbmdfaGVhZGVyX3NpemUgPiBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIG51bGwgLy8gdGhpcyBidWZmZXIgaXMgZnJhZ21lbnRlZCBiZWZvcmUgaWRfdGFyZ2V0XG4gICAgZWxzZSA6OlxuICAgICAgaW5mby5pZF90YXJnZXQgPSBidWYucmVhZFVJbnQzMkxFIEAgMTJcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5KVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgcGFja2V0X2xlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdCA9IEJ1ZmZlci5hbGxvYyBAIHBrdF9oZWFkZXJfc2l6ZVxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0LndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBpZiAhIGlkX3JvdXRlciA6OlxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCAwLCA4XG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBwa3Qud3JpdGVVSW50MzJMRSBAIGlkX3JvdXRlciwgOFxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCBpZF90YXJnZXQgfHwgMCwgMTJcblxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5jb25jYXQgQCMgcGt0LCBoZWFkZXIsIGJvZHlcbiAgICBpZiBwYWNrZXRfbGVuICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tlZCBtZXNzYWdlIGxlbmd0aCBtaXNtYXRjaCAobGlicmFyeSBlcnJvcilgXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlVUludDMyTEUoaWQsIG9mZnNldClcbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIHJldHVybiBidWYucmVhZFVJbnQzMkxFKG9mZnNldClcblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIHJldHVybiBCdWZmZXIuZnJvbShzdHIsICd1dGYtOCcpXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICByZXR1cm4gYXNCdWZmZXIoYnVmKS50b1N0cmluZygndXRmLTgnKVxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKSAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc1NhZmVJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpXG4gICAgICByZXR1cm4gQnVmZmVyLmNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBCdWZmZXIoMClcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChsc3QpXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG5cbiAgLi4uLjQuLi4uLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uNS4uLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uNjcuLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgbGVuZ3RoXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSB1aW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gdWludDMyIGlkX3RhcmdldCAod2hlbiBpZF9yb3V0ZXIgIT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9jb250cm9sX2hlYWRlcl9zaXplID0gMTJcbmNvbnN0IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBsZXQgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0VWludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXJcblxuICAgIGlmIDAgPT09IGlkX3JvdXRlciA6OlxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGVsc2UgaWYgcGt0X3JvdXRpbmdfaGVhZGVyX3NpemUgPiBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIG51bGwgLy8gdGhpcyBidWZmZXIgaXMgZnJhZ21lbnRlZCBiZWZvcmUgaWRfdGFyZ2V0XG4gICAgZWxzZSA6OlxuICAgICAgaW5mby5pZF90YXJnZXQgPSBkdi5nZXRVaW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZVxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2UoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIsICdoZWFkZXInKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5LCAnYm9keScpXG5cbiAgICBjb25zdCBwa3RfaGVhZGVyX3NpemUgPSBpZF9yb3V0ZXJcbiAgICAgID8gcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcbiAgICAgIDogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBjb25zdCBsZW4gPSBwa3RfaGVhZGVyX3NpemUgKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IGFycmF5ID0gbmV3IEFycmF5QnVmZmVyKGxlbilcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXJyYXksIDAsIHBrdF9oZWFkZXJfc2l6ZVxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiAhIGlkX3JvdXRlciA6OlxuICAgICAgZHYuc2V0VWludDMyIEAgIDgsIDAsIGxpdHRsZV9lbmRpYW5cbiAgICAgIGlmIGlkX3RhcmdldCA6OlxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXQgZm9yIGNvbnRyb2wgcGFja2V0YFxuICAgIGVsc2UgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIGR2LnNldFVpbnQzMiBAIDEyLCBpZF90YXJnZXQgfHwgMCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShhcnJheSlcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShoZWFkZXIpLCBwa3RfaGVhZGVyX3NpemVcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldFVpbnQzMiBAIG9mZnNldHx8MCwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRVaW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRVSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNTYWZlSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJtc2dfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImJvZHlfb2Zmc2V0IiwiaGVhZGVyX29mZnNldCIsImJ1ZiIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja01lc3NhZ2VPYmoiLCJhcmdzIiwibXNnX3JhdyIsInBhY2tNZXNzYWdlIiwibXNnX29iaiIsImFzTXNnT2JqIiwicGFyc2VIZWFkZXIiLCJkZWZpbmVQcm9wZXJ0aWVzIiwidmFsdWUiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJtc2ciLCJwYXJzZVRpcE1lc3NhZ2UiLCJ1bmRlZmluZWQiLCJsZW5ndGgiLCJjb25jYXRCdWZmZXJzIiwibGVuIiwiYnl0ZXMiLCJuIiwidHJhaWxpbmdCeXRlcyIsInBhcnRzIiwic3BsaWNlIiwidGFpbCIsInNpZ25hdHVyZSIsInBrdF9jb250cm9sX2hlYWRlcl9zaXplIiwicGt0X3JvdXRpbmdfaGVhZGVyX3NpemUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInVucGFja191dGY4Iiwic2lnIiwicmVhZFVJbnQxNkxFIiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsImlkX3JvdXRlciIsInJlYWRVSW50MzJMRSIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJwa3RfaGVhZGVyX3NpemUiLCJwa3QiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZVVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJOdW1iZXIiLCJpc1NhZmVJbnRlZ2VyIiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRVaW50MzIiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0VWludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJidWZmZXIiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsImFyciJdLCJtYXBwaW5ncyI6IkFBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFBQTtpQkFBQTtZQUFBLEtBTUpBLG1CQU5GOztRQVFNQyxnQkFBa0I7Z0JBQ1Y7YUFBVSxLQUFLQyxLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0MsV0FBeEIsQ0FBUDtLQURPO2tCQUVSO2FBQVUsS0FBS0YsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtFLGFBQXhCLEVBQXVDLEtBQUtELFdBQTVDLENBQVA7S0FGSzthQUdiRSxHQUFULEVBQWNDLFNBQU8sQ0FBckIsRUFBd0I7YUFBVUMsU0FBU0YsT0FBTyxLQUFLSixLQUFyQixFQUE0QkssTUFBNUIsQ0FBUDtLQUhMLEVBQXhCOztRQUtNRSxrQkFBa0JDLE9BQU9DLE1BQVAsQ0FDdEJELE9BQU9FLE1BQVAsQ0FBYyxJQUFkLENBRHNCLEVBRXRCWixtQkFGc0IsRUFHdEI7a0JBQUE7Z0JBQUE7WUFBQTtpQkFBQSxFQUhzQixDQUF4QjtTQVFPUyxlQUFQOztXQUdTSSxjQUFULENBQXdCLEdBQUdDLElBQTNCLEVBQWlDO1VBQ3pCQyxVQUFVQyxZQUFjLEdBQUdGLElBQWpCLENBQWhCO1VBQ01HLFVBQVVDLFNBQVdDLFlBQWNKLE9BQWQsQ0FBWCxDQUFoQjtXQUNPSyxnQkFBUCxDQUEwQkgsT0FBMUIsRUFBcUM7YUFDNUIsRUFB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
