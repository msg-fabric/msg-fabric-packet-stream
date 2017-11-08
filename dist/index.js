'use strict';

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

function createBufferPacketParser(options = {}) {
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

function createPacketParser(...args) {
  return createBufferPacketParser(...args);
}

Object.assign(createPacketParser, {
  asPacketParserAPI,
  createBufferPacketParser,
  createDataViewPacketParser });

module.exports = createPacketParser;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKCkgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KCkgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmJvZHlfYnVmZmVyKClcbiAgICBib2R5X2pzb24oKSA6OiByZXR1cm4gSlNPTi5wYXJzZSBAIHRoaXMuYm9keV91dGY4KCkgfHwgbnVsbFxuXG4gICAgdW5wYWNrSWQoYnVmLCBvZmZzZXQ9OCkgOjogcmV0dXJuIHVucGFja0lkKGJ1ZiB8fCB0aGlzLl9yYXdfLCBvZmZzZXQpXG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZyA9IHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIG1zZy5fcmF3XyA9IG1zZ19yYXdcbiAgICByZXR1cm4gYXNNc2dPYmoobXNnKVxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgNFxuICAgIGNvbnN0IHR5cGUgPSBidWYucmVhZFVJbnQ4IEAgNlxuXG4gICAgbGV0IHR0bCA9IGJ1Zi5yZWFkVUludDggQCA3XG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBidWYud3JpdGVVSW50OCBAIHR0bCwgN1xuXG4gICAgY29uc3QgaWRfcm91dGVyID0gYnVmLnJlYWRVSW50MzJMRSBAIDhcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gYnVmLnJlYWRVSW50MzJMRSBAIDEyXG4gICAgICByZXR1cm4gQDogaW5mbywgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgcGt0X2hlYWRlcl9sZW46IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlcilcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSlcblxuICAgIGNvbnN0IHBrdF9oZWFkZXJfc2l6ZSA9IGlkX3JvdXRlclxuICAgICAgPyBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZVxuICAgICAgOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBwa3RfaGVhZGVyX3NpemUgKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3QgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX3NpemVcbiAgICBwa3Qud3JpdGVVSW50MTZMRSBAIHNpZ25hdHVyZSwgMFxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgcGFja2V0X2xlbiwgMlxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgaGVhZGVyLmJ5dGVMZW5ndGgsIDRcbiAgICBwa3Qud3JpdGVVSW50OCBAIHR5cGUgfHwgMCwgNlxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHRsIHx8IGRlZmF1bHRfdHRsLCA3XG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIHBrdC53cml0ZVVJbnQzMkxFIEAgMCwgOFxuICAgICAgaWYgaWRfdGFyZ2V0IDo6XG4gICAgICAgIHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldCBmb3IgY29udHJvbCBwYWNrZXRgXG4gICAgZWxzZSA6OlxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCBpZF9yb3V0ZXIsIDhcbiAgICAgIHBrdC53cml0ZVVJbnQzMkxFIEAgaWRfdGFyZ2V0IHx8IDAsIDEyXG5cbiAgICBjb25zdCBidWYgPSBCdWZmZXIuY29uY2F0IEAjIHBrdCwgaGVhZGVyLCBib2R5XG4gICAgaWYgcGFja2V0X2xlbiAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZWQgbWVzc2FnZSBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5hbGxvYyg0KVxuICAgIGJ1Zi53cml0ZVVJbnQzMkxFKGlkLCBvZmZzZXQpXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRVSW50MzJMRShvZmZzZXQpXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBCdWZmZXIoMClcblxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKSAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc1NhZmVJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpXG4gICAgICByZXR1cm4gQnVmZmVyLmNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBCdWZmZXIoMClcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChsc3QpXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG5cbiAgLi4uLjQuLi4uLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uNS4uLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uNjcuLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgbGVuZ3RoXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSB1aW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gdWludDMyIGlkX3RhcmdldCAod2hlbiBpZF9yb3V0ZXIgIT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9jb250cm9sX2hlYWRlcl9zaXplID0gMTJcbmNvbnN0IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBsZXQgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0VWludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXJcblxuICAgIGlmIDAgPT09IGlkX3JvdXRlciA6OlxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGVsc2UgaWYgcGt0X3JvdXRpbmdfaGVhZGVyX3NpemUgPiBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIG51bGwgLy8gdGhpcyBidWZmZXIgaXMgZnJhZ21lbnRlZCBiZWZvcmUgaWRfdGFyZ2V0XG4gICAgZWxzZSA6OlxuICAgICAgaW5mby5pZF90YXJnZXQgPSBkdi5nZXRVaW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgICAgcmV0dXJuIEA6IGluZm8sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIHBrdF9oZWFkZXJfbGVuOiBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZVxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2UoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIsICdoZWFkZXInKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5LCAnYm9keScpXG5cbiAgICBjb25zdCBwa3RfaGVhZGVyX3NpemUgPSBpZF9yb3V0ZXJcbiAgICAgID8gcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcbiAgICAgIDogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBjb25zdCBsZW4gPSBwa3RfaGVhZGVyX3NpemUgKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IGFycmF5ID0gbmV3IEFycmF5QnVmZmVyKGxlbilcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXJyYXksIDAsIHBrdF9oZWFkZXJfc2l6ZVxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiAhIGlkX3JvdXRlciA6OlxuICAgICAgZHYuc2V0VWludDMyIEAgIDgsIDAsIGxpdHRsZV9lbmRpYW5cbiAgICAgIGlmIGlkX3RhcmdldCA6OlxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXQgZm9yIGNvbnRyb2wgcGFja2V0YFxuICAgIGVsc2UgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIGR2LnNldFVpbnQzMiBAIDEyLCBpZF90YXJnZXQgfHwgMCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShhcnJheSlcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShoZWFkZXIpLCBwa3RfaGVhZGVyX3NpemVcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldFVpbnQzMiBAIG9mZnNldHx8MCwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRVaW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIHVuZGVmaW5lZCA9PT0gYnVmLmJ1ZmZlciA6OlxuICAgICAgICByZXR1cm4gYnVmXG5cbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBidWYuYnVmZmVyXG5cbiAgICAgIGlmICdmdW5jdGlvbicgPT09IHR5cGVvZiBidWYucmVhZFVJbnQzMkxFIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXIgLy8gTm9kZUpTIEJ1ZmZlclxuXG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc1NhZmVJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIiwiaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5pbXBvcnQgY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIGZyb20gJy4vYnVmZmVyJ1xuaW1wb3J0IGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIGZyb20gJy4vZGF0YXZpZXcnXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZVBhY2tldFBhcnNlciguLi5hcmdzKSA6OlxuICByZXR1cm4gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKC4uLmFyZ3MpXG5cbk9iamVjdC5hc3NpZ24gQCBjcmVhdGVQYWNrZXRQYXJzZXIsIEB7fVxuICBhc1BhY2tldFBhcnNlckFQSVxuICBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXJcbiAgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInVucGFja191dGY4IiwibXNnX29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJoZWFkZXJfb2Zmc2V0IiwiYm9keV9vZmZzZXQiLCJoZWFkZXJfYnVmZmVyIiwiSlNPTiIsInBhcnNlIiwiaGVhZGVyX3V0ZjgiLCJib2R5X2J1ZmZlciIsImJvZHlfdXRmOCIsImJ1ZiIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja01lc3NhZ2VPYmoiLCJhcmdzIiwibXNnX3JhdyIsInBhY2tNZXNzYWdlIiwibXNnIiwicGFyc2VIZWFkZXIiLCJhc01zZ09iaiIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwibXNnX29iaiIsInZhbHVlIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsInBhcnNlVGlwTWVzc2FnZSIsInVuZGVmaW5lZCIsImxlbmd0aCIsImNvbmNhdEJ1ZmZlcnMiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwicGt0X2NvbnRyb2xfaGVhZGVyX3NpemUiLCJwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSIsImRlZmF1bHRfdHRsIiwiY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIiwicGFja191dGY4Iiwic2lnIiwicmVhZFVJbnQxNkxFIiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsImlkX3JvdXRlciIsInJlYWRVSW50MzJMRSIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJwa3RfaGVhZGVyX3NpemUiLCJwa3QiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZVVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJOdW1iZXIiLCJpc1NhZmVJbnRlZ2VyIiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRVaW50MzIiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0VWludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJidWZmZXIiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsImFyciIsImNyZWF0ZVBhY2tldFBhcnNlciJdLCJtYXBwaW5ncyI6Ijs7QUFDZSxTQUFTQSxpQkFBVCxDQUEyQkMsbUJBQTNCLEVBQWdEO1FBQ3ZEO2VBQUE7ZUFBQTtZQUFBO2lCQUFBO1lBQUEsRUFLTUMsV0FMTixLQU1KRCxtQkFORjs7UUFRTUUsZ0JBQWtCO29CQUNOO2FBQVUsS0FBS0MsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtDLGFBQXhCLEVBQXVDLEtBQUtDLFdBQTVDLENBQVA7S0FERztrQkFFUjthQUFVTCxZQUFjLEtBQUtNLGFBQUwsRUFBZCxDQUFQO0tBRks7a0JBR1I7YUFBVUMsS0FBS0MsS0FBTCxDQUFhLEtBQUtDLFdBQUwsTUFBc0IsSUFBbkMsQ0FBUDtLQUhLOztrQkFLUjthQUFVLEtBQUtQLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEs7Z0JBTVY7YUFBVUwsWUFBYyxLQUFLVSxXQUFMLEVBQWQsQ0FBUDtLQU5PO2dCQU9WO2FBQVVILEtBQUtDLEtBQUwsQ0FBYSxLQUFLRyxTQUFMLE1BQW9CLElBQWpDLENBQVA7S0FQTzs7YUFTYkMsR0FBVCxFQUFjQyxTQUFPLENBQXJCLEVBQXdCO2FBQVVDLFNBQVNGLE9BQU8sS0FBS1YsS0FBckIsRUFBNEJXLE1BQTVCLENBQVA7S0FUTCxFQUF4Qjs7UUFXTUUsa0JBQWtCQyxPQUFPQyxNQUFQLENBQ3RCRCxPQUFPRSxNQUFQLENBQWMsSUFBZCxDQURzQixFQUV0Qm5CLG1CQUZzQixFQUd0QjtrQkFBQTtnQkFBQTtZQUFBO2lCQUFBLEVBSHNCLENBQXhCO1NB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
