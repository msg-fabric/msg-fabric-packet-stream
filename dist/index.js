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

function createBufferPacketParser(options = {}) {
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

function createPacketParser(...args) {
  return createBufferPacketParser(...args);
}

Object.assign(createPacketParser, {
  asPacketParserAPI,
  createBufferPacketParser,
  createDataViewPacketParser });

module.exports = createPacketParser;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrTWVzc2FnZU9ialxuICAgICAgcGFja2V0U3RyZWFtXG4gICAgICBhc01zZ09ialxuICAgICAgbXNnX29ial9wcm90b1xuXG4gIG1zZ19vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZyA9IHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIG1zZy5fcmF3XyA9IG1zZ19yYXdcbiAgICByZXR1cm4gYXNNc2dPYmoobXNnKVxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3Qgc2lnID0gYnVmLnJlYWRVSW50MTZMRSBAIDBcbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDJcbiAgICBjb25zdCBoZWFkZXJfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDRcbiAgICBjb25zdCB0eXBlID0gYnVmLnJlYWRVSW50OCBAIDZcblxuICAgIGxldCB0dGwgPSBidWYucmVhZFVJbnQ4IEAgN1xuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgYnVmLndyaXRlVUludDggQCB0dGwsIDdcblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGJ1Zi5yZWFkSW50MzJMRSBAIDhcbiAgICBjb25zdCBpZF90YXJnZXQgPSBidWYucmVhZEludDMyTEUgQCAxMlxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAOiBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2UoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBpZiAhIE51bWJlci5pc0ludGVnZXIoaWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmICEgTnVtYmVyLmlzSW50ZWdlcihpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHkpXG5cbiAgICBjb25zdCBwYWNrZXRfbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3QgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX2xlblxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0LndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBwa3Qud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIHBrdC53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuXG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmNvbmNhdCBAIyBwa3QsIGhlYWRlciwgYm9keVxuICAgIGlmIHBhY2tldF9sZW4gIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2VkIG1lc3NhZ2UgbGVuZ3RoIG1pc21hdGNoIChsaWJyYXJ5IGVycm9yKWBcbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBCdWZmZXIuYWxsb2MoNClcbiAgICBidWYud3JpdGVJbnQzMkxFKGlkLCBvZmZzZXQpXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRJbnQzMkxFKG9mZnNldClcblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIHJldHVybiBCdWZmZXIuZnJvbShzdHIsICd1dGYtOCcpXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICByZXR1cm4gYXNCdWZmZXIoYnVmKS50b1N0cmluZygndXRmLTgnKVxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlcigwKVxuXG4gICAgaWYgQnVmZmVyLmlzQnVmZmVyKGJ1ZikgOjpcbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpIC8vIFR5cGVkQXJyYXkgb3IgQXJyYXlCdWZmZXJcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKVxuICAgICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gQnVmZmVyKDApXG4gICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQobHN0KVxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRJbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpZF90YXJnZXQgPSBkdi5nZXRJbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEA6IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGFycmF5KVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCBpZCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhc0J1ZmZlcihidWYpXG4gICAgcmV0dXJuIGR2LmdldEludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRJbnQzMkxFIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXIgLy8gTm9kZUpTIEJ1ZmZlclxuXG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iLCJpbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcbmltcG9ydCBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIgZnJvbSAnLi9idWZmZXInXG5pbXBvcnQgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIgZnJvbSAnLi9kYXRhdmlldydcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlUGFja2V0UGFyc2VyKC4uLmFyZ3MpIDo6XG4gIHJldHVybiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIoLi4uYXJncylcblxuT2JqZWN0LmFzc2lnbiBAIGNyZWF0ZVBhY2tldFBhcnNlciwgQHt9XG4gIGFzUGFja2V0UGFyc2VyQVBJXG4gIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlclxuICBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwidW5wYWNrX3V0ZjgiLCJtc2dfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4Iiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrZXRQYXJzZXIiLCJwYWNrTWVzc2FnZU9iaiIsImFyZ3MiLCJtc2dfcmF3IiwicGFja01lc3NhZ2UiLCJtc2ciLCJwYXJzZUhlYWRlciIsImFzTXNnT2JqIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJtc2dfb2JqIiwidmFsdWUiLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwicGFyc2VUaXBNZXNzYWdlIiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsIkVycm9yIiwidG9TdHJpbmciLCJ0eXBlIiwicmVhZFVJbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsIndyaXRlVUludDgiLCJpZF9yb3V0ZXIiLCJyZWFkSW50MzJMRSIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJOdW1iZXIiLCJpc0ludGVnZXIiLCJwa3QiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZUludDMyTEUiLCJjb25jYXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsImZyb20iLCJpc0J1ZmZlciIsIkFycmF5IiwiaXNBcnJheSIsIm1hcCIsImxzdCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsImR2IiwiRGF0YVZpZXciLCJnZXRVaW50MTYiLCJnZXRVaW50OCIsInNldFVpbnQ4IiwiZ2V0SW50MzIiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0SW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJ0ZSIsImVuY29kZSIsImJ1ZmZlciIsInRkIiwiZGVjb2RlIiwiaXNWaWV3IiwiYXJyIiwiY3JlYXRlUGFja2V0UGFyc2VyIl0sIm1hcHBpbmdzIjoiOztBQUNlLFNBQVNBLGlCQUFULENBQTJCQyxtQkFBM0IsRUFBZ0Q7UUFDdkQ7ZUFBQTtlQUFBO1lBQUE7aUJBQUE7WUFBQSxFQUtNQyxXQUxOLEtBTUpELG1CQU5GOztRQVFNRSxnQkFBa0I7b0JBQ047YUFBVSxLQUFLQyxLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0MsYUFBeEIsRUFBdUMsS0FBS0MsV0FBNUMsQ0FBUDtLQURHO2dCQUVWQyxHQUFaLEVBQWlCO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0MsYUFBTCxFQUFyQixDQUFQO0tBRkU7Z0JBR1ZELEdBQVosRUFBaUI7YUFBVUUsS0FBS0MsS0FBTCxDQUFhLEtBQUtDLFdBQUwsQ0FBaUJKLEdBQWpCLEtBQXlCLElBQXRDLENBQVA7S0FIRTs7a0JBS1I7YUFBVSxLQUFLSixLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0UsV0FBeEIsQ0FBUDtLQUxLO2NBTVpDLEdBQVYsRUFBZTthQUFVTixZQUFjTSxPQUFPLEtBQUtLLFdBQUwsRUFBckIsQ0FBUDtLQU5JO2NBT1pMLEdBQVYsRUFBZTthQUFV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
