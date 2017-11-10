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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrTWVzc2FnZU9ialxuICAgICAgcGFja2V0U3RyZWFtXG4gICAgICBhc01zZ09ialxuICAgICAgbXNnX29ial9wcm90b1xuXG4gIG1zZ19vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZyA9IHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIG1zZy5fcmF3XyA9IG1zZ19yYXdcbiAgICByZXR1cm4gYXNNc2dPYmoobXNnKVxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrTWVzc2FnZVxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3Qgc2lnID0gYnVmLnJlYWRVSW50MTZMRSBAIDBcbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDJcbiAgICBjb25zdCBoZWFkZXJfbGVuID0gYnVmLnJlYWRVSW50MTZMRSBAIDRcbiAgICBjb25zdCB0eXBlID0gYnVmLnJlYWRVSW50OCBAIDZcblxuICAgIGxldCB0dGwgPSBidWYucmVhZFVJbnQ4IEAgN1xuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgYnVmLndyaXRlVUludDggQCB0dGwsIDdcblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGJ1Zi5yZWFkSW50MzJMRSBAIDhcbiAgICBjb25zdCBpZF90YXJnZXQgPSBidWYucmVhZEludDMyTEUgQCAxMlxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAOiBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2UoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBpZiAhIE51bWJlci5pc0ludGVnZXIoaWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmICEgTnVtYmVyLmlzSW50ZWdlcihpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHkpXG5cbiAgICBjb25zdCBwYWNrZXRfbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3QgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX2xlblxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgc2lnbmF0dXJlLCAwXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBwYWNrZXRfbGVuLCAyXG4gICAgcGt0LndyaXRlVUludDE2TEUgQCBoZWFkZXIuYnl0ZUxlbmd0aCwgNFxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHlwZSB8fCAwLCA2XG4gICAgcGt0LndyaXRlVUludDggQCB0dGwgfHwgZGVmYXVsdF90dGwsIDdcbiAgICBwa3Qud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIHBrdC53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuXG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmNvbmNhdCBAIyBwa3QsIGhlYWRlciwgYm9keVxuICAgIGlmIHBhY2tldF9sZW4gIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2VkIG1lc3NhZ2UgbGVuZ3RoIG1pc21hdGNoIChsaWJyYXJ5IGVycm9yKWBcbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBCdWZmZXIuYWxsb2MoNClcbiAgICBidWYud3JpdGVJbnQzMkxFIEAgMCB8IGlkLCBvZmZzZXR8fDBcbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIHJldHVybiBidWYucmVhZEludDMyTEUgQCBvZmZzZXR8fDBcblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIHJldHVybiBCdWZmZXIuZnJvbShzdHIsICd1dGYtOCcpXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICByZXR1cm4gYXNCdWZmZXIoYnVmKS50b1N0cmluZygndXRmLTgnKVxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlcigwKVxuXG4gICAgaWYgQnVmZmVyLmlzQnVmZmVyKGJ1ZikgOjpcbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpIC8vIFR5cGVkQXJyYXkgb3IgQXJyYXlCdWZmZXJcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKVxuICAgICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gQnVmZmVyKDApXG4gICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQobHN0KVxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRJbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpZF90YXJnZXQgPSBkdi5nZXRJbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEA6IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGFycmF5KVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIiwiaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5pbXBvcnQgY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIGZyb20gJy4vYnVmZmVyJ1xuaW1wb3J0IGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIGZyb20gJy4vZGF0YXZpZXcnXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZVBhY2tldFBhcnNlciguLi5hcmdzKSA6OlxuICByZXR1cm4gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKC4uLmFyZ3MpXG5cbk9iamVjdC5hc3NpZ24gQCBjcmVhdGVQYWNrZXRQYXJzZXIsIEB7fVxuICBhc1BhY2tldFBhcnNlckFQSVxuICBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXJcbiAgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInVucGFja191dGY4IiwibXNnX29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJoZWFkZXJfb2Zmc2V0IiwiYm9keV9vZmZzZXQiLCJidWYiLCJoZWFkZXJfYnVmZmVyIiwiSlNPTiIsInBhcnNlIiwiaGVhZGVyX3V0ZjgiLCJib2R5X2J1ZmZlciIsImJvZHlfdXRmOCIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja2V0UGFyc2VyIiwicGFja01lc3NhZ2VPYmoiLCJhcmdzIiwibXNnX3JhdyIsInBhY2tNZXNzYWdlIiwibXNnIiwicGFyc2VIZWFkZXIiLCJhc01zZ09iaiIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwibXNnX29iaiIsInZhbHVlIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsInBhcnNlVGlwTWVzc2FnZSIsInVuZGVmaW5lZCIsImxlbmd0aCIsImNvbmNhdEJ1ZmZlcnMiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwiZGVmYXVsdF90dGwiLCJjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIiLCJwYWNrX3V0ZjgiLCJzaWciLCJyZWFkVUludDE2TEUiLCJFcnJvciIsInRvU3RyaW5nIiwidHlwZSIsInJlYWRVSW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJ3cml0ZVVJbnQ4IiwiaWRfcm91dGVyIiwicmVhZEludDMyTEUiLCJpZF90YXJnZXQiLCJoZWFkZXIiLCJib2R5IiwiTnVtYmVyIiwiaXNJbnRlZ2VyIiwicGt0IiwiQnVmZmVyIiwiYWxsb2MiLCJ3cml0ZVVJbnQxNkxFIiwid3JpdGVJbnQzMkxFIiwiY29uY2F0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJmcm9tIiwiaXNCdWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJtYXAiLCJsc3QiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJkdiIsIkRhdGFWaWV3IiwiZ2V0VWludDE2IiwiZ2V0VWludDgiLCJzZXRVaW50OCIsImdldEludDMyIiwiYXJyYXkiLCJBcnJheUJ1ZmZlciIsInNldFVpbnQxNiIsInNldEludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJidWZmZXIiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsImFyciIsImNyZWF0ZVBhY2tldFBhcnNlciJdLCJtYXBwaW5ncyI6Ijs7QUFDZSxTQUFTQSxpQkFBVCxDQUEyQkMsbUJBQTNCLEVBQWdEO1FBQ3ZEO2VBQUE7ZUFBQTtZQUFBO2lCQUFBO1lBQUEsRUFLTUMsV0FMTixLQU1KRCxtQkFORjs7UUFRTUUsZ0JBQWtCO29CQUNOO2FBQVUsS0FBS0MsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtDLGFBQXhCLEVBQXVDLEtBQUtDLFdBQTVDLENBQVA7S0FERztnQkFFVkMsR0FBWixFQUFpQjthQUFVTixZQUFjTSxPQUFPLEtBQUtDLGFBQUwsRUFBckIsQ0FBUDtLQUZFO2dCQUdWRCxHQUFaLEVBQWlCO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLQyxXQUFMLENBQWlCSixHQUFqQixLQUF5QixJQUF0QyxDQUFQO0tBSEU7O2tCQUtSO2FBQVUsS0FBS0osS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtFLFdBQXhCLENBQVA7S0FMSztjQU1aQyxHQUFWLEVBQWU7YUFBVU4sWUFBY00sT0FBTyxLQUFLSyxXQUFMLEVBQXJCLENBQVA7S0FOSTtjQU9a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
