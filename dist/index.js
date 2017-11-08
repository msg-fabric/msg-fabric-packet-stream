'use strict';

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

function createPacketParser(...args) {
  return createBufferPacketParser(...args);
}

Object.assign(createPacketParser, {
  asPacketParserAPI,
  createBufferPacketParser,
  createDataViewPacketParser });

module.exports = createPacketParser;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBtc2dfb2JqX3Byb3RvID0gQDpcbiAgICBzbGljZUJvZHkoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBzbGljZUhlYWRlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgdW5wYWNrSWQoYnVmLCBvZmZzZXQ9OCkgOjogcmV0dXJuIHVucGFja0lkKGJ1ZiB8fCB0aGlzLl9yYXdfLCBvZmZzZXQpXG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZ19vYmogPSBhc01zZ09iaiBAIHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0aWVzIEAgbXNnX29iaiwgQDpcbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IG1zZ19yYXdcbiAgICByZXR1cm4gbXNnX29ialxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja01lc3NhZ2VcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGNvbnN0IHNpZyA9IGJ1Zi5yZWFkVUludDE2TEUgQCAwXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGJ1Zi5yZWFkVUludDE2TEUgQCAyXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgNFxuICAgIGNvbnN0IHR5cGUgPSBidWYucmVhZFVJbnQ4IEAgNlxuXG4gICAgbGV0IHR0bCA9IGJ1Zi5yZWFkVUludDggQCA3XG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBidWYud3JpdGVVSW50OCBAIHR0bCwgN1xuXG4gICAgY29uc3QgaWRfcm91dGVyID0gYnVmLnJlYWRVSW50MzJMRSBAIDhcbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gYnVmLnJlYWRVSW50MzJMRSBAIDEyXG4gICAgICByZXR1cm4gQDogaW5mbywgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgcGt0X2hlYWRlcl9sZW46IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZSguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlcilcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSlcblxuICAgIGNvbnN0IHBrdF9oZWFkZXJfc2l6ZSA9IGlkX3JvdXRlclxuICAgICAgPyBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZVxuICAgICAgOiBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZVxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBwa3RfaGVhZGVyX3NpemUgKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIHBhY2tldF9sZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3QgPSBCdWZmZXIuYWxsb2MgQCBwa3RfaGVhZGVyX3NpemVcbiAgICBwa3Qud3JpdGVVSW50MTZMRSBAIHNpZ25hdHVyZSwgMFxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgcGFja2V0X2xlbiwgMlxuICAgIHBrdC53cml0ZVVJbnQxNkxFIEAgaGVhZGVyLmJ5dGVMZW5ndGgsIDRcbiAgICBwa3Qud3JpdGVVSW50OCBAIHR5cGUgfHwgMCwgNlxuICAgIHBrdC53cml0ZVVJbnQ4IEAgdHRsIHx8IGRlZmF1bHRfdHRsLCA3XG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIHBrdC53cml0ZVVJbnQzMkxFIEAgMCwgOFxuICAgICAgaWYgaWRfdGFyZ2V0IDo6XG4gICAgICAgIHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldCBmb3IgY29udHJvbCBwYWNrZXRgXG4gICAgZWxzZSA6OlxuICAgICAgcGt0LndyaXRlVUludDMyTEUgQCBpZF9yb3V0ZXIsIDhcbiAgICAgIHBrdC53cml0ZVVJbnQzMkxFIEAgaWRfdGFyZ2V0IHx8IDAsIDEyXG5cbiAgICBjb25zdCBidWYgPSBCdWZmZXIuY29uY2F0IEAjIHBrdCwgaGVhZGVyLCBib2R5XG4gICAgaWYgcGFja2V0X2xlbiAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZWQgbWVzc2FnZSBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5hbGxvYyg0KVxuICAgIGJ1Zi53cml0ZVVJbnQzMkxFKGlkLCBvZmZzZXQpXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRVSW50MzJMRShvZmZzZXQpXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBCdWZmZXIuaXNCdWZmZXIoYnVmKSA6OlxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZikgLy8gVHlwZWRBcnJheSBvciBBcnJheUJ1ZmZlclxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNTYWZlSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20oYnVmKVxuICAgICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gQnVmZmVyKDApXG4gICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQobHN0KVxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldFVpbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gZHYuZ2V0VWludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX3NpemVcbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBkdi5zZXRVaW50MzIgQCAgOCwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgICBkdi5zZXRVaW50MzIgQCAxMiwgaWRfdGFyZ2V0IHx8IDAsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9zaXplXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIGFycmF5XG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRVaW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0VWludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkVUludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzU2FmZUludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iLCJpbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcbmltcG9ydCBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIgZnJvbSAnLi9idWZmZXInXG5pbXBvcnQgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIgZnJvbSAnLi9kYXRhdmlldydcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlUGFja2V0UGFyc2VyKC4uLmFyZ3MpIDo6XG4gIHJldHVybiBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIoLi4uYXJncylcblxuT2JqZWN0LmFzc2lnbiBAIGNyZWF0ZVBhY2tldFBhcnNlciwgQHt9XG4gIGFzUGFja2V0UGFyc2VyQVBJXG4gIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlclxuICBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwibXNnX29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJib2R5X29mZnNldCIsImhlYWRlcl9vZmZzZXQiLCJidWYiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tNZXNzYWdlT2JqIiwiYXJncyIsIm1zZ19yYXciLCJwYWNrTWVzc2FnZSIsIm1zZ19vYmoiLCJhc01zZ09iaiIsInBhcnNlSGVhZGVyIiwiZGVmaW5lUHJvcGVydGllcyIsInZhbHVlIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwibXNnIiwicGFyc2VUaXBNZXNzYWdlIiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSIsInBrdF9yb3V0aW5nX2hlYWRlcl9zaXplIiwiZGVmYXVsdF90dGwiLCJjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIiLCJwYWNrX3V0ZjgiLCJ1bnBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsIkVycm9yIiwidG9TdHJpbmciLCJ0eXBlIiwicmVhZFVJbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsIndyaXRlVUludDgiLCJpZF9yb3V0ZXIiLCJyZWFkVUludDMyTEUiLCJpZF90YXJnZXQiLCJoZWFkZXIiLCJib2R5IiwicGt0X2hlYWRlcl9zaXplIiwicGt0IiwiQnVmZmVyIiwiYWxsb2MiLCJ3cml0ZVVJbnQxNkxFIiwid3JpdGVVSW50MzJMRSIsImNvbmNhdCIsInBhY2tJZCIsImlkIiwic3RyIiwiZnJvbSIsImlzQnVmZmVyIiwiQXJyYXkiLCJpc0FycmF5IiwiTnVtYmVyIiwiaXNTYWZlSW50ZWdlciIsIm1hcCIsImxzdCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsImR2IiwiRGF0YVZpZXciLCJnZXRVaW50MTYiLCJnZXRVaW50OCIsInNldFVpbnQ4IiwiZ2V0VWludDMyIiwiYXJyYXkiLCJBcnJheUJ1ZmZlciIsInNldFVpbnQxNiIsInNldFVpbnQzMiIsInU4IiwiVWludDhBcnJheSIsInNldCIsInRlIiwiZW5jb2RlIiwiYnVmZmVyIiwidGQiLCJkZWNvZGUiLCJpc1ZpZXciLCJhcnIiLCJjcmVhdGVQYWNrZXRQYXJzZXIiXSwibWFwcGluZ3MiOiI7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFBQTtpQkFBQTtZQUFBLEtBTUpBLG1CQU5GOztRQVFNQyxnQkFBa0I7Z0JBQ1Y7YUFBVSxLQUFLQyxLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0MsV0FBeEIsQ0FBUDtLQURPO2tCQUVSO2FBQVUsS0FBS0YsS0FBTCxDQUFXQyxLQUFY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
