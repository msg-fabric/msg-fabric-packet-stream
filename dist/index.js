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

function createPacketParser(...args) {
  return createBufferPacketParser(...args);
}

Object.assign(createPacketParser, {
  asPacketParserAPI,
  createBufferPacketParser,
  createDataViewPacketParser });

module.exports = createPacketParser;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQHt9XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICBmd2RfdG8oZndkX2lkKSA6OiByZXR1cm4gYXNGd2RQa3RPYmogQCB0aGlzLCBmd2RfaWRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrUGFja2V0T2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzUGt0T2JqLCBhc0Z3ZFBrdE9ialxuICAgICAgcGt0X29ial9wcm90b1xuXG4gIHBrdF9vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXRPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBwa3RfcmF3ID0gcGFja1BhY2tldCBAIC4uLmFyZ3NcbiAgICBjb25zdCBwa3QgPSBwYXJzZUhlYWRlciBAIHBrdF9yYXdcbiAgICBwa3QuX3Jhd18gPSBwa3RfcmF3XG4gICAgcmV0dXJuIGFzUGt0T2JqKHBrdClcblxuXG4gIGZ1bmN0aW9uIGFzUGt0T2JqKHtpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgX3Jhd199KSA6OlxuICAgIGxldCBib2R5X29mZnNldCA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyX2xlblxuICAgIGlmIGJvZHlfb2Zmc2V0ID4gcGFja2V0X2xlbiA6OlxuICAgICAgYm9keV9vZmZzZXQgPSBudWxsIC8vIGludmFsaWQgcGFja2V0IGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgcGt0X29iaiA9IE9iamVjdC5jcmVhdGUgQCBwa3Rfb2JqX3Byb3RvLCBAe31cbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIHBrdF9vYmosIGluZm9cblxuICBmdW5jdGlvbiBhc0Z3ZFBrdE9iaihwa3Rfb2JqLCB7aWRfcm91dGVyLCBpZF90YXJnZXR9KSA6OlxuICAgIGlmIG51bGwgPT0gaWRfdGFyZ2V0IDo6IHRocm93IG5ldyBFcnJvciBAICdpZF90YXJnZXQgcmVxdWlyZWQnXG4gICAgY29uc3QgcmF3ID0gZndkSGVhZGVyIEAgcGt0X29iai5fcmF3XywgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICBjb25zdCBmd2Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmosIEB7fSBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGZ3ZF9vYmouaWRfcm91dGVyID0gaWRfcm91dGVyXG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogZndkX29iai5pZF90YXJnZXQgPSBpZF90YXJnZXRcbiAgICBmd2Rfb2JqLmlzX2Z3ZCA9IHRydWVcbiAgICByZXR1cm4gZndkX29ialxuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgcGt0ID0gcGFyc2VUaXBQYWNrZXQoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IHBrdCA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBwa3RcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBQYWNrZXQoKSA6OlxuICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6XG4gICAgICAgIGlmIDAgPT09IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcmV0dXJuXG4gICAgICAgIGlmIDEgPCBxLmxlbmd0aCA6OlxuICAgICAgICAgIHEgPSBAW10gY29uY2F0QnVmZmVycyBAIHEsIHFCeXRlTGVuXG5cbiAgICAgICAgdGlwID0gcGFyc2VIZWFkZXIgQCBxWzBdLCBkZWNyZW1lbnRfdHRsXG4gICAgICAgIGlmIG51bGwgPT09IHRpcCA6OiByZXR1cm5cblxuICAgICAgY29uc3QgbGVuID0gdGlwLnBhY2tldF9sZW5cbiAgICAgIGlmIHFCeXRlTGVuIDwgbGVuIDo6XG4gICAgICAgIHJldHVyblxuXG4gICAgICBsZXQgYnl0ZXMgPSAwLCBuID0gMFxuICAgICAgd2hpbGUgYnl0ZXMgPCBsZW4gOjpcbiAgICAgICAgYnl0ZXMgKz0gcVtuKytdLmJ5dGVMZW5ndGhcblxuICAgICAgY29uc3QgdHJhaWxpbmdCeXRlcyA9IGJ5dGVzIC0gbGVuXG4gICAgICBpZiAwID09PSB0cmFpbGluZ0J5dGVzIDo6IC8vIHdlIGhhdmUgYW4gZXhhY3QgbGVuZ3RoIG1hdGNoXG4gICAgICAgIGNvbnN0IHBhcnRzID0gcS5zcGxpY2UoMCwgbilcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgZWxzZSA6OiAvLyB3ZSBoYXZlIHRyYWlsaW5nIGJ5dGVzIG9uIHRoZSBsYXN0IGFycmF5XG4gICAgICAgIGNvbnN0IHBhcnRzID0gMSA9PT0gcS5sZW5ndGggPyBbXSA6IHEuc3BsaWNlKDAsIG4tMSlcbiAgICAgICAgY29uc3QgdGFpbCA9IHFbMF1cblxuICAgICAgICBwYXJ0cy5wdXNoIEAgdGFpbC5zbGljZSgwLCAtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcVswXSA9IHRhaWwuc2xpY2UoLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIDo6XG4gICAgICAgIGNvbnN0IHBrdF9vYmogPSBhc1BrdE9iaih0aXApXG4gICAgICAgIHRpcCA9IG51bGxcbiAgICAgICAgcmV0dXJuIHBrdF9vYmpcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja1BhY2tldCwgZndkSGVhZGVyXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBzaWcgPSBidWYucmVhZFVJbnQxNkxFIEAgMFxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgMlxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgNFxuICAgIGNvbnN0IHR5cGUgPSBidWYucmVhZFVJbnQ4IEAgNlxuXG4gICAgbGV0IHR0bCA9IGJ1Zi5yZWFkVUludDggQCA3XG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBidWYud3JpdGVVSW50OCBAIHR0bCwgN1xuXG4gICAgY29uc3QgaWRfcm91dGVyID0gYnVmLnJlYWRJbnQzMkxFIEAgOFxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGJ1Zi5yZWFkSW50MzJMRSBAIDEyXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEB7fSBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldCguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9XG4gICAgICAxID09PSBhcmdzLmxlbmd0aCA/IGFyZ3NbMF0gOiBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcblxuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlcilcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSlcblxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgcGFja2V0X2xlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdGhkciA9IEJ1ZmZlci5hbGxvYyBAIHBrdF9oZWFkZXJfbGVuXG4gICAgcGt0aGRyLndyaXRlVUludDE2TEUgQCBzaWduYXR1cmUsIDBcbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIHBhY2tldF9sZW4sIDJcbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIGhlYWRlci5ieXRlTGVuZ3RoLCA0XG4gICAgcGt0aGRyLndyaXRlVUludDggQCB0eXBlIHx8IDAsIDZcbiAgICBwa3RoZHIud3JpdGVVSW50OCBAIHR0bCB8fCBkZWZhdWx0X3R0bCwgN1xuICAgIHBrdGhkci53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgcGt0aGRyLndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG5cbiAgICBjb25zdCBidWYgPSBCdWZmZXIuY29uY2F0IEAjIHBrdGhkciwgaGVhZGVyLCBib2R5XG4gICAgaWYgcGFja2V0X2xlbiAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgbGVuZ3RoIG1pc21hdGNoIChsaWJyYXJ5IGVycm9yKWBcbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBmd2RIZWFkZXIoYnVmLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCkgOjpcbiAgICBidWYgPSBuZXcgQnVmZmVyKGJ1ZilcbiAgICBpZiBudWxsICE9IGlkX3JvdXRlciA6OiBidWYud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3JvdXRlciwgOFxuICAgIGlmIG51bGwgIT0gaWRfdGFyZ2V0IDo6IGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWRfdGFyZ2V0LCAxMlxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5hbGxvYyg0KVxuICAgIGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWQsIG9mZnNldHx8MFxuICAgIHJldHVybiBidWZcbiAgZnVuY3Rpb24gdW5wYWNrSWQoYnVmLCBvZmZzZXQpIDo6XG4gICAgcmV0dXJuIGJ1Zi5yZWFkSW50MzJMRSBAIG9mZnNldHx8MFxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgcmV0dXJuIEJ1ZmZlci5mcm9tKHN0ciwgJ3V0Zi04JylcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIHJldHVybiBhc0J1ZmZlcihidWYpLnRvU3RyaW5nKCd1dGYtOCcpXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gQnVmZmVyKDApXG5cbiAgICBpZiBCdWZmZXIuaXNCdWZmZXIoYnVmKSA6OlxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tIEAgYnVmLmJ1ZmZlciAvLyBEYXRhVmlld1xuICAgICAgZWxzZSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20gQCBidWYgLy8gVHlwZWRBcnJheSBvciBBcnJheUJ1ZmZlclxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbShidWYpXG4gICAgICByZXR1cm4gQnVmZmVyLmNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBCdWZmZXIoMClcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChsc3QpXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5jb25zdCBsaXR0bGVfZW5kaWFuID0gdHJ1ZVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICBjb25zdCBfVGV4dEVuY29kZXJfID0gb3B0aW9ucy5UZXh0RW5jb2RlciB8fCBUZXh0RW5jb2RlclxuICBjb25zdCBfVGV4dERlY29kZXJfID0gb3B0aW9ucy5UZXh0RGVjb2RlciB8fCBUZXh0RGVjb2RlclxuXG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBwYWNrSWQsIHVucGFja0lkLCBwYWNrX3V0ZjgsIHVucGFja191dGY4XG5cbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuXG5cbiAgZnVuY3Rpb24gcGFyc2VIZWFkZXIoYnVmLCBkZWNyZW1lbnRfdHRsKSA6OlxuICAgIGlmIHBrdF9oZWFkZXJfbGVuID4gYnVmLmJ5dGVMZW5ndGggOjogcmV0dXJuIG51bGxcblxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmXG5cbiAgICBjb25zdCBzaWcgPSBkdi5nZXRVaW50MTYgQCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgc2lnbmF0dXJlICE9PSBzaWcgOjpcbiAgICAgIHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgc3RyZWFtIGZyYW1pbmcgZXJyb3IgKGZvdW5kOiAke3NpZy50b1N0cmluZygxNil9IGV4cGVjdGVkOiAke3NpZ25hdHVyZS50b1N0cmluZygxNil9KWBcblxuICAgIC8vIHVwIHRvIDY0ayBwYWNrZXQgbGVuZ3RoOyBsZW5ndGggaW5jbHVkZXMgaGVhZGVyXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IGR2LmdldFVpbnQxNiBAIDIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBoZWFkZXJfbGVuID0gZHYuZ2V0VWludDE2IEAgNCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IHR5cGUgPSBkdi5nZXRVaW50OCBAIDYsIGxpdHRsZV9lbmRpYW5cblxuICAgIGxldCB0dGwgPSBkdi5nZXRVaW50OCBAIDcsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBkZWNyZW1lbnRfdHRsIDo6XG4gICAgICB0dGwgPSBNYXRoLm1heCBAIDAsIHR0bCAtIDFcbiAgICAgIGR2LnNldFVpbnQ4IEAgNywgdHRsLCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCBpZF9yb3V0ZXIgPSBkdi5nZXRJbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpZF90YXJnZXQgPSBkdi5nZXRJbnQzMiBAIDEyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEB7fSBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldCguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9XG4gICAgICAxID09PSBhcmdzLmxlbmd0aCA/IGFyZ3NbMF0gOiBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcblxuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBwa3RoZHIgPSBuZXcgQXJyYXlCdWZmZXIobGVuKVxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgcGt0aGRyLCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KHBrdGhkcilcbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShoZWFkZXIpLCBwa3RfaGVhZGVyX2xlblxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGJvZHkpLCBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIGFycmF5XG5cblxuICBmdW5jdGlvbiBmd2RIZWFkZXIoYnVmLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCkgOjpcbiAgICBidWYgPSBuZXcgVWludDhBcnJheShidWYpLmJ1ZmZlclxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmLCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRJbnQzMiBAIG9mZnNldHx8MCwgMCB8IGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0SW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIHVuZGVmaW5lZCA9PT0gYnVmLmJ1ZmZlciA6OlxuICAgICAgICByZXR1cm4gYnVmXG5cbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBidWYuYnVmZmVyXG5cbiAgICAgIGlmICdmdW5jdGlvbicgPT09IHR5cGVvZiBidWYucmVhZEludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiIsImltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuaW1wb3J0IGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciBmcm9tICcuL2J1ZmZlcidcbmltcG9ydCBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciBmcm9tICcuL2RhdGF2aWV3J1xuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVQYWNrZXRQYXJzZXIoLi4uYXJncykgOjpcbiAgcmV0dXJuIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciguLi5hcmdzKVxuXG5PYmplY3QuYXNzaWduIEAgY3JlYXRlUGFja2V0UGFyc2VyLCBAe31cbiAgYXNQYWNrZXRQYXJzZXJBUElcbiAgY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyXG4gIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJwYWNrUGFja2V0IiwiZndkSGVhZGVyIiwiY29uY2F0QnVmZmVycyIsInVucGFja191dGY4IiwicGt0X29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJoZWFkZXJfb2Zmc2V0IiwiYm9keV9vZmZzZXQiLCJidWYiLCJoZWFkZXJfYnVmZmVyIiwiSlNPTiIsInBhcnNlIiwiaGVhZGVyX3V0ZjgiLCJib2R5X2J1ZmZlciIsImJvZHlfdXRmOCIsImZ3ZF9pZCIsImFzRndkUGt0T2JqIiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrZXRQYXJzZXIiLCJwYWNrUGFja2V0T2JqIiwiYXJncyIsInBrdF9yYXciLCJwa3QiLCJwYXJzZUhlYWRlciIsImFzUGt0T2JqIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJwa3Rfb2JqIiwidmFsdWUiLCJpZF9yb3V0ZXIiLCJpZF90YXJnZXQiLCJFcnJvciIsInJhdyIsImZ3ZF9vYmoiLCJpc19md2QiLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwicGFyc2VUaXBQYWNrZXQiLCJ1bmRlZmluZWQiLCJsZW5ndGgiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwiZGVmYXVsdF90dGwiLCJjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXIiLCJwYWNrX3V0ZjgiLCJzaWciLCJyZWFkVUludDE2TEUiLCJ0b1N0cmluZyIsInR5cGUiLCJyZWFkVUludDgiLCJ0dGwiLCJNYXRoIiwibWF4Iiwid3JpdGVVSW50OCIsInJlYWRJbnQzMkxFIiwiaGVhZGVyIiwiYm9keSIsIk51bWJlciIsImlzSW50ZWdlciIsInBrdGhkciIsIkJ1ZmZlciIsImFsbG9jIiwid3JpdGVVSW50MTZMRSIsIndyaXRlSW50MzJMRSIsImNvbmNhdCIsInBhY2tJZCIsImlkIiwic3RyIiwiZnJvbSIsImlzQnVmZmVyIiwiQXJyYXlCdWZmZXIiLCJpc1ZpZXciLCJidWZmZXIiLCJBcnJheSIsImlzQXJyYXkiLCJtYXAiLCJsc3QiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJkdiIsIkRhdGFWaWV3IiwiZ2V0VWludDE2IiwiZ2V0VWludDgiLCJzZXRVaW50OCIsImdldEludDMyIiwic2V0VWludDE2Iiwic2V0SW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJhcnJheSIsInRlIiwiZW5jb2RlIiwidGQiLCJkZWNvZGUiLCJhcnIiLCJjcmVhdGVQYWNrZXRQYXJzZXIiXSwibWFwcGluZ3MiOiI7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBLEVBQ1NDLFVBRFQsRUFDcUJDLFNBRHJCO1lBQUEsRUFFTUMsYUFGTjtZQUFBLEVBR01DLFdBSE4sS0FJSkosbUJBSkY7O1FBTU1LLGdCQUFnQjtvQkFDSjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREM7Z0JBRVJDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGQTtnQkFHUkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FBeUIsSUFBdEMsQ0FBUDtLQUhBOztrQkFLTjthQUFVLEtBQUtKLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEc7Y0FNVkMsR0FBVixFQUFlO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0ssV0FBTCxFQUFyQixDQUFQO0tBTkU7Y0FPVkwsR0FBVixFQUFlO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLRyxTQUFMLENBQWVOLEdBQWYsS0FBdUIsSUFBcEMsQ0FBUDtLQVBFOztXQVNiTyxNQUFQLEVBQWU7YUFBVUMsWUFBYyxJQUFkLEVBQW9CRCxNQUFwQixDQUFQO0tBVEU7YUFVWFAsR0FBVCxFQUFjUyxTQUFPLENBQXJCLEVBQXdCO2FBQVVDLFNBQVNWLE9BQU8sS0FBS0osS0FBckIsRUFBNEJhLE1BQTVCLENBQVA7S0FWUDtlQUFBLEVBQXRCOztRQWFNRSxrQkFBa0JDLE9BQU9DLE1BQVAsQ0FDdEJELE9BQU9FLE1BQVAsQ0FBYyxJQUFkLENBRHNCLEVBRXRCeEIsbUJBRnNCLEVBR3RCO3FCQUNtQjthQUFVLElBQVA7S0FEdEI7aUJBQUE7Z0JBQUE7WUFBQSxFQUlZa0IsV0FKWjtpQkFBQSxFQUhzQixDQUF4Qjs7Z0JBVWNPLFlBQWQsR0FBNkJKLGVBQTdCO1NBQ09BLGVBQVA7O1dBR1NLLGFBQVQsQ0FBdUIsR0FBR0MsSUFBMUIsRUFBZ0M7VUFDeEJDLFVBQVUzQixXQUFhLEdBQUcwQixJQUFoQixDQUFoQjtVQUNNRSxNQUFNQyxZQUFjRixPQUFkLENBQVo7UUFDSXRCLEtBQUosR0FBWXNCLE9BQVo7V0FDT0csU0FBU0YsR0FBVCxDQUFQOzs7V0FHT0UsUUFBVCxDQUFrQixFQUFDQyxJQUFELEVBQU9DLGNBQVAsRUFBdUJDLFVBQXZCLEVBQW1DQyxVQUFuQyxFQUErQzdCLEtBQS9DLEVBQWxCLEVBQXlFO1FBQ25FRyxjQUFjd0IsaUJBQWlCRSxVQUFuQztRQUNHMUIsY0FBY3lCLFVBQWpCLEVBQThCO29CQUNkLElBQWQsQ0FENEI7S0FHOUIsTUFBTUUsVUFBVWQsT0FBT0UsTUFBUCxDQUFnQm5CLGFBQWhCLEVBQStCO3FCQUM5QixFQUFJZ0MsT0FBT0osY0FBWCxFQUQ4QjttQkFFaEMsRUFBSUksT0FBTzVCLFdBQVgsRUFGZ0M7a0JBR2pDLEVBQUk0QixPQUFPSCxVQUFYLEVBSGlDO2FBSXRDLEVBQUlHLE9BQU8vQixLQUFYLEVBSnNDLEVBQS9CLENBQWhCOztXQU1PZ0IsT0FBT0MsTUFBUCxDQUFnQmEsT0FBaEIsRUFBeUJKLElBQXpCLENBQVA7OztXQUVPZCxXQUFULENBQXFCa0IsT0FBckIsRUFBOEIsRUFBQ0UsU0FBRCxFQUFZQyxTQUFaLEVBQTlCLEVBQXNEO1FBQ2pELFFBQVFBLFNBQVgsRUFBdUI7WUFBTyxJQUFJQyxLQUFKLENBQVksb0JBQVosQ0FBTjs7VUFDbEJDLE1BQU12QyxVQUFZa0MsUUFBUTlCLEtBQXBCLEVBQTJCZ0MsU0FBM0IsRUFBc0NDLFNBQXRDLENBQVo7VUFDTUcsVUFBVXBCLE9BQU9FLE1BQVAsQ0FBZ0JZLE9BQWhCLEVBQXlCLEVBQUk5QixPQUFPLEVBQUkrQixPQUFPL0IsS0FBWCxFQUFYLEVBQXpCLENBQWhCO1FBQ0csUUFBUWdDLFNBQVgsRUFBdUI7Y0FBU0EsU0FBUixHQUFvQkEsU0FBcEI7O1FBQ3JCLFFBQVFDLFNBQVgsRUFBdUI7Y0FBU0EsU0FBUixHQUFvQkEsU0FBcEI7O1lBQ2hCSSxNQUFSLEdBQWlCLElBQWpCO1dBQ09ELE9BQVA7OztXQUdPRSxZQUFULENBQXNCQyxPQUF0QixFQUErQjtRQUMxQixDQUFFQSxPQUFMLEVBQWU7Z0JBQVcsRUFBVjs7O1VBRVZDLGdCQUNKLFFBQVFELFFBQVFDLGFBQWhCLEdBQ0ksSUFESixHQUNXLENBQUMsQ0FBRUQsUUFBUUMsYUFGeEI7O1FBSUlDLE1BQUksSUFBUjtRQUFjQyxXQUFXLENBQXpCO1FBQTRCQyxJQUFJLEVBQWhDO1dBQ09DLElBQVA7O2FBRVNBLElBQVQsQ0FBY0MsSUFBZCxFQUFvQkMsV0FBUyxFQUE3QixFQUFpQzthQUN4QkMsU0FBU0YsSUFBVCxDQUFQO1FBQ0VHLElBQUYsQ0FBU0gsSUFBVDtrQkFDWUEsS0FBS0ksVUFBakI7O2FBRU0sQ0FBTixFQUFVO2NBQ0YxQixNQUFNMkIsZ0JBQVo7WUFDR0MsY0FBYzVCLEdBQWpCLEVBQXVCO21CQUNaeUIsSUFBVCxDQUFnQnpCLEdBQWhCO1NBREYsTUFFSyxPQUFPdUIsUUFBUDs7OzthQUdBSSxjQUFULEdBQTBCO1VBQ3JCLFNBQVNULEdBQVosRUFBa0I7WUFDYixNQUFNRSxFQUFFUyxNQUFYLEVBQW9COzs7WUFFakIsSUFBSVQsRUFBRVMsTUFBVCxFQUFrQjtjQUNaLENBQUl2RCxjQUFnQjhDLENBQWhCLEVBQW1CRCxRQUFuQixDQUFKLENBQUo7OztjQUVJbEIsWUFBY21CLEVBQUUsQ0FBRixDQUFkLEVBQW9CSCxhQUFwQixDQUFOO1lBQ0csU0FBU0MsR0FBWixFQUFrQjs7Ozs7WUFFZFksTUFBTVosSUFBSWIsVUFBaEI7VUFDR2MsV0FBV1csR0FBZCxFQUFvQjs7OztVQUdoQkMsUUFBUSxDQUFaO1VBQWVDLElBQUksQ0FBbkI7YUFDTUQsUUFBUUQsR0FBZCxFQUFvQjtpQkFDVFYsRUFBRVksR0FBRixFQUFPTixVQUFoQjs7O1lBRUlPLGdCQUFnQkYsUUFBUUQsR0FBOUI7VUFDRyxNQUFNRyxhQUFULEVBQXlCOztjQUNqQkMsUUFBUWQsRUFBRWUsTUFBRixDQUFTLENBQVQsRUFBWUgsQ0FBWixDQUFkO29CQUNZRixHQUFaOztZQUVJckQsS0FBSixHQUFZSCxjQUFnQjRELEtBQWhCLEVBQXVCSixHQUF2QixDQUFaO09BSkYsTUFNSzs7Y0FDR0ksUUFBUSxNQUFNZCxFQUFFUyxNQUFSLEdBQWlCLEVBQWpCLEdBQXNCVCxFQUFFZSxNQUFGLENBQVMsQ0FBVCxFQUFZSCxJQUFFLENBQWQsQ0FBcEM7Y0FDTUksT0FBT2hCLEVBQUUsQ0FBRixDQUFiOztjQUVNSyxJQUFOLENBQWFXLEtBQUsxRCxLQUFMLENBQVcsQ0FBWCxFQUFjLENBQUN1RCxhQUFmLENBQWI7VUFDRSxDQUFGLElBQU9HLEtBQUsxRCxLQUFMLENBQVcsQ0FBQ3VELGFBQVosQ0FBUDtvQkFDWUgsR0FBWjs7WUFFSXJELEtBQUosR0FBWUgsY0FBZ0I0RCxLQUFoQixFQUF1QkosR0FBdkIsQ0FBWjs7OztjQUdNdkIsVUFBVUwsU0FBU2dCLEdBQVQsQ0FBaEI7Y0FDTSxJQUFOO2VBQ09YLE9BQVA7Ozs7OztBQzdIUjs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQW1CQSxBQUVBLE1BQU04QixZQUFZLE1BQWxCO0FBQ0EsTUFBTWpDLGlCQUFpQixFQUF2QjtBQUNBLE1BQU1rQyxjQUFjLEVBQXBCOztBQUVBLEFBQWUsU0FBU0Msd0JBQVQsQ0FBa0N2QixVQUFRLEVBQTFDLEVBQThDO1NBQ3BEOUMsa0JBQW9CO2VBQUEsRUFDWkUsVUFEWSxFQUNBQyxTQURBO1VBQUEsRUFFakJrQixRQUZpQixFQUVQaUQsU0FGTyxFQUVJakUsV0FGSjs7WUFBQSxFQUlmRCxhQUplLEVBQXBCLENBQVA7O1dBT1MyQixXQUFULENBQXFCcEIsR0FBckIsRUFBMEJvQyxhQUExQixFQUF5QztRQUNwQ2IsaUJBQWlCdkIsSUFBSTZDLFVBQXhCLEVBQXFDO2FBQVEsSUFBUDs7O1VBRWhDZSxNQUFNNUQsSUFBSTZELFlBQUosQ0FBbUIsQ0FBbkIsQ0FBWjtRQUNHTCxjQUFjSSxHQUFqQixFQUF1QjtZQUNmLElBQUk5QixLQUFKLENBQWEsdUNBQXNDOEIsSUFBSUUsUUFBSixDQUFhLEVBQWIsQ0FBaUIsY0FBYU4sVUFBVU0sUUFBVixDQUFtQixFQUFuQixDQUF1QixHQUF4RyxDQUFOOzs7O1VBR0l0QyxhQUFheEIsSUFBSTZELFlBQUosQ0FBbUIsQ0FBbkIsQ0FBbkI7VUFDTXBDLGFBQWF6QixJQUFJNkQsWUFBSixDQUFtQixDQUFuQixDQUFuQjtVQUNNRSxPQUFPL0QsSUFBSWdFLFNBQUosQ0FBZ0IsQ0FBaEIsQ0FBYjs7UUFFSUMsTUFBTWpFLElBQUlnRSxTQUFKLENBQWdCLENBQWhCLENBQVY7UUFDRzVCLGFBQUgsRUFBbUI7WUFDWDhCLEtBQUtDLEdBQUwsQ0FBVyxDQUFYLEVBQWNGLE1BQU0sQ0FBcEIsQ0FBTjtVQUNJRyxVQUFKLENBQWlCSCxHQUFqQixFQUFzQixDQUF0Qjs7O1VBRUlyQyxZQUFZNUIsSUFBSXFFLFdBQUosQ0FBa0IsQ0FBbEIsQ0FBbEI7VUFDTXhDLFlBQVk3QixJQUFJcUUsV0FBSixDQUFrQixFQUFsQixDQUFsQjtVQUNNL0MsT0FBTyxFQUFJeUMsSUFBSixFQUFVRSxHQUFWLEVBQWVyQyxTQUFmLEVBQTBCQyxTQUExQixFQUFiO1dBQ08sRUFBSVAsSUFBSixFQUFVQyxjQUFWLEVBQTBCQyxVQUExQixFQUFzQ0MsVUFBdEMsRUFBUDs7O1dBR09sQyxVQUFULENBQW9CLEdBQUcwQixJQUF2QixFQUE2QjtRQUN2QixFQUFDOEMsSUFBRCxFQUFPRSxHQUFQLEVBQVlyQyxTQUFaLEVBQXVCQyxTQUF2QixFQUFrQ3lDLE1BQWxDLEVBQTBDQyxJQUExQyxLQUNGLE1BQU10RCxLQUFLK0IsTUFBWCxHQUFvQi9CLEtBQUssQ0FBTCxDQUFwQixHQUE4QkwsT0FBT0MsTUFBUCxDQUFnQixFQUFoQixFQUFvQixHQUFHSSxJQUF2QixDQURoQzs7UUFHRyxDQUFFdUQsT0FBT0MsU0FBUCxDQUFpQjdDLFNBQWpCLENBQUwsRUFBbUM7WUFBTyxJQUFJRSxLQUFKLENBQWEsbUJBQWIsQ0FBTjs7UUFDakNELGFBQWEsQ0FBRTJDLE9BQU9DLFNBQVAsQ0FBaUI1QyxTQUFqQixDQUFsQixFQUFnRDtZQUFPLElBQUlDLEtBQUosQ0FBYSxtQkFBYixDQUFOOzthQUN4Q2EsU0FBUzJCLE1BQVQsQ0FBVDtXQUNPM0IsU0FBUzRCLElBQVQsQ0FBUDs7VUFFTS9DLGFBQWFELGlCQUFpQitDLE9BQU96QixVQUF4QixHQUFxQzBCLEtBQUsxQixVQUE3RDtRQUNHckIsYUFBYSxNQUFoQixFQUF5QjtZQUFPLElBQUlNLEtBQUosQ0FBYSxrQkFBYixDQUFOOzs7VUFFcEI0QyxTQUFTQyxPQUFPQyxLQUFQLENBQWVyRCxjQUFmLENBQWY7V0FDT3NELGFBQVAsQ0FBdUJyQixTQUF2QixFQUFrQyxDQUFsQztXQUNPcUIsYUFBUCxDQUF1QnJELFVBQXZCLEVBQW1DLENBQW5DO1dBQ09xRCxhQUFQLENBQXVCUCxPQUFPekIsVUFBOUIsRUFBMEMsQ0FBMUM7V0FDT3VCLFVBQVAsQ0FBb0JMLFFBQVEsQ0FBNUIsRUFBK0IsQ0FBL0I7V0FDT0ssVUFBUCxDQUFvQkgsT0FBT1IsV0FBM0IsRUFBd0MsQ0FBeEM7V0FDT3FCLFlBQVAsQ0FBc0IsSUFBSWxELFNBQTFCLEVBQXFDLENBQXJDO1dBQ09rRCxZQUFQLENBQXNCLElBQUlqRCxTQUExQixFQUFxQyxFQUFyQzs7VUFFTTdCLE1BQU0yRSxPQUFPSSxNQUFQLENBQWdCLENBQUNMLE1BQUQsRUFBU0osTUFBVCxFQUFpQkMsSUFBakIsQ0FBaEIsQ0FBWjtRQUNHL0MsZUFBZXhCLElBQUk2QyxVQUF0QixFQUFtQztZQUMzQixJQUFJZixLQUFKLENBQWEsd0NBQWIsQ0FBTjs7V0FDSzlCLEdBQVA7OztXQUdPUixTQUFULENBQW1CUSxHQUFuQixFQUF3QjRCLFNBQXhCLEVBQW1DQyxTQUFuQyxFQUE4QztVQUN0QyxJQUFJOEMsTUFBSixDQUFXM0UsR0FBWCxDQUFOO1FBQ0csUUFBUTRCLFNBQVgsRUFBdUI7VUFBS2tELFlBQUosQ0FBbUIsSUFBSWxELFNBQXZCLEVBQWtDLENBQWxDOztRQUNyQixRQUFRQyxTQUFYLEVBQXVCO1VBQUtpRCxZQUFKLENBQW1CLElBQUlqRCxTQUF2QixFQUFrQyxFQUFsQzs7V0FDakI3QixHQUFQOzs7V0FHT2dGLE1BQVQsQ0FBZ0JDLEVBQWhCLEVBQW9CeEUsTUFBcEIsRUFBNEI7VUFDcEJULE1BQU0yRSxPQUFPQyxLQUFQLENBQWEsQ0FBYixDQUFaO1FBQ0lFLFlBQUosQ0FBbUIsSUFBSUcsRUFBdkIsRUFBMkJ4RSxVQUFRLENBQW5DO1dBQ09ULEdBQVA7O1dBQ09VLFFBQVQsQ0FBa0JWLEdBQWxCLEVBQXVCUyxNQUF2QixFQUErQjtXQUN0QlQsSUFBSXFFLFdBQUosQ0FBa0I1RCxVQUFRLENBQTFCLENBQVA7OztXQUVPa0QsU0FBVCxDQUFtQnVCLEdBQW5CLEVBQXdCO1dBQ2ZQLE9BQU9RLElBQVAsQ0FBWUQsR0FBWixFQUFpQixPQUFqQixDQUFQOztXQUNPeEYsV0FBVCxDQUFxQk0sR0FBckIsRUFBMEI7V0FDakIyQyxTQUFTM0MsR0FBVCxFQUFjOEQsUUFBZCxDQUF1QixPQUF2QixDQUFQOzs7V0FHT25CLFFBQVQsQ0FBa0IzQyxHQUFsQixFQUF1QjtRQUNsQixTQUFTQSxHQUFULElBQWdCK0MsY0FBYy9DLEdBQWpDLEVBQXVDO2FBQzlCMkUsT0FBTyxDQUFQLENBQVA7OztRQUVDQSxPQUFPUyxRQUFQLENBQWdCcEYsR0FBaEIsQ0FBSCxFQUEwQjthQUNqQkEsR0FBUDs7O1FBRUMsYUFBYSxPQUFPQSxHQUF2QixFQUE2QjthQUNwQjJELFVBQVUzRCxHQUFWLENBQVA7OztRQUVDK0MsY0FBYy9DLElBQUk2QyxVQUFyQixFQUFrQztVQUM3QndDLFlBQVlDLE1BQVosQ0FBbUJ0RixHQUFuQixDQUFILEVBQTZCO2VBQ3BCMkUsT0FBT1EsSUFBUCxDQUFjbkYsSUFBSXVGLE1BQWxCO1NBQVA7T0FERixNQUVLO2VBQ0laLE9BQU9RLElBQVAsQ0FBY25GLEdBQWQ7U0FBUDs7OztRQUVEd0YsTUFBTUMsT0FBTixDQUFjekYsR0FBZCxDQUFILEVBQXdCO1VBQ25Cd0UsT0FBT0MsU0FBUCxDQUFtQnpFLElBQUksQ0FBSixDQUFuQixDQUFILEVBQStCO2VBQ3RCMkUsT0FBT1EsSUFBUCxDQUFZbkYsR0FBWixDQUFQOzthQUNLMkUsT0FBT0ksTUFBUCxDQUFnQi9FLElBQUkwRixHQUFKLENBQVUvQyxRQUFWLENBQWhCLENBQVA7Ozs7V0FHS2xELGFBQVQsQ0FBdUJrRyxHQUF2QixFQUE0QjFDLEdBQTVCLEVBQWlDO1FBQzVCLE1BQU0wQyxJQUFJM0MsTUFBYixFQUFzQjthQUFRMkMsSUFBSSxDQUFKLENBQVA7O1FBQ3BCLE1BQU1BLElBQUkzQyxNQUFiLEVBQXNCO2FBQVEyQixPQUFPLENBQVAsQ0FBUDs7V0FDaEJBLE9BQU9JLE1BQVAsQ0FBY1ksR0FBZCxDQUFQOzs7O0FDaElKOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBbUJBLEFBRUEsTUFBTW5DLGNBQVksTUFBbEI7QUFDQSxNQUFNakMsbUJBQWlCLEVBQXZCO0FBQ0EsTUFBTWtDLGdCQUFjLEVBQXBCOztBQUVBLE1BQU1tQyxnQkFBZ0IsSUFBdEI7O0FBRUEsQUFBZSxTQUFTQywwQkFBVCxDQUFvQzFELFVBQVEsRUFBNUMsRUFBZ0Q7UUFDdkQyRCxnQkFBZ0IzRCxRQUFRNEQsV0FBUixJQUF1QkEsV0FBN0M7UUFDTUMsZ0JBQWdCN0QsUUFBUThELFdBQVIsSUFBdUJBLFdBQTdDOztTQUVPNUcsa0JBQW9CO2VBQUEsRUFDWkUsVUFEWSxFQUNBQyxTQURBO1VBQUEsRUFFakJrQixRQUZpQixFQUVQaUQsU0FGTyxFQUVJakUsV0FGSjs7WUFBQSxFQUlmRCxhQUplLEVBQXBCLENBQVA7O1dBT1MyQixXQUFULENBQXFCcEIsR0FBckIsRUFBMEJvQyxhQUExQixFQUF5QztRQUNwQ2IsbUJBQWlCdkIsSUFBSTZDLFVBQXhCLEVBQXFDO2FBQVEsSUFBUDs7O1VBRWhDcUQsS0FBSyxJQUFJQyxRQUFKLENBQWVuRyxHQUFmLENBQVg7O1VBRU00RCxNQUFNc0MsR0FBR0UsU0FBSCxDQUFlLENBQWYsRUFBa0JSLGFBQWxCLENBQVo7UUFDR3BDLGdCQUFjSSxHQUFqQixFQUF1QjtZQUNmLElBQUk5QixLQUFKLENBQWEsdUNBQXNDOEIsSUFBSUUsUUFBSixDQUFhLEVBQWIsQ0FBaUIsY0FBYU4sWUFBVU0sUUFBVixDQUFtQixFQUFuQixDQUF1QixHQUF4RyxDQUFOOzs7O1VBR0l0QyxhQUFhMEUsR0FBR0UsU0FBSCxDQUFlLENBQWYsRUFBa0JSLGFBQWxCLENBQW5CO1VBQ01uRSxhQUFheUUsR0FBR0UsU0FBSCxDQUFlLENBQWYsRUFBa0JSLGFBQWxCLENBQW5CO1VBQ003QixPQUFPbUMsR0FBR0csUUFBSCxDQUFjLENBQWQsRUFBaUJULGFBQWpCLENBQWI7O1FBRUkzQixNQUFNaUMsR0FBR0csUUFBSCxDQUFjLENBQWQsRUFBaUJULGFBQWpCLENBQVY7UUFDR3hELGFBQUgsRUFBbUI7WUFDWDhCLEtBQUtDLEdBQUwsQ0FBVyxDQUFYLEVBQWNGLE1BQU0sQ0FBcEIsQ0FBTjtTQUNHcUMsUUFBSCxDQUFjLENBQWQsRUFBaUJyQyxHQUFqQixFQUFzQjJCLGFBQXRCOzs7VUFFSWhFLFlBQVlzRSxHQUFHSyxRQUFILENBQWMsQ0FBZCxFQUFpQlgsYUFBakIsQ0FBbEI7VUFDTS9ELFlBQVlxRSxHQUFHSyxRQUFILENBQWMsRUFBZCxFQUFrQlgsYUFBbEIsQ0FBbEI7VUFDTXRFLE9BQU8sRUFBSXlDLElBQUosRUFBVUUsR0FBVixFQUFlckMsU0FBZixFQUEwQkMsU0FBMUIsRUFBYjtXQUNPLEVBQUlQLElBQUosa0JBQVVDLGdCQUFWLEVBQTBCQyxVQUExQixFQUFzQ0MsVUFBdEMsRUFBUDs7O1dBR09sQyxVQUFULENBQW9CLEdBQUcwQixJQUF2QixFQUE2QjtRQUN2QixFQUFDOEMsSUFBRCxFQUFPRSxHQUFQLEVBQVlyQyxTQUFaLEVBQXVCQyxTQUF2QixFQUFrQ3lDLE1BQWxDLEVBQTBDQyxJQUExQyxLQUNGLE1BQU10RCxLQUFLK0IsTUFBWCxHQUFvQi9CLEtBQUssQ0FBTCxDQUFwQixHQUE4QkwsT0FBT0MsTUFBUCxDQUFnQixFQUFoQixFQUFvQixHQUFHSSxJQUF2QixDQURoQzs7UUFHRyxDQUFFdUQsT0FBT0MsU0FBUCxDQUFpQjdDLFNBQWpCLENBQUwsRUFBbUM7WUFBTyxJQUFJRSxLQUFKLENBQWEsbUJBQWIsQ0FBTjs7UUFDakNELGFBQWEsQ0FBRTJDLE9BQU9DLFNBQVAsQ0FBaUI1QyxTQUFqQixDQUFsQixFQUFnRDtZQUFPLElBQUlDLEtBQUosQ0FBYSxtQkFBYixDQUFOOzthQUN4Q2EsU0FBUzJCLE1BQVQsRUFBaUIsUUFBakIsQ0FBVDtXQUNPM0IsU0FBUzRCLElBQVQsRUFBZSxNQUFmLENBQVA7O1VBRU10QixNQUFNMUIsbUJBQWlCK0MsT0FBT3pCLFVBQXhCLEdBQXFDMEIsS0FBSzFCLFVBQXREO1FBQ0dJLE1BQU0sTUFBVCxFQUFrQjtZQUFPLElBQUluQixLQUFKLENBQWEsa0JBQWIsQ0FBTjs7O1VBRWI0QyxTQUFTLElBQUlXLFdBQUosQ0FBZ0JwQyxHQUFoQixDQUFmO1VBQ01pRCxLQUFLLElBQUlDLFFBQUosQ0FBZXpCLE1BQWYsRUFBdUIsQ0FBdkIsRUFBMEJuRCxnQkFBMUIsQ0FBWDtPQUNHaUYsU0FBSCxDQUFnQixDQUFoQixFQUFtQmhELFdBQW5CLEVBQThCb0MsYUFBOUI7T0FDR1ksU0FBSCxDQUFnQixDQUFoQixFQUFtQnZELEdBQW5CLEVBQXdCMkMsYUFBeEI7T0FDR1ksU0FBSCxDQUFnQixDQUFoQixFQUFtQmxDLE9BQU96QixVQUExQixFQUFzQytDLGFBQXRDO09BQ0dVLFFBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUJ2QyxRQUFRLENBQTNCLEVBQThCNkIsYUFBOUI7T0FDR1UsUUFBSCxDQUFnQixDQUFoQixFQUFtQnJDLE9BQU9SLGFBQTFCLEVBQXVDbUMsYUFBdkM7T0FDR2EsUUFBSCxDQUFnQixDQUFoQixFQUFtQixJQUFJN0UsU0FBdkIsRUFBa0NnRSxhQUFsQztPQUNHYSxRQUFILENBQWUsRUFBZixFQUFtQixJQUFJNUUsU0FBdkIsRUFBa0MrRCxhQUFsQzs7VUFFTWMsS0FBSyxJQUFJQyxVQUFKLENBQWVqQyxNQUFmLENBQVg7T0FDR2tDLEdBQUgsQ0FBUyxJQUFJRCxVQUFKLENBQWVyQyxNQUFmLENBQVQsRUFBaUMvQyxnQkFBakM7T0FDR3FGLEdBQUgsQ0FBUyxJQUFJRCxVQUFKLENBQWVwQyxJQUFmLENBQVQsRUFBK0JoRCxtQkFBaUIrQyxPQUFPekIsVUFBdkQ7V0FDT2dFLEtBQVA7OztXQUdPckgsU0FBVCxDQUFtQlEsR0FBbkIsRUFBd0I0QixTQUF4QixFQUFtQ0MsU0FBbkMsRUFBOEM7VUFDdEMsSUFBSThFLFVBQUosQ0FBZTNHLEdBQWYsRUFBb0J1RixNQUExQjtVQUNNVyxLQUFLLElBQUlDLFFBQUosQ0FBZW5HLEdBQWYsRUFBb0IsQ0FBcEIsRUFBdUJ1QixnQkFBdkIsQ0FBWDtRQUNHLFFBQVFLLFNBQVgsRUFBdUI7U0FBSTZFLFFBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUIsSUFBSTdFLFNBQXZCLEVBQWtDZ0UsYUFBbEM7O1FBQ3JCLFFBQVEvRCxTQUFYLEVBQXVCO1NBQUk0RSxRQUFILENBQWUsRUFBZixFQUFtQixJQUFJNUUsU0FBdkIsRUFBa0MrRCxhQUFsQzs7V0FDakI1RixHQUFQOzs7V0FHT2dGLE1BQVQsQ0FBZ0JDLEVBQWhCLEVBQW9CeEUsTUFBcEIsRUFBNEI7VUFDcEJULE1BQU0sSUFBSXFGLFdBQUosQ0FBZ0IsQ0FBaEIsQ0FBWjtRQUNJYyxRQUFKLENBQWFuRyxHQUFiLEVBQWtCeUcsUUFBbEIsQ0FBNkJoRyxVQUFRLENBQXJDLEVBQXdDLElBQUl3RSxFQUE1QyxFQUFnRFcsYUFBaEQ7V0FDTzVGLEdBQVA7O1dBQ09VLFFBQVQsQ0FBa0JWLEdBQWxCLEVBQXVCUyxNQUF2QixFQUErQjtVQUN2QnlGLEtBQUssSUFBSUMsUUFBSixDQUFleEQsU0FBUzNDLEdBQVQsQ0FBZixDQUFYO1dBQ09rRyxHQUFHSyxRQUFILENBQWM5RixVQUFRLENBQXRCLEVBQXlCbUYsYUFBekIsQ0FBUDs7O1dBRU9qQyxTQUFULENBQW1CdUIsR0FBbkIsRUFBd0I7VUFDaEI0QixLQUFLLElBQUloQixhQUFKLENBQWtCLE9BQWxCLENBQVg7V0FDT2dCLEdBQUdDLE1BQUgsQ0FBVTdCLElBQUlwQixRQUFKLEVBQVYsRUFBMEJ5QixNQUFqQzs7V0FDTzdGLFdBQVQsQ0FBcUJNLEdBQXJCLEVBQTBCO1VBQ2xCZ0gsS0FBSyxJQUFJaEIsYUFBSixDQUFrQixPQUFsQixDQUFYO1dBQ09nQixHQUFHQyxNQUFILENBQVl0RSxTQUFXM0MsR0FBWCxDQUFaLENBQVA7OztXQUdPMkMsUUFBVCxDQUFrQjNDLEdBQWxCLEVBQXVCO1FBQ2xCLFNBQVNBLEdBQVQsSUFBZ0IrQyxjQUFjL0MsR0FBakMsRUFBdUM7YUFDOUIsSUFBSXFGLFdBQUosQ0FBZ0IsQ0FBaEIsQ0FBUDs7O1FBRUN0QyxjQUFjL0MsSUFBSTZDLFVBQXJCLEVBQWtDO1VBQzdCRSxjQUFjL0MsSUFBSXVGLE1BQXJCLEVBQThCO2VBQ3JCdkYsR0FBUDs7O1VBRUNxRixZQUFZQyxNQUFaLENBQW1CdEYsR0FBbkIsQ0FBSCxFQUE2QjtlQUNwQkEsSUFBSXVGLE1BQVg7OztVQUVDLGVBQWUsT0FBT3ZGLElBQUlxRSxXQUE3QixFQUEyQztlQUNsQ3NDLFdBQVd4QixJQUFYLENBQWdCbkYsR0FBaEIsRUFBcUJ1RixNQUE1QixDQUR5QztPQUczQyxPQUFPdkYsR0FBUDs7O1FBRUMsYUFBYSxPQUFPQSxHQUF2QixFQUE2QjthQUNwQjJELFVBQVUzRCxHQUFWLENBQVA7OztRQUVDd0YsTUFBTUMsT0FBTixDQUFjekYsR0FBZCxDQUFILEVBQXdCO1VBQ25Cd0UsT0FBT0MsU0FBUCxDQUFtQnpFLElBQUksQ0FBSixDQUFuQixDQUFILEVBQStCO2VBQ3RCMkcsV0FBV3hCLElBQVgsQ0FBZ0JuRixHQUFoQixFQUFxQnVGLE1BQTVCOzthQUNLUixPQUFTL0UsSUFBSTBGLEdBQUosQ0FBVS9DLFFBQVYsQ0FBVCxDQUFQOzs7O1dBR0tsRCxhQUFULENBQXVCa0csR0FBdkIsRUFBNEIxQyxHQUE1QixFQUFpQztRQUM1QixNQUFNMEMsSUFBSTNDLE1BQWIsRUFBc0I7YUFBUTJDLElBQUksQ0FBSixDQUFQOztRQUNwQixNQUFNQSxJQUFJM0MsTUFBYixFQUFzQjthQUFRLElBQUlxQyxXQUFKLENBQWdCLENBQWhCLENBQVA7OztRQUVwQixRQUFRcEMsR0FBWCxFQUFpQjtZQUNULENBQU47V0FDSSxNQUFNaUUsR0FBVixJQUFpQnZCLEdBQWpCLEVBQXVCO2VBQ2R1QixJQUFJckUsVUFBWDs7OztVQUVFNkQsS0FBSyxJQUFJQyxVQUFKLENBQWUxRCxHQUFmLENBQVg7UUFDSXhDLFNBQVMsQ0FBYjtTQUNJLE1BQU15RyxHQUFWLElBQWlCdkIsR0FBakIsRUFBdUI7U0FDbEJpQixHQUFILENBQVMsSUFBSUQsVUFBSixDQUFlTyxHQUFmLENBQVQsRUFBOEJ6RyxNQUE5QjtnQkFDVXlHLElBQUlyRSxVQUFkOztXQUNLNkQsR0FBR25CLE1BQVY7Ozs7QUN0SlcsU0FBUzRCLGtCQUFULENBQTRCLEdBQUdsRyxJQUEvQixFQUFxQztTQUMzQ3lDLHlCQUF5QixHQUFHekMsSUFBNUIsQ0FBUDs7O0FBRUZMLE9BQU9DLE1BQVAsQ0FBZ0JzRyxrQkFBaEIsRUFBb0M7bUJBQUE7MEJBQUE7NEJBQUEsRUFBcEM7Ozs7In0=
