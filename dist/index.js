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

  function packPacket(...args) {
    let { type, ttl, id_router, id_target, header, body } = 1 === args.length ? args[0] : Object.assign({}, ...args);

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL2NvZGUvYmFzaWMuanMiLCIuLi9jb2RlL2J1ZmZlci5qcyIsIi4uL2NvZGUvZGF0YXZpZXcuanMiLCIuLi9jb2RlL2luZGV4LmNqcy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQHt9XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICBmd2RfdG8oZndkX2lkKSA6OiByZXR1cm4gYXNGd2RQa3RPYmogQCB0aGlzLCBmd2RfaWRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrUGFja2V0T2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzUGt0T2JqLCBhc0Z3ZFBrdE9ialxuICAgICAgcGt0X29ial9wcm90b1xuXG4gIHBrdF9vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXRPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBwa3RfcmF3ID0gcGFja1BhY2tldCBAIC4uLmFyZ3NcbiAgICBjb25zdCBwa3QgPSBwYXJzZUhlYWRlciBAIHBrdF9yYXdcbiAgICBwa3QuX3Jhd18gPSBwa3RfcmF3XG4gICAgcmV0dXJuIGFzUGt0T2JqKHBrdClcblxuXG4gIGZ1bmN0aW9uIGFzUGt0T2JqKHtpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgX3Jhd199KSA6OlxuICAgIGxldCBib2R5X29mZnNldCA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyX2xlblxuICAgIGlmIGJvZHlfb2Zmc2V0ID4gcGFja2V0X2xlbiA6OlxuICAgICAgYm9keV9vZmZzZXQgPSBudWxsIC8vIGludmFsaWQgcGFja2V0IGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgcGt0X29iaiA9IE9iamVjdC5jcmVhdGUgQCBwa3Rfb2JqX3Byb3RvLCBAe31cbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIHBrdF9vYmosIGluZm9cblxuICBmdW5jdGlvbiBhc0Z3ZFBrdE9iaihwa3Rfb2JqLCB7aWRfcm91dGVyLCBpZF90YXJnZXR9KSA6OlxuICAgIGlmIG51bGwgPT0gaWRfdGFyZ2V0IDo6IHRocm93IG5ldyBFcnJvciBAICdpZF90YXJnZXQgcmVxdWlyZWQnXG4gICAgY29uc3QgcmF3ID0gZndkSGVhZGVyIEAgcGt0X29iai5fcmF3XywgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICBjb25zdCBmd2Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmosIEB7fSBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGZ3ZF9vYmouaWRfcm91dGVyID0gaWRfcm91dGVyXG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogZndkX29iai5pZF90YXJnZXQgPSBpZF90YXJnZXRcbiAgICBmd2Rfb2JqLmlzX2Z3ZCA9IHRydWVcbiAgICByZXR1cm4gZndkX29ialxuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgcGt0ID0gcGFyc2VUaXBQYWNrZXQoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IHBrdCA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBwa3RcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBQYWNrZXQoKSA6OlxuICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6XG4gICAgICAgIGlmIDAgPT09IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcmV0dXJuXG4gICAgICAgIGlmIDEgPCBxLmxlbmd0aCA6OlxuICAgICAgICAgIHEgPSBAW10gY29uY2F0QnVmZmVycyBAIHEsIHFCeXRlTGVuXG5cbiAgICAgICAgdGlwID0gcGFyc2VIZWFkZXIgQCBxWzBdLCBkZWNyZW1lbnRfdHRsXG4gICAgICAgIGlmIG51bGwgPT09IHRpcCA6OiByZXR1cm5cblxuICAgICAgY29uc3QgbGVuID0gdGlwLnBhY2tldF9sZW5cbiAgICAgIGlmIHFCeXRlTGVuIDwgbGVuIDo6XG4gICAgICAgIHJldHVyblxuXG4gICAgICBsZXQgYnl0ZXMgPSAwLCBuID0gMFxuICAgICAgd2hpbGUgYnl0ZXMgPCBsZW4gOjpcbiAgICAgICAgYnl0ZXMgKz0gcVtuKytdLmJ5dGVMZW5ndGhcblxuICAgICAgY29uc3QgdHJhaWxpbmdCeXRlcyA9IGJ5dGVzIC0gbGVuXG4gICAgICBpZiAwID09PSB0cmFpbGluZ0J5dGVzIDo6IC8vIHdlIGhhdmUgYW4gZXhhY3QgbGVuZ3RoIG1hdGNoXG4gICAgICAgIGNvbnN0IHBhcnRzID0gcS5zcGxpY2UoMCwgbilcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgZWxzZSA6OiAvLyB3ZSBoYXZlIHRyYWlsaW5nIGJ5dGVzIG9uIHRoZSBsYXN0IGFycmF5XG4gICAgICAgIGNvbnN0IHBhcnRzID0gMSA9PT0gcS5sZW5ndGggPyBbXSA6IHEuc3BsaWNlKDAsIG4tMSlcbiAgICAgICAgY29uc3QgdGFpbCA9IHFbMF1cblxuICAgICAgICBwYXJ0cy5wdXNoIEAgdGFpbC5zbGljZSgwLCAtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcVswXSA9IHRhaWwuc2xpY2UoLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIDo6XG4gICAgICAgIGNvbnN0IHBrdF9vYmogPSBhc1BrdE9iaih0aXApXG4gICAgICAgIHRpcCA9IG51bGxcbiAgICAgICAgcmV0dXJuIHBrdF9vYmpcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja1BhY2tldCwgZndkSGVhZGVyXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBzaWcgPSBidWYucmVhZFVJbnQxNkxFIEAgMFxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgMlxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBidWYucmVhZFVJbnQxNkxFIEAgNFxuICAgIGNvbnN0IHR5cGUgPSBidWYucmVhZFVJbnQ4IEAgNlxuXG4gICAgbGV0IHR0bCA9IGJ1Zi5yZWFkVUludDggQCA3XG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBidWYud3JpdGVVSW50OCBAIHR0bCwgN1xuXG4gICAgY29uc3QgaWRfcm91dGVyID0gYnVmLnJlYWRJbnQzMkxFIEAgOFxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGJ1Zi5yZWFkSW50MzJMRSBAIDEyXG4gICAgY29uc3QgaW5mbyA9IEB7fSB0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0XG4gICAgcmV0dXJuIEB7fSBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldCguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9XG4gICAgICAxID09PSBhcmdzLmxlbmd0aCA/IGFyZ3NbMF0gOiBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcblxuICAgIGlmIE51bWJlci5pc05hTigraWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmIE51bWJlci5pc05hTigraWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5KVxuXG4gICAgY29uc3QgcGFja2V0X2xlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBwYWNrZXRfbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgcGt0aGRyID0gQnVmZmVyLmFsbG9jIEAgcGt0X2hlYWRlcl9sZW5cbiAgICBwa3RoZHIud3JpdGVVSW50MTZMRSBAIHNpZ25hdHVyZSwgMFxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgcGFja2V0X2xlbiwgMlxuICAgIHBrdGhkci53cml0ZVVJbnQxNkxFIEAgaGVhZGVyLmJ5dGVMZW5ndGgsIDRcbiAgICBwa3RoZHIud3JpdGVVSW50OCBAIHR5cGUgfHwgMCwgNlxuICAgIHBrdGhkci53cml0ZVVJbnQ4IEAgdHRsIHx8IGRlZmF1bHRfdHRsLCA3XG4gICAgcGt0aGRyLndyaXRlSW50MzJMRSBAIDAgfCBpZF9yb3V0ZXIsIDhcbiAgICBwa3RoZHIud3JpdGVJbnQzMkxFIEAgMCB8IGlkX3RhcmdldCwgMTJcblxuICAgIGNvbnN0IGJ1ZiA9IEJ1ZmZlci5jb25jYXQgQCMgcGt0aGRyLCBoZWFkZXIsIGJvZHlcbiAgICBpZiBwYWNrZXRfbGVuICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBsZW5ndGggbWlzbWF0Y2ggKGxpYnJhcnkgZXJyb3IpYFxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBCdWZmZXIoYnVmKVxuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGJ1Zi53cml0ZUludDMyTEUgQCAwIHwgaWRfcm91dGVyLCA4XG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZF90YXJnZXQsIDEyXG4gICAgcmV0dXJuIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gQnVmZmVyLmFsbG9jKDQpXG4gICAgYnVmLndyaXRlSW50MzJMRSBAIDAgfCBpZCwgb2Zmc2V0fHwwXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICByZXR1cm4gYnVmLnJlYWRJbnQzMkxFIEAgb2Zmc2V0fHwwXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oc3RyLCAndXRmLTgnKVxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgcmV0dXJuIGFzQnVmZmVyKGJ1ZikudG9TdHJpbmcoJ3V0Zi04JylcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBCdWZmZXIoMClcblxuICAgIGlmIEJ1ZmZlci5pc0J1ZmZlcihidWYpIDo6XG4gICAgICByZXR1cm4gYnVmXG5cbiAgICBpZiAnc3RyaW5nJyA9PT0gdHlwZW9mIGJ1ZiA6OlxuICAgICAgcmV0dXJuIHBhY2tfdXRmOChidWYpXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20gQCBidWYuYnVmZmVyIC8vIERhdGFWaWV3XG4gICAgICBlbHNlIDo6XG4gICAgICAgIHJldHVybiBCdWZmZXIuZnJvbSBAIGJ1ZiAvLyBUeXBlZEFycmF5IG9yIEFycmF5QnVmZmVyXG5cbiAgICBpZiBBcnJheS5pc0FycmF5KGJ1ZikgOjpcbiAgICAgIGlmIE51bWJlci5pc0ludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIEJ1ZmZlci5mcm9tKGJ1ZilcbiAgICAgIHJldHVybiBCdWZmZXIuY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIEJ1ZmZlcigwKVxuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KGxzdClcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldEludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGR2LmdldEludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID1cbiAgICAgIDEgPT09IGFyZ3MubGVuZ3RoID8gYXJnc1swXSA6IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuXG4gICAgaWYgTnVtYmVyLmlzTmFOKCtpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgTnVtYmVyLmlzTmFOKCtpZF90YXJnZXQpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3RhcmdldGBcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIsICdoZWFkZXInKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5LCAnYm9keScpXG5cbiAgICBjb25zdCBsZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgcGt0aGRyID0gbmV3IEFycmF5QnVmZmVyKGxlbilcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIHBrdGhkciwgMCwgcGt0X2hlYWRlcl9sZW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShwa3RoZHIpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9sZW5cbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBwa3RoZHJcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBVaW50OEFycmF5KGJ1ZikuYnVmZmVyXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWYsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIiwiaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5pbXBvcnQgY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyIGZyb20gJy4vYnVmZmVyJ1xuaW1wb3J0IGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIGZyb20gJy4vZGF0YXZpZXcnXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZVBhY2tldFBhcnNlciguLi5hcmdzKSA6OlxuICByZXR1cm4gY3JlYXRlQnVmZmVyUGFja2V0UGFyc2VyKC4uLmFyZ3MpXG5cbk9iamVjdC5hc3NpZ24gQCBjcmVhdGVQYWNrZXRQYXJzZXIsIEB7fVxuICBhc1BhY2tldFBhcnNlckFQSVxuICBjcmVhdGVCdWZmZXJQYWNrZXRQYXJzZXJcbiAgY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInBhY2tQYWNrZXQiLCJmd2RIZWFkZXIiLCJjb25jYXRCdWZmZXJzIiwidW5wYWNrX3V0ZjgiLCJwa3Rfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4IiwiZndkX2lkIiwiYXNGd2RQa3RPYmoiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tldFBhcnNlciIsInBhY2tQYWNrZXRPYmoiLCJhcmdzIiwicGt0X3JhdyIsInBrdCIsInBhcnNlSGVhZGVyIiwiYXNQa3RPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBrdF9vYmoiLCJ2YWx1ZSIsImlkX3JvdXRlciIsImlkX3RhcmdldCIsIkVycm9yIiwicmF3IiwiZndkX29iaiIsImlzX2Z3ZCIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcFBhY2tldCIsInVuZGVmaW5lZCIsImxlbmd0aCIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImNyZWF0ZUJ1ZmZlclBhY2tldFBhcnNlciIsInBhY2tfdXRmOCIsInNpZyIsInJlYWRVSW50MTZMRSIsInRvU3RyaW5nIiwidHlwZSIsInJlYWRVSW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJ3cml0ZVVJbnQ4IiwicmVhZEludDMyTEUiLCJoZWFkZXIiLCJib2R5IiwiTnVtYmVyIiwiaXNOYU4iLCJwa3RoZHIiLCJCdWZmZXIiLCJhbGxvYyIsIndyaXRlVUludDE2TEUiLCJ3cml0ZUludDMyTEUiLCJjb25jYXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsImZyb20iLCJpc0J1ZmZlciIsIkFycmF5QnVmZmVyIiwiaXNWaWV3IiwiYnVmZmVyIiwiQXJyYXkiLCJpc0FycmF5IiwiaXNJbnRlZ2VyIiwibWFwIiwibHN0IiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwiZHYiLCJEYXRhVmlldyIsImdldFVpbnQxNiIsImdldFVpbnQ4Iiwic2V0VWludDgiLCJnZXRJbnQzMiIsInNldFVpbnQxNiIsInNldEludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwidGUiLCJlbmNvZGUiLCJ0ZCIsImRlY29kZSIsImFyciIsImNyZWF0ZVBhY2tldFBhcnNlciJdLCJtYXBwaW5ncyI6Ijs7QUFDZSxTQUFTQSxpQkFBVCxDQUEyQkMsbUJBQTNCLEVBQWdEO1FBQ3ZE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
