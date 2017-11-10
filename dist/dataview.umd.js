(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define(factory) :
	(global['msg-fabric-packet-stream'] = factory());
}(this, (function () { 'use strict';

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

const little_endian = true;

function createDataViewPacketParser(options = {}) {
  const _TextEncoder_ = options.TextEncoder || TextEncoder;
  const _TextDecoder_ = options.TextDecoder || TextDecoder;

  return asPacketParserAPI({
    parseHeader, packPacket,
    packId, unpackId, pack_utf8, unpack_utf8,

    asBuffer, concatBuffers });

  function parseHeader(buf, decrement_ttl) {
    if (pkt_header_len > buf.byteLength) {
      return null;
    }

    const dv = new DataView(buf);

    const sig = dv.getUint16(0, little_endian);
    if (signature !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`);
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
    header = asBuffer(header, 'header');
    body = asBuffer(body, 'body');

    const len = pkt_header_len + header.byteLength + body.byteLength;
    if (len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const array = new ArrayBuffer(len);

    const dv = new DataView(array, 0, pkt_header_len);
    dv.setUint16(0, signature, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl, little_endian);
    dv.setInt32(8, 0 | id_router, little_endian);
    dv.setInt32(12, 0 | id_target, little_endian);

    const u8 = new Uint8Array(array);
    u8.set(new Uint8Array(header), pkt_header_len);
    u8.set(new Uint8Array(body), pkt_header_len + header.byteLength);
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

return createDataViewPacketParser;

})));
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja1BhY2tldFxuICAgIGFzQnVmZmVyXG4gICAgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQDpcbiAgICBoZWFkZXJfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmhlYWRlcl9vZmZzZXQsIHRoaXMuYm9keV9vZmZzZXRcbiAgICBoZWFkZXJfdXRmOChidWYpIDo6IHJldHVybiB1bnBhY2tfdXRmOCBAIGJ1ZiB8fCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KGJ1ZikgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5ib2R5X2J1ZmZlcigpXG4gICAgYm9keV9qc29uKGJ1ZikgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmJvZHlfdXRmOChidWYpIHx8IG51bGxcblxuICAgIHVucGFja0lkKGJ1Ziwgb2Zmc2V0PTgpIDo6IHJldHVybiB1bnBhY2tJZChidWYgfHwgdGhpcy5fcmF3Xywgb2Zmc2V0KVxuICAgIHVucGFja191dGY4XG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIGlzUGFja2V0UGFyc2VyKCkgOjogcmV0dXJuIHRydWVcbiAgICAgIHBhY2tQYWNrZXRPYmpcbiAgICAgIHBhY2tldFN0cmVhbVxuICAgICAgYXNQa3RPYmpcbiAgICAgIHBrdF9vYmpfcHJvdG9cblxuICBwa3Rfb2JqX3Byb3RvLnBhY2tldFBhcnNlciA9IHBhY2tldFBhcnNlckFQSVxuICByZXR1cm4gcGFja2V0UGFyc2VyQVBJXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0T2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgcGt0X3JhdyA9IHBhY2tQYWNrZXQgQCAuLi5hcmdzXG4gICAgY29uc3QgcGt0ID0gcGFyc2VIZWFkZXIgQCBwa3RfcmF3XG4gICAgcGt0Ll9yYXdfID0gcGt0X3Jhd1xuICAgIHJldHVybiBhc1BrdE9iaihwa3QpXG5cblxuICBmdW5jdGlvbiBhc1BrdE9iaih7aW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW4sIF9yYXdffSkgOjpcbiAgICBsZXQgYm9keV9vZmZzZXQgPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlcl9sZW5cbiAgICBpZiBib2R5X29mZnNldCA+IHBhY2tldF9sZW4gOjpcbiAgICAgIGJvZHlfb2Zmc2V0ID0gbnVsbCAvLyBpbnZhbGlkIHBhY2tldCBjb25zdHJ1Y3Rpb25cblxuICAgIGNvbnN0IHBrdF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29ial9wcm90bywgQDpcbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIHBrdF9vYmosIGluZm9cblxuXG4gIGZ1bmN0aW9uIHBhY2tldFN0cmVhbShvcHRpb25zKSA6OlxuICAgIGlmICEgb3B0aW9ucyA6OiBvcHRpb25zID0ge31cblxuICAgIGNvbnN0IGRlY3JlbWVudF90dGwgPVxuICAgICAgbnVsbCA9PSBvcHRpb25zLmRlY3JlbWVudF90dGxcbiAgICAgICAgPyB0cnVlIDogISEgb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG5cbiAgICBsZXQgdGlwPW51bGwsIHFCeXRlTGVuID0gMCwgcSA9IFtdXG4gICAgcmV0dXJuIGZlZWRcblxuICAgIGZ1bmN0aW9uIGZlZWQoZGF0YSwgY29tcGxldGU9W10pIDo6XG4gICAgICBkYXRhID0gYXNCdWZmZXIoZGF0YSlcbiAgICAgIHEucHVzaCBAIGRhdGFcbiAgICAgIHFCeXRlTGVuICs9IGRhdGEuYnl0ZUxlbmd0aFxuXG4gICAgICB3aGlsZSAxIDo6XG4gICAgICAgIGNvbnN0IHBrdCA9IHBhcnNlVGlwUGFja2V0KClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBwa3QgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgcGt0XG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwUGFja2V0KCkgOjpcbiAgICAgIGlmIG51bGwgPT09IHRpcCA6OlxuICAgICAgICBpZiAwID09PSBxLmxlbmd0aCA6OlxuICAgICAgICAgIHJldHVyblxuICAgICAgICBpZiAxIDwgcS5sZW5ndGggOjpcbiAgICAgICAgICBxID0gQFtdIGNvbmNhdEJ1ZmZlcnMgQCBxLCBxQnl0ZUxlblxuXG4gICAgICAgIHRpcCA9IHBhcnNlSGVhZGVyIEAgcVswXSwgZGVjcmVtZW50X3R0bFxuICAgICAgICBpZiBudWxsID09PSB0aXAgOjogcmV0dXJuXG5cbiAgICAgIGNvbnN0IGxlbiA9IHRpcC5wYWNrZXRfbGVuXG4gICAgICBpZiBxQnl0ZUxlbiA8IGxlbiA6OlxuICAgICAgICByZXR1cm5cblxuICAgICAgbGV0IGJ5dGVzID0gMCwgbiA9IDBcbiAgICAgIHdoaWxlIGJ5dGVzIDwgbGVuIDo6XG4gICAgICAgIGJ5dGVzICs9IHFbbisrXS5ieXRlTGVuZ3RoXG5cbiAgICAgIGNvbnN0IHRyYWlsaW5nQnl0ZXMgPSBieXRlcyAtIGxlblxuICAgICAgaWYgMCA9PT0gdHJhaWxpbmdCeXRlcyA6OiAvLyB3ZSBoYXZlIGFuIGV4YWN0IGxlbmd0aCBtYXRjaFxuICAgICAgICBjb25zdCBwYXJ0cyA9IHEuc3BsaWNlKDAsIG4pXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIGVsc2UgOjogLy8gd2UgaGF2ZSB0cmFpbGluZyBieXRlcyBvbiB0aGUgbGFzdCBhcnJheVxuICAgICAgICBjb25zdCBwYXJ0cyA9IDEgPT09IHEubGVuZ3RoID8gW10gOiBxLnNwbGljZSgwLCBuLTEpXG4gICAgICAgIGNvbnN0IHRhaWwgPSBxWzBdXG5cbiAgICAgICAgcGFydHMucHVzaCBAIHRhaWwuc2xpY2UoMCwgLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFbMF0gPSB0YWlsLnNsaWNlKC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICA6OlxuICAgICAgICBjb25zdCBwa3Rfb2JqID0gYXNQa3RPYmoodGlwKVxuICAgICAgICB0aXAgPSBudWxsXG4gICAgICAgIHJldHVybiBwa3Rfb2JqXG5cbiIsIi8qXG4gIDAxMjM0NTY3ODlhYiAgICAgLS0gMTItYnl0ZSBwYWNrZXQgaGVhZGVyIChjb250cm9sKVxuICAwMTIzNDU2Nzg5YWJjZGVmIC0tIDE2LWJ5dGUgcGFja2V0IGhlYWRlciAocm91dGluZylcbiAgXG4gIDAxLi4uLi4uLi4uLi4uLi4gLS0gdWludDE2IHNpZ25hdHVyZSA9IDB4RkUgMHhFRFxuICAuLjIzIC4uLi4uLi4uLi4uIC0tIHVpbnQxNiBwYWNrZXQgbGVuZ3RoXG4gIC4uLi40NS4uLi4uLi4uLi4gLS0gdWludDE2IGhlYWRlciBsZW5ndGhcbiAgLi4uLi4uNi4uLi4uLi4uLiAtLSB1aW50OCBoZWFkZXIgdHlwZVxuICAuLi4uLi4uNy4uLi4uLi4uIC0tIHVpbnQ4IHR0bCBob3BzXG5cbiAgLi4uLi4uLi44OWFiLi4uLiAtLSBpbnQzMiBpZF9yb3V0ZXJcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG5cbiAgLi4uLi4uLi4uLi4uY2RlZiAtLSBpbnQzMiBpZF90YXJnZXRcbiAgICAgICAgICAgICAgICAgICAgICA0LWJ5dGUgcmFuZG9tIHNwYWNlIGFsbG93cyAxIG1pbGxpb24gbm9kZXMgd2l0aFxuICAgICAgICAgICAgICAgICAgICAgIDAuMDIlIGNoYW5jZSBvZiB0d28gbm9kZXMgc2VsZWN0aW5nIHRoZSBzYW1lIGlkXG4gKi9cblxuaW1wb3J0IGFzUGFja2V0UGFyc2VyQVBJIGZyb20gJy4vYmFzaWMnXG5cbmNvbnN0IHNpZ25hdHVyZSA9IDB4ZWRmZVxuY29uc3QgcGt0X2hlYWRlcl9sZW4gPSAxNlxuY29uc3QgZGVmYXVsdF90dGwgPSAzMVxuXG5jb25zdCBsaXR0bGVfZW5kaWFuID0gdHJ1ZVxuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlcihvcHRpb25zPXt9KSA6OlxuICBjb25zdCBfVGV4dEVuY29kZXJfID0gb3B0aW9ucy5UZXh0RW5jb2RlciB8fCBUZXh0RW5jb2RlclxuICBjb25zdCBfVGV4dERlY29kZXJfID0gb3B0aW9ucy5UZXh0RGVjb2RlciB8fCBUZXh0RGVjb2RlclxuXG4gIHJldHVybiBhc1BhY2tldFBhcnNlckFQSSBAOlxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0XG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0SW50MzIgQCA4LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gZHYuZ2V0SW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAOiBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja1BhY2tldCguLi5hcmdzKSA6OlxuICAgIGxldCB7dHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCwgaGVhZGVyLCBib2R5fSA9IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuICAgIGlmICEgTnVtYmVyLmlzSW50ZWdlcihpZF9yb3V0ZXIpIDo6IHRocm93IG5ldyBFcnJvciBAIGBJbnZhbGlkIGlkX3JvdXRlcmBcbiAgICBpZiBpZF90YXJnZXQgJiYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3RhcmdldCkgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0YFxuICAgIGhlYWRlciA9IGFzQnVmZmVyKGhlYWRlciwgJ2hlYWRlcicpXG4gICAgYm9keSA9IGFzQnVmZmVyKGJvZHksICdib2R5JylcblxuICAgIGNvbnN0IGxlbiA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGR2LnNldFVpbnQxNiBAICAwLCBzaWduYXR1cmUsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMiwgbGVuLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDQsIGhlYWRlci5ieXRlTGVuZ3RoLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDYsIHR5cGUgfHwgMCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA3LCB0dGwgfHwgZGVmYXVsdF90dGwsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRJbnQzMiAgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAIDEyLCAwIHwgaWRfdGFyZ2V0LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGFycmF5KVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInVucGFja191dGY4IiwicGt0X29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJoZWFkZXJfb2Zmc2V0IiwiYm9keV9vZmZzZXQiLCJidWYiLCJoZWFkZXJfYnVmZmVyIiwiSlNPTiIsInBhcnNlIiwiaGVhZGVyX3V0ZjgiLCJib2R5X2J1ZmZlciIsImJvZHlfdXRmOCIsIm9mZnNldCIsInVucGFja0lkIiwicGFja2V0UGFyc2VyQVBJIiwiT2JqZWN0IiwiYXNzaWduIiwiY3JlYXRlIiwicGFja2V0UGFyc2VyIiwicGFja1BhY2tldE9iaiIsImFyZ3MiLCJwa3RfcmF3IiwicGFja1BhY2tldCIsInBrdCIsInBhcnNlSGVhZGVyIiwiYXNQa3RPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBrdF9vYmoiLCJ2YWx1ZSIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcFBhY2tldCIsInVuZGVmaW5lZCIsImxlbmd0aCIsImNvbmNhdEJ1ZmZlcnMiLCJsZW4iLCJieXRlcyIsIm4iLCJ0cmFpbGluZ0J5dGVzIiwicGFydHMiLCJzcGxpY2UiLCJ0YWlsIiwic2lnbmF0dXJlIiwiZGVmYXVsdF90dGwiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJwYWNrX3V0ZjgiLCJkdiIsIkRhdGFWaWV3Iiwic2lnIiwiZ2V0VWludDE2IiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJnZXRVaW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJzZXRVaW50OCIsImlkX3JvdXRlciIsImdldEludDMyIiwiaWRfdGFyZ2V0IiwiaGVhZGVyIiwiYm9keSIsIk51bWJlciIsImlzSW50ZWdlciIsImFycmF5IiwiQXJyYXlCdWZmZXIiLCJzZXRVaW50MTYiLCJzZXRJbnQzMiIsInU4IiwiVWludDhBcnJheSIsInNldCIsInBhY2tJZCIsImlkIiwic3RyIiwidGUiLCJlbmNvZGUiLCJidWZmZXIiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsInJlYWRJbnQzMkxFIiwiZnJvbSIsIkFycmF5IiwiaXNBcnJheSIsImNvbmNhdCIsIm1hcCIsImxzdCIsImFyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2NBQUE7WUFBQTtpQkFBQTtZQUFBLEVBS01DLFdBTE4sS0FNSkQsbUJBTkY7O1FBUU1FLGdCQUFrQjtvQkFDTjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREc7Z0JBRVZDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGRTtnQkFHVkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FBeUIsSUFBdEMsQ0FBUDtLQUhFOztrQkFLUjthQUFVLEtBQUtKLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEs7Y0FNWkMsR0FBVixFQUFlO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0ssV0FBTCxFQUFyQixDQUFQO0tBTkk7Y0FPWkwsR0FBVixFQUFlO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLRyxTQUFMLENBQWVOLEdBQWYsS0FBdUIsSUFBcEMsQ0FBUDtLQVBJOzthQVNiQSxHQUFULEVBQWNPLFNBQU8sQ0FBckIsRUFBd0I7YUFBVUMsU0FBU1IsT0FBTyxLQUFLSixLQUFyQixFQUE0QlcsTUFBNUIsQ0FBUDtLQVRMO2VBQUEsRUFBeEI7O1FBWU1FLGtCQUFrQkMsT0FBT0MsTUFBUCxDQUN0QkQsT0FBT0UsTUFBUCxDQUFjLElBQWQsQ0FEc0IsRUFFdEJuQixtQkFGc0IsRUFHdEI7cUJBQ21CO2FBQVUsSUFBUDtLQUR0QjtpQkFBQTtnQkFBQTtZQUFBO2lCQUFBLEVBSHNCLENBQXhCOztnQkFVY29CLFlBQWQsR0FBNkJKLGVBQTdCO1NBQ09BLGVBQVA7O1dBR1NLLGFBQVQsQ0FBdUIsR0FBR0MsSUFBMUIsRUFBZ0M7VUFDeEJDLFVBQVVDLFdBQWEsR0FBR0YsSUFBaEIsQ0FBaEI7VUFDTUcsTUFBTUMsWUFBY0gsT0FBZCxDQUFaO1FBQ0lwQixLQUFKLEdBQVlvQixPQUFaO1dBQ09JLFNBQVNGLEdBQVQsQ0FBUDs7O1dBR09FLFFBQVQsQ0FBa0IsRUFBQ0MsSUFBRCxFQUFPQyxjQUFQLEVBQXVCQyxVQUF2QixFQUFtQ0MsVUFBbkMsRUFBK0M1QixLQUEvQyxFQUFsQixFQUF5RTtRQUNuRUcsY0FBY3VCLGlCQUFpQkUsVUFBbkM7UUFDR3pCLGNBQWN3QixVQUFqQixFQUE4QjtvQkFDZCxJQUFkLENBRDRCO0tBRzlCLE1BQU1FLFVBQVVmLE9BQU9FLE1BQVAsQ0FBZ0JqQixhQUFoQixFQUFpQztxQkFDaEMsRUFBSStCLE9BQU9KLGNBQVgsRUFEZ0M7bUJBRWxDLEVBQUlJLE9BQU8zQixXQUFYLEVBRmtDO2tCQUduQyxFQUFJMkIsT0FBT0gsVUFBWCxFQUhtQzthQUl4QyxFQUFJRyxPQUFPOUIsS0FBWCxFQUp3QyxFQUFqQyxDQUFoQjs7V0FNT2MsT0FBT0MsTUFBUCxDQUFnQmMsT0FBaEIsRUFBeUJKLElBQXpCLENBQVA7OztXQUdPTSxZQUFULENBQXNCQyxPQUF0QixFQUErQjtRQUMxQixDQUFFQSxPQUFMLEVBQWU7Z0JBQVcsRUFBVjs7O1VBRVZDLGdCQUNKLFFBQVFELFFBQVFDLGFBQWhCLEdBQ0ksSUFESixHQUNXLENBQUMsQ0FBRUQsUUFBUUMsYUFGeEI7O1FBSUlDLE1BQUksSUFBUjtRQUFjQyxXQUFXLENBQXpCO1FBQTRCQyxJQUFJLEVBQWhDO1dBQ09DLElBQVA7O2FBRVNBLElBQVQsQ0FBY0MsSUFBZCxFQUFvQkMsV0FBUyxFQUE3QixFQUFpQzthQUN4QkMsU0FBU0YsSUFBVCxDQUFQO1FBQ0VHLElBQUYsQ0FBU0gsSUFBVDtrQkFDWUEsS0FBS0ksVUFBakI7O2FBRU0sQ0FBTixFQUFVO2NBQ0ZwQixNQUFNcUIsZ0JBQVo7WUFDR0MsY0FBY3RCLEdBQWpCLEVBQXVCO21CQUNabUIsSUFBVCxDQUFnQm5CLEdBQWhCO1NBREYsTUFFSyxPQUFPaUIsUUFBUDs7OzthQUdBSSxjQUFULEdBQTBCO1VBQ3JCLFNBQVNULEdBQVosRUFBa0I7WUFDYixNQUFNRSxFQUFFUyxNQUFYLEVBQW9COzs7WUFFakIsSUFBSVQsRUFBRVMsTUFBVCxFQUFrQjtjQUNaLENBQUlDLGNBQWdCVixDQUFoQixFQUFtQkQsUUFBbkIsQ0FBSixDQUFKOzs7Y0FFSVosWUFBY2EsRUFBRSxDQUFGLENBQWQsRUFBb0JILGFBQXBCLENBQU47WUFDRyxTQUFTQyxHQUFaLEVBQWtCOzs7OztZQUVkYSxNQUFNYixJQUFJUCxVQUFoQjtVQUNHUSxXQUFXWSxHQUFkLEVBQW9COzs7O1VBR2hCQyxRQUFRLENBQVo7VUFBZUMsSUFBSSxDQUFuQjthQUNNRCxRQUFRRCxHQUFkLEVBQW9CO2lCQUNUWCxFQUFFYSxHQUFGLEVBQU9QLFVBQWhCOzs7WUFFSVEsZ0JBQWdCRixRQUFRRCxHQUE5QjtVQUNHLE1BQU1HLGFBQVQsRUFBeUI7O2NBQ2pCQyxRQUFRZixFQUFFZ0IsTUFBRixDQUFTLENBQVQsRUFBWUgsQ0FBWixDQUFkO29CQUNZRixHQUFaOztZQUVJL0MsS0FBSixHQUFZOEMsY0FBZ0JLLEtBQWhCLEVBQXVCSixHQUF2QixDQUFaO09BSkYsTUFNSzs7Y0FDR0ksUUFBUSxNQUFNZixFQUFFUyxNQUFSLEdBQWlCLEVBQWpCLEdBQXNCVCxFQUFFZ0IsTUFBRixDQUFTLENBQVQsRUFBWUgsSUFBRSxDQUFkLENBQXBDO2NBQ01JLE9BQU9qQixFQUFFLENBQUYsQ0FBYjs7Y0FFTUssSUFBTixDQUFhWSxLQUFLcEQsS0FBTCxDQUFXLENBQVgsRUFBYyxDQUFDaUQsYUFBZixDQUFiO1VBQ0UsQ0FBRixJQUFPRyxLQUFLcEQsS0FBTCxDQUFXLENBQUNpRCxhQUFaLENBQVA7b0JBQ1lILEdBQVo7O1lBRUkvQyxLQUFKLEdBQVk4QyxjQUFnQkssS0FBaEIsRUFBdUJKLEdBQXZCLENBQVo7Ozs7Y0FHTWxCLFVBQVVMLFNBQVNVLEdBQVQsQ0FBaEI7Y0FDTSxJQUFOO2VBQ09MLE9BQVA7Ozs7OztBQ3JIUjs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQW1CQSxBQUVBLE1BQU15QixZQUFZLE1BQWxCO0FBQ0EsTUFBTTVCLGlCQUFpQixFQUF2QjtBQUNBLE1BQU02QixjQUFjLEVBQXBCOztBQUVBLE1BQU1DLGdCQUFnQixJQUF0Qjs7QUFFQSxBQUFlLFNBQVNDLDBCQUFULENBQW9DekIsVUFBUSxFQUE1QyxFQUFnRDtRQUN2RDBCLGdCQUFnQjFCLFFBQVEyQixXQUFSLElBQXVCQSxXQUE3QztRQUNNQyxnQkFBZ0I1QixRQUFRNkIsV0FBUixJQUF1QkEsV0FBN0M7O1NBRU9qRSxrQkFBb0I7ZUFBQSxFQUNaeUIsVUFEWTtVQUFBLEVBRWpCVCxRQUZpQixFQUVQa0QsU0FGTyxFQUVJaEUsV0FGSjs7WUFBQSxFQUlmZ0QsYUFKZSxFQUFwQixDQUFQOztXQU9TdkIsV0FBVCxDQUFxQm5CLEdBQXJCLEVBQTBCNkIsYUFBMUIsRUFBeUM7UUFDcENQLGlCQUFpQnRCLElBQUlzQyxVQUF4QixFQUFxQzthQUFRLElBQVA7OztVQUVoQ3FCLEtBQUssSUFBSUMsUUFBSixDQUFlNUQsR0FBZixDQUFYOztVQUVNNkQsTUFBTUYsR0FBR0csU0FBSCxDQUFlLENBQWYsRUFBa0JWLGFBQWxCLENBQVo7UUFDR0YsY0FBY1csR0FBakIsRUFBdUI7WUFDZixJQUFJRSxLQUFKLENBQWEsdUNBQXNDRixJQUFJRyxRQUFKLENBQWEsRUFBYixDQUFpQixjQUFhZCxVQUFVYyxRQUFWLENBQW1CLEVBQW5CLENBQXVCLEdBQXhHLENBQU47Ozs7VUFHSXpDLGFBQWFvQyxHQUFHRyxTQUFILENBQWUsQ0FBZixFQUFrQlYsYUFBbEIsQ0FBbkI7VUFDTTVCLGFBQWFtQyxHQUFHRyxTQUFILENBQWUsQ0FBZixFQUFrQlYsYUFBbEIsQ0FBbkI7VUFDTWEsT0FBT04sR0FBR08sUUFBSCxDQUFjLENBQWQsRUFBaUJkLGFBQWpCLENBQWI7O1FBRUllLE1BQU1SLEdBQUdPLFFBQUgsQ0FBYyxDQUFkLEVBQWlCZCxhQUFqQixDQUFWO1FBQ0d2QixhQUFILEVBQW1CO1lBQ1h1QyxLQUFLQyxHQUFMLENBQVcsQ0FBWCxFQUFjRixNQUFNLENBQXBCLENBQU47U0FDR0csUUFBSCxDQUFjLENBQWQsRUFBaUJILEdBQWpCLEVBQXNCZixhQUF0Qjs7O1VBRUltQixZQUFZWixHQUFHYSxRQUFILENBQWMsQ0FBZCxFQUFpQnBCLGFBQWpCLENBQWxCO1VBQ01xQixZQUFZZCxHQUFHYSxRQUFILENBQWMsRUFBZCxFQUFrQnBCLGFBQWxCLENBQWxCO1VBQ00vQixPQUFPLEVBQUk0QyxJQUFKLEVBQVVFLEdBQVYsRUFBZUksU0FBZixFQUEwQkUsU0FBMUIsRUFBYjtXQUNTLEVBQUNwRCxJQUFELEVBQU9DLGNBQVAsRUFBdUJDLFVBQXZCLEVBQW1DQyxVQUFuQyxFQUFUOzs7V0FHT1AsVUFBVCxDQUFvQixHQUFHRixJQUF2QixFQUE2QjtRQUN2QixFQUFDa0QsSUFBRCxFQUFPRSxHQUFQLEVBQVlJLFNBQVosRUFBdUJFLFNBQXZCLEVBQWtDQyxNQUFsQyxFQUEwQ0MsSUFBMUMsS0FBa0RqRSxPQUFPQyxNQUFQLENBQWdCLEVBQWhCLEVBQW9CLEdBQUdJLElBQXZCLENBQXREO1FBQ0csQ0FBRTZELE9BQU9DLFNBQVAsQ0FBaUJOLFNBQWpCLENBQUwsRUFBbUM7WUFBTyxJQUFJUixLQUFKLENBQWEsbUJBQWIsQ0FBTjs7UUFDakNVLGFBQWEsQ0FBRUcsT0FBT0MsU0FBUCxDQUFpQkosU0FBakIsQ0FBbEIsRUFBZ0Q7WUFBTyxJQUFJVixLQUFKLENBQWEsbUJBQWIsQ0FBTjs7YUFDeEMzQixTQUFTc0MsTUFBVCxFQUFpQixRQUFqQixDQUFUO1dBQ090QyxTQUFTdUMsSUFBVCxFQUFlLE1BQWYsQ0FBUDs7VUFFTWhDLE1BQU1yQixpQkFBaUJvRCxPQUFPcEMsVUFBeEIsR0FBcUNxQyxLQUFLckMsVUFBdEQ7UUFDR0ssTUFBTSxNQUFULEVBQWtCO1lBQU8sSUFBSW9CLEtBQUosQ0FBYSxrQkFBYixDQUFOOzs7VUFFYmUsUUFBUSxJQUFJQyxXQUFKLENBQWdCcEMsR0FBaEIsQ0FBZDs7VUFFTWdCLEtBQUssSUFBSUMsUUFBSixDQUFla0IsS0FBZixFQUFzQixDQUF0QixFQUF5QnhELGNBQXpCLENBQVg7T0FDRzBELFNBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUI5QixTQUFuQixFQUE4QkUsYUFBOUI7T0FDRzRCLFNBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUJyQyxHQUFuQixFQUF3QlMsYUFBeEI7T0FDRzRCLFNBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUJOLE9BQU9wQyxVQUExQixFQUFzQ2MsYUFBdEM7T0FDR2tCLFFBQUgsQ0FBZ0IsQ0FBaEIsRUFBbUJMLFFBQVEsQ0FBM0IsRUFBOEJiLGFBQTlCO09BQ0drQixRQUFILENBQWdCLENBQWhCLEVBQW1CSCxPQUFPaEIsV0FBMUIsRUFBdUNDLGFBQXZDO09BQ0c2QixRQUFILENBQWdCLENBQWhCLEVBQW1CLElBQUlWLFNBQXZCLEVBQWtDbkIsYUFBbEM7T0FDRzZCLFFBQUgsQ0FBZSxFQUFmLEVBQW1CLElBQUlSLFNBQXZCLEVBQWtDckIsYUFBbEM7O1VBRU04QixLQUFLLElBQUlDLFVBQUosQ0FBZUwsS0FBZixDQUFYO09BQ0dNLEdBQUgsQ0FBUyxJQUFJRCxVQUFKLENBQWVULE1BQWYsQ0FBVCxFQUFpQ3BELGNBQWpDO09BQ0c4RCxHQUFILENBQVMsSUFBSUQsVUFBSixDQUFlUixJQUFmLENBQVQsRUFBK0JyRCxpQkFBaUJvRCxPQUFPcEMsVUFBdkQ7V0FDT3dDLEtBQVA7OztXQUdPTyxNQUFULENBQWdCQyxFQUFoQixFQUFvQi9FLE1BQXBCLEVBQTRCO1VBQ3BCUCxNQUFNLElBQUkrRSxXQUFKLENBQWdCLENBQWhCLENBQVo7UUFDSW5CLFFBQUosQ0FBYTVELEdBQWIsRUFBa0JpRixRQUFsQixDQUE2QjFFLFVBQVEsQ0FBckMsRUFBd0MsSUFBSStFLEVBQTVDLEVBQWdEbEMsYUFBaEQ7V0FDT3BELEdBQVA7O1dBQ09RLFFBQVQsQ0FBa0JSLEdBQWxCLEVBQXVCTyxNQUF2QixFQUErQjtVQUN2Qm9ELEtBQUssSUFBSUMsUUFBSixDQUFleEIsU0FBU3BDLEdBQVQsQ0FBZixDQUFYO1dBQ08yRCxHQUFHYSxRQUFILENBQWNqRSxVQUFRLENBQXRCLEVBQXlCNkMsYUFBekIsQ0FBUDs7O1dBRU9NLFNBQVQsQ0FBbUI2QixHQUFuQixFQUF3QjtVQUNoQkMsS0FBSyxJQUFJbEMsYUFBSixDQUFrQixPQUFsQixDQUFYO1dBQ09rQyxHQUFHQyxNQUFILENBQVVGLElBQUl2QixRQUFKLEVBQVYsRUFBMEIwQixNQUFqQzs7V0FDT2hHLFdBQVQsQ0FBcUJNLEdBQXJCLEVBQTBCO1VBQ2xCMkYsS0FBSyxJQUFJbkMsYUFBSixDQUFrQixPQUFsQixDQUFYO1dBQ09tQyxHQUFHQyxNQUFILENBQVl4RCxTQUFXcEMsR0FBWCxDQUFaLENBQVA7OztXQUdPb0MsUUFBVCxDQUFrQnBDLEdBQWxCLEVBQXVCO1FBQ2xCLFNBQVNBLEdBQVQsSUFBZ0J3QyxjQUFjeEMsR0FBakMsRUFBdUM7YUFDOUIsSUFBSStFLFdBQUosQ0FBZ0IsQ0FBaEIsQ0FBUDs7O1FBRUN2QyxjQUFjeEMsSUFBSXNDLFVBQXJCLEVBQWtDO1VBQzdCRSxjQUFjeEMsSUFBSTBGLE1BQXJCLEVBQThCO2VBQ3JCMUYsR0FBUDs7O1VBRUMrRSxZQUFZYyxNQUFaLENBQW1CN0YsR0FBbkIsQ0FBSCxFQUE2QjtlQUNwQkEsSUFBSTBGLE1BQVg7OztVQUVDLGVBQWUsT0FBTzFGLElBQUk4RixXQUE3QixFQUEyQztlQUNsQ1gsV0FBV1ksSUFBWCxDQUFnQi9GLEdBQWhCLEVBQXFCMEYsTUFBNUIsQ0FEeUM7T0FHM0MsT0FBTzFGLEdBQVA7OztRQUVDLGFBQWEsT0FBT0EsR0FBdkIsRUFBNkI7YUFDcEIwRCxVQUFVMUQsR0FBVixDQUFQOzs7UUFFQ2dHLE1BQU1DLE9BQU4sQ0FBY2pHLEdBQWQsQ0FBSCxFQUF3QjtVQUNuQjRFLE9BQU9DLFNBQVAsQ0FBbUI3RSxJQUFJLENBQUosQ0FBbkIsQ0FBSCxFQUErQjtlQUN0Qm1GLFdBQVdZLElBQVgsQ0FBZ0IvRixHQUFoQixFQUFxQjBGLE1BQTVCOzthQUNLUSxPQUFTbEcsSUFBSW1HLEdBQUosQ0FBVS9ELFFBQVYsQ0FBVCxDQUFQOzs7O1dBR0tNLGFBQVQsQ0FBdUIwRCxHQUF2QixFQUE0QnpELEdBQTVCLEVBQWlDO1FBQzVCLE1BQU15RCxJQUFJM0QsTUFBYixFQUFzQjthQUFRMkQsSUFBSSxDQUFKLENBQVA7O1FBQ3BCLE1BQU1BLElBQUkzRCxNQUFiLEVBQXNCO2FBQVEsSUFBSXNDLFdBQUosQ0FBZ0IsQ0FBaEIsQ0FBUDs7O1FBRXBCLFFBQVFwQyxHQUFYLEVBQWlCO1lBQ1QsQ0FBTjtXQUNJLE1BQU0wRCxHQUFWLElBQWlCRCxHQUFqQixFQUF1QjtlQUNkQyxJQUFJL0QsVUFBWDs7OztVQUVFNEMsS0FBSyxJQUFJQyxVQUFKLENBQWV4QyxHQUFmLENBQVg7UUFDSXBDLFNBQVMsQ0FBYjtTQUNJLE1BQU04RixHQUFWLElBQWlCRCxHQUFqQixFQUF1QjtTQUNsQmhCLEdBQUgsQ0FBUyxJQUFJRCxVQUFKLENBQWVrQixHQUFmLENBQVQsRUFBOEI5RixNQUE5QjtnQkFDVThGLElBQUkvRCxVQUFkOztXQUNLNEMsR0FBR1EsTUFBVjs7Ozs7Ozs7OzsifQ==
