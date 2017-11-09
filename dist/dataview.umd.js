(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define(factory) :
	(global['msg-fabric-packet-stream'] = factory());
}(this, (function () { 'use strict';

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
    parseHeader, packMessage,
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

  function packMessage(...args) {
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
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

return createDataViewPacketParser;

})));
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBwYWNrTWVzc2FnZU9ialxuICAgICAgcGFja2V0U3RyZWFtXG4gICAgICBhc01zZ09ialxuICAgICAgbXNnX29ial9wcm90b1xuICByZXR1cm4gcGFja2V0UGFyc2VyQVBJXG5cblxuICBmdW5jdGlvbiBwYWNrTWVzc2FnZU9iaiguLi5hcmdzKSA6OlxuICAgIGNvbnN0IG1zZ19yYXcgPSBwYWNrTWVzc2FnZSBAIC4uLmFyZ3NcbiAgICBjb25zdCBtc2cgPSBwYXJzZUhlYWRlciBAIG1zZ19yYXdcbiAgICBtc2cuX3Jhd18gPSBtc2dfcmF3XG4gICAgcmV0dXJuIGFzTXNnT2JqKG1zZylcblxuXG4gIGZ1bmN0aW9uIGFzTXNnT2JqKHtpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgX3Jhd199KSA6OlxuICAgIGxldCBib2R5X29mZnNldCA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyX2xlblxuICAgIGlmIGJvZHlfb2Zmc2V0ID4gcGFja2V0X2xlbiA6OlxuICAgICAgYm9keV9vZmZzZXQgPSBudWxsIC8vIGludmFsaWQgbWVzc2FnZSBjb25zdHJ1Y3Rpb25cblxuICAgIGNvbnN0IG1zZ19vYmogPSBPYmplY3QuY3JlYXRlIEAgbXNnX29ial9wcm90bywgQDpcbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIG1zZ19vYmosIGluZm9cblxuXG4gIGZ1bmN0aW9uIHBhY2tldFN0cmVhbShvcHRpb25zKSA6OlxuICAgIGlmICEgb3B0aW9ucyA6OiBvcHRpb25zID0ge31cblxuICAgIGNvbnN0IGRlY3JlbWVudF90dGwgPVxuICAgICAgbnVsbCA9PSBvcHRpb25zLmRlY3JlbWVudF90dGxcbiAgICAgICAgPyB0cnVlIDogISEgb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG5cbiAgICBsZXQgdGlwPW51bGwsIHFCeXRlTGVuID0gMCwgcSA9IFtdXG4gICAgcmV0dXJuIGZlZWRcblxuICAgIGZ1bmN0aW9uIGZlZWQoZGF0YSwgY29tcGxldGU9W10pIDo6XG4gICAgICBkYXRhID0gYXNCdWZmZXIoZGF0YSlcbiAgICAgIHEucHVzaCBAIGRhdGFcbiAgICAgIHFCeXRlTGVuICs9IGRhdGEuYnl0ZUxlbmd0aFxuXG4gICAgICB3aGlsZSAxIDo6XG4gICAgICAgIGNvbnN0IG1zZyA9IHBhcnNlVGlwTWVzc2FnZSgpXG4gICAgICAgIGlmIHVuZGVmaW5lZCAhPT0gbXNnIDo6XG4gICAgICAgICAgY29tcGxldGUucHVzaCBAIG1zZ1xuICAgICAgICBlbHNlIHJldHVybiBjb21wbGV0ZVxuXG5cbiAgICBmdW5jdGlvbiBwYXJzZVRpcE1lc3NhZ2UoKSA6OlxuICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6XG4gICAgICAgIGlmIDAgPT09IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcmV0dXJuXG4gICAgICAgIGlmIDEgPCBxLmxlbmd0aCA6OlxuICAgICAgICAgIHEgPSBAW10gY29uY2F0QnVmZmVycyBAIHEsIHFCeXRlTGVuXG5cbiAgICAgICAgdGlwID0gcGFyc2VIZWFkZXIgQCBxWzBdLCBkZWNyZW1lbnRfdHRsXG4gICAgICAgIGlmIG51bGwgPT09IHRpcCA6OiByZXR1cm5cblxuICAgICAgY29uc3QgbGVuID0gdGlwLnBhY2tldF9sZW5cbiAgICAgIGlmIHFCeXRlTGVuIDwgbGVuIDo6XG4gICAgICAgIHJldHVyblxuXG4gICAgICBsZXQgYnl0ZXMgPSAwLCBuID0gMFxuICAgICAgd2hpbGUgYnl0ZXMgPCBsZW4gOjpcbiAgICAgICAgYnl0ZXMgKz0gcVtuKytdLmJ5dGVMZW5ndGhcblxuICAgICAgY29uc3QgdHJhaWxpbmdCeXRlcyA9IGJ5dGVzIC0gbGVuXG4gICAgICBpZiAwID09PSB0cmFpbGluZ0J5dGVzIDo6IC8vIHdlIGhhdmUgYW4gZXhhY3QgbGVuZ3RoIG1hdGNoXG4gICAgICAgIGNvbnN0IHBhcnRzID0gcS5zcGxpY2UoMCwgbilcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgZWxzZSA6OiAvLyB3ZSBoYXZlIHRyYWlsaW5nIGJ5dGVzIG9uIHRoZSBsYXN0IGFycmF5XG4gICAgICAgIGNvbnN0IHBhcnRzID0gMSA9PT0gcS5sZW5ndGggPyBbXSA6IHEuc3BsaWNlKDAsIG4tMSlcbiAgICAgICAgY29uc3QgdGFpbCA9IHFbMF1cblxuICAgICAgICBwYXJ0cy5wdXNoIEAgdGFpbC5zbGljZSgwLCAtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcVswXSA9IHRhaWwuc2xpY2UoLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIDo6XG4gICAgICAgIGNvbnN0IG1zZ19vYmogPSBhc01zZ09iaih0aXApXG4gICAgICAgIHRpcCA9IG51bGxcbiAgICAgICAgcmV0dXJuIG1zZ19vYmpcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0SW50MzIgQCA4LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gZHYuZ2V0SW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAOiBpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlblxuXG5cbiAgZnVuY3Rpb24gcGFja01lc3NhZ2UoLi4uYXJncykgOjpcbiAgICBsZXQge3R5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXQsIGhlYWRlciwgYm9keX0gPSBPYmplY3QuYXNzaWduIEAge30sIC4uLmFyZ3NcbiAgICBoZWFkZXIgPSBhc0J1ZmZlcihoZWFkZXIsICdoZWFkZXInKVxuICAgIGJvZHkgPSBhc0J1ZmZlcihib2R5LCAnYm9keScpXG5cbiAgICBjb25zdCBsZW4gPSBwa3RfaGVhZGVyX2xlbiArIGhlYWRlci5ieXRlTGVuZ3RoICsgYm9keS5ieXRlTGVuZ3RoXG4gICAgaWYgbGVuID4gMHhmZmZmIDo6IHRocm93IG5ldyBFcnJvciBAIGBQYWNrZXQgdG9vIGxhcmdlYFxuXG4gICAgY29uc3QgYXJyYXkgPSBuZXcgQXJyYXlCdWZmZXIobGVuKVxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBhcnJheSwgMCwgcGt0X2hlYWRlcl9sZW5cbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgQCAgOCwgMCB8IGlkX3JvdXRlciwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9sZW5cbiAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShib2R5KSwgcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiBhcnJheVxuXG5cbiAgZnVuY3Rpb24gcGFja0lkKGlkLCBvZmZzZXQpIDo6XG4gICAgY29uc3QgYnVmID0gbmV3IEFycmF5QnVmZmVyKDQpXG4gICAgbmV3IERhdGFWaWV3KGJ1Zikuc2V0SW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0SW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIHVuZGVmaW5lZCA9PT0gYnVmLmJ1ZmZlciA6OlxuICAgICAgICByZXR1cm4gYnVmXG5cbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBidWYuYnVmZmVyXG5cbiAgICAgIGlmICdmdW5jdGlvbicgPT09IHR5cGVvZiBidWYucmVhZEludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzU2FmZUludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwidW5wYWNrX3V0ZjgiLCJtc2dfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4Iiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrTWVzc2FnZU9iaiIsImFyZ3MiLCJtc2dfcmF3IiwicGFja01lc3NhZ2UiLCJtc2ciLCJwYXJzZUhlYWRlciIsImFzTXNnT2JqIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJtc2dfb2JqIiwidmFsdWUiLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwicGFyc2VUaXBNZXNzYWdlIiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsInBhY2tfdXRmOCIsImR2IiwiRGF0YVZpZXciLCJzaWciLCJnZXRVaW50MTYiLCJFcnJvciIsInRvU3RyaW5nIiwidHlwZSIsImdldFVpbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsInNldFVpbnQ4IiwiaWRfcm91dGVyIiwiZ2V0SW50MzIiLCJpZF90YXJnZXQiLCJoZWFkZXIiLCJib2R5IiwiYXJyYXkiLCJBcnJheUJ1ZmZlciIsInNldFVpbnQxNiIsInNldEludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJ0ZSIsImVuY29kZSIsImJ1ZmZlciIsInRkIiwiZGVjb2RlIiwiaXNWaWV3IiwicmVhZEludDMyTEUiLCJmcm9tIiwiQXJyYXkiLCJpc0FycmF5IiwiTnVtYmVyIiwiaXNTYWZlSW50ZWdlciIsImNvbmNhdCIsIm1hcCIsImxzdCIsImFyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFBQTtpQkFBQTtZQUFBLEVBS01DLFdBTE4sS0FNSkQsbUJBTkY7O1FBUU1FLGdCQUFrQjtvQkFDTjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREc7Z0JBRVZDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGRTtnQkFHVkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FBeUIsSUFBdEMsQ0FBUDtLQUhFOztrQkFLUjthQUFVLEtBQUtKLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLRSxXQUF4QixDQUFQO0tBTEs7Y0FNWkMsR0FBVixFQUFlO2FBQVVOLFlBQWNNLE9BQU8sS0FBS0ssV0FBTCxFQUFyQixDQUFQO0tBTkk7Y0FPWkwsR0FBVixFQUFlO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLRyxTQUFMLENBQWVOLEdBQWYsS0FBdUIsSUFBcEMsQ0FBUDtLQVBJOzthQVNiQSxHQUFULEVBQWNPLFNBQU8sQ0FBckIsRUFBd0I7YUFBVUMsU0FBU1IsT0FBTyxLQUFLSixLQUFyQixFQUE0QlcsTUFBNUIsQ0FBUDtLQVRMO2VBQUEsRUFBeEI7O1FBWU1FLGtCQUFr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
