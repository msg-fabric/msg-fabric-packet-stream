(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define(factory) :
	(global['msg-fabric-packet-stream'] = factory());
}(this, (function () { 'use strict';

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

const little_endian = true;

function createDataViewPacketParser(options = {}) {
  const _TextEncoder_ = options.TextEncoder || TextEncoder;
  const _TextDecoder_ = options.TextDecoder || TextDecoder;

  return asPacketParserAPI({
    parseHeader, packPacket, fwdHeader,
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
    let { type, ttl, id_router, id_target, header, body } = 1 === args.length ? args[0] : Object.assign({}, ...args);

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

    const pkthdr = new ArrayBuffer(len);
    const dv = new DataView(pkthdr, 0, pkt_header_len);
    dv.setUint16(0, signature, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl, little_endian);
    dv.setInt32(8, 0 | id_router, little_endian);
    dv.setInt32(12, 0 | id_target, little_endian);

    const u8 = new Uint8Array(pkthdr);
    u8.set(new Uint8Array(header), pkt_header_len);
    u8.set(new Uint8Array(body), pkt_header_len + header.byteLength);
    return array;
  }

  function fwdHeader(buf, id_router, id_target) {
    buf = new Uint8Array(buf).buffer;
    const dv = new DataView(buf, 0, pkt_header_len);
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

return createDataViewPacketParser;

})));
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQHt9XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICBmd2RfdG8oZndkX2lkKSA6OiByZXR1cm4gYXNGd2RQa3RPYmogQCB0aGlzLCBmd2RfaWRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrUGFja2V0T2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzUGt0T2JqLCBhc0Z3ZFBrdE9ialxuICAgICAgcGt0X29ial9wcm90b1xuXG4gIHBrdF9vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXRPYmooLi4uYXJncykgOjpcbiAgICBjb25zdCBwa3RfcmF3ID0gcGFja1BhY2tldCBAIC4uLmFyZ3NcbiAgICBjb25zdCBwa3QgPSBwYXJzZUhlYWRlciBAIHBrdF9yYXdcbiAgICBwa3QuX3Jhd18gPSBwa3RfcmF3XG4gICAgcmV0dXJuIGFzUGt0T2JqKHBrdClcblxuXG4gIGZ1bmN0aW9uIGFzUGt0T2JqKHtpbmZvLCBwa3RfaGVhZGVyX2xlbiwgcGFja2V0X2xlbiwgaGVhZGVyX2xlbiwgX3Jhd199KSA6OlxuICAgIGxldCBib2R5X29mZnNldCA9IHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyX2xlblxuICAgIGlmIGJvZHlfb2Zmc2V0ID4gcGFja2V0X2xlbiA6OlxuICAgICAgYm9keV9vZmZzZXQgPSBudWxsIC8vIGludmFsaWQgcGFja2V0IGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgcGt0X29iaiA9IE9iamVjdC5jcmVhdGUgQCBwa3Rfb2JqX3Byb3RvLCBAe31cbiAgICAgIGhlYWRlcl9vZmZzZXQ6IEB7fSB2YWx1ZTogcGt0X2hlYWRlcl9sZW5cbiAgICAgIGJvZHlfb2Zmc2V0OiBAe30gdmFsdWU6IGJvZHlfb2Zmc2V0XG4gICAgICBwYWNrZXRfbGVuOiBAe30gdmFsdWU6IHBhY2tldF9sZW5cbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG5cbiAgICByZXR1cm4gT2JqZWN0LmFzc2lnbiBAIHBrdF9vYmosIGluZm9cblxuICBmdW5jdGlvbiBhc0Z3ZFBrdE9iaihwa3Rfb2JqLCB7aWRfcm91dGVyLCBpZF90YXJnZXR9KSA6OlxuICAgIGlmIG51bGwgPT0gaWRfdGFyZ2V0IDo6IHRocm93IG5ldyBFcnJvciBAICdpZF90YXJnZXQgcmVxdWlyZWQnXG4gICAgY29uc3QgcmF3ID0gZndkSGVhZGVyIEAgcGt0X29iai5fcmF3XywgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICBjb25zdCBmd2Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmosIEB7fSBfcmF3XzogQHt9IHZhbHVlOiBfcmF3X1xuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGZ3ZF9vYmouaWRfcm91dGVyID0gaWRfcm91dGVyXG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogZndkX29iai5pZF90YXJnZXQgPSBpZF90YXJnZXRcbiAgICBmd2Rfb2JqLmlzX2Z3ZCA9IHRydWVcbiAgICByZXR1cm4gZndkX29ialxuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgcGt0ID0gcGFyc2VUaXBQYWNrZXQoKVxuICAgICAgICBpZiB1bmRlZmluZWQgIT09IHBrdCA6OlxuICAgICAgICAgIGNvbXBsZXRlLnB1c2ggQCBwa3RcbiAgICAgICAgZWxzZSByZXR1cm4gY29tcGxldGVcblxuXG4gICAgZnVuY3Rpb24gcGFyc2VUaXBQYWNrZXQoKSA6OlxuICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6XG4gICAgICAgIGlmIDAgPT09IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcmV0dXJuXG4gICAgICAgIGlmIDEgPCBxLmxlbmd0aCA6OlxuICAgICAgICAgIHEgPSBAW10gY29uY2F0QnVmZmVycyBAIHEsIHFCeXRlTGVuXG5cbiAgICAgICAgdGlwID0gcGFyc2VIZWFkZXIgQCBxWzBdLCBkZWNyZW1lbnRfdHRsXG4gICAgICAgIGlmIG51bGwgPT09IHRpcCA6OiByZXR1cm5cblxuICAgICAgY29uc3QgbGVuID0gdGlwLnBhY2tldF9sZW5cbiAgICAgIGlmIHFCeXRlTGVuIDwgbGVuIDo6XG4gICAgICAgIHJldHVyblxuXG4gICAgICBsZXQgYnl0ZXMgPSAwLCBuID0gMFxuICAgICAgd2hpbGUgYnl0ZXMgPCBsZW4gOjpcbiAgICAgICAgYnl0ZXMgKz0gcVtuKytdLmJ5dGVMZW5ndGhcblxuICAgICAgY29uc3QgdHJhaWxpbmdCeXRlcyA9IGJ5dGVzIC0gbGVuXG4gICAgICBpZiAwID09PSB0cmFpbGluZ0J5dGVzIDo6IC8vIHdlIGhhdmUgYW4gZXhhY3QgbGVuZ3RoIG1hdGNoXG4gICAgICAgIGNvbnN0IHBhcnRzID0gcS5zcGxpY2UoMCwgbilcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgZWxzZSA6OiAvLyB3ZSBoYXZlIHRyYWlsaW5nIGJ5dGVzIG9uIHRoZSBsYXN0IGFycmF5XG4gICAgICAgIGNvbnN0IHBhcnRzID0gMSA9PT0gcS5sZW5ndGggPyBbXSA6IHEuc3BsaWNlKDAsIG4tMSlcbiAgICAgICAgY29uc3QgdGFpbCA9IHFbMF1cblxuICAgICAgICBwYXJ0cy5wdXNoIEAgdGFpbC5zbGljZSgwLCAtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcVswXSA9IHRhaWwuc2xpY2UoLXRyYWlsaW5nQnl0ZXMpXG4gICAgICAgIHFCeXRlTGVuIC09IGxlblxuXG4gICAgICAgIHRpcC5fcmF3XyA9IGNvbmNhdEJ1ZmZlcnMgQCBwYXJ0cywgbGVuXG5cbiAgICAgIDo6XG4gICAgICAgIGNvbnN0IHBrdF9vYmogPSBhc1BrdE9iaih0aXApXG4gICAgICAgIHRpcCA9IG51bGxcbiAgICAgICAgcmV0dXJuIHBrdF9vYmpcblxuIiwiLypcbiAgMDEyMzQ1Njc4OWFiICAgICAtLSAxMi1ieXRlIHBhY2tldCBoZWFkZXIgKGNvbnRyb2wpXG4gIDAxMjM0NTY3ODlhYmNkZWYgLS0gMTYtYnl0ZSBwYWNrZXQgaGVhZGVyIChyb3V0aW5nKVxuICBcbiAgMDEuLi4uLi4uLi4uLi4uLiAtLSB1aW50MTYgc2lnbmF0dXJlID0gMHhGRSAweEVEXG4gIC4uMjMgLi4uLi4uLi4uLi4gLS0gdWludDE2IHBhY2tldCBsZW5ndGhcbiAgLi4uLjQ1Li4uLi4uLi4uLiAtLSB1aW50MTYgaGVhZGVyIGxlbmd0aFxuICAuLi4uLi42Li4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLi43Li4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLi4uLjg5YWIuLi4uIC0tIGludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIGludDMyIGlkX3RhcmdldFxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfaGVhZGVyX2xlbiA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tQYWNrZXQsIGZ3ZEhlYWRlclxuICAgIHBhY2tJZCwgdW5wYWNrSWQsIHBhY2tfdXRmOCwgdW5wYWNrX3V0ZjhcblxuICAgIGFzQnVmZmVyLCBjb25jYXRCdWZmZXJzXG5cblxuICBmdW5jdGlvbiBwYXJzZUhlYWRlcihidWYsIGRlY3JlbWVudF90dGwpIDo6XG4gICAgaWYgcGt0X2hlYWRlcl9sZW4gPiBidWYuYnl0ZUxlbmd0aCA6OiByZXR1cm4gbnVsbFxuXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWZcblxuICAgIGNvbnN0IHNpZyA9IGR2LmdldFVpbnQxNiBAIDAsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBzaWduYXR1cmUgIT09IHNpZyA6OlxuICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCBzdHJlYW0gZnJhbWluZyBlcnJvciAoZm91bmQ6ICR7c2lnLnRvU3RyaW5nKDE2KX0gZXhwZWN0ZWQ6ICR7c2lnbmF0dXJlLnRvU3RyaW5nKDE2KX0pYFxuXG4gICAgLy8gdXAgdG8gNjRrIHBhY2tldCBsZW5ndGg7IGxlbmd0aCBpbmNsdWRlcyBoZWFkZXJcbiAgICBjb25zdCBwYWNrZXRfbGVuID0gZHYuZ2V0VWludDE2IEAgMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldEludDMyIEAgOCwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGlkX3RhcmdldCA9IGR2LmdldEludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyLCBpZF90YXJnZXRcbiAgICByZXR1cm4gQHt9IGluZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuXG5cblxuICBmdW5jdGlvbiBwYWNrUGFja2V0KC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID1cbiAgICAgIDEgPT09IGFyZ3MubGVuZ3RoID8gYXJnc1swXSA6IE9iamVjdC5hc3NpZ24gQCB7fSwgLi4uYXJnc1xuXG4gICAgaWYgISBOdW1iZXIuaXNJbnRlZ2VyKGlkX3JvdXRlcikgOjogdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfcm91dGVyYFxuICAgIGlmIGlkX3RhcmdldCAmJiAhIE51bWJlci5pc0ludGVnZXIoaWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdGhkciA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBwa3RoZHIsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkocGt0aGRyKVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gYXJyYXlcblxuXG4gIGZ1bmN0aW9uIGZ3ZEhlYWRlcihidWYsIGlkX3JvdXRlciwgaWRfdGFyZ2V0KSA6OlxuICAgIGJ1ZiA9IG5ldyBVaW50OEFycmF5KGJ1ZikuYnVmZmVyXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBidWYsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZHYuc2V0SW50MzIgIEAgIDgsIDAgfCBpZF9yb3V0ZXIsIGxpdHRsZV9lbmRpYW5cbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBkdi5zZXRJbnQzMiAgQCAxMiwgMCB8IGlkX3RhcmdldCwgbGl0dGxlX2VuZGlhblxuICAgIHJldHVybiBidWZcblxuXG4gIGZ1bmN0aW9uIHBhY2tJZChpZCwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGJ1ZiA9IG5ldyBBcnJheUJ1ZmZlcig0KVxuICAgIG5ldyBEYXRhVmlldyhidWYpLnNldEludDMyIEAgb2Zmc2V0fHwwLCAwIHwgaWQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG4gIGZ1bmN0aW9uIHVucGFja0lkKGJ1Ziwgb2Zmc2V0KSA6OlxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYXNCdWZmZXIoYnVmKVxuICAgIHJldHVybiBkdi5nZXRJbnQzMiBAIG9mZnNldHx8MCwgbGl0dGxlX2VuZGlhblxuXG4gIGZ1bmN0aW9uIHBhY2tfdXRmOChzdHIpIDo6XG4gICAgY29uc3QgdGUgPSBuZXcgX1RleHRFbmNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZS5lbmNvZGUoc3RyLnRvU3RyaW5nKCkpLmJ1ZmZlclxuICBmdW5jdGlvbiB1bnBhY2tfdXRmOChidWYpIDo6XG4gICAgY29uc3QgdGQgPSBuZXcgX1RleHREZWNvZGVyXygndXRmLTgnKVxuICAgIHJldHVybiB0ZC5kZWNvZGUgQCBhc0J1ZmZlciBAIGJ1ZlxuXG5cbiAgZnVuY3Rpb24gYXNCdWZmZXIoYnVmKSA6OlxuICAgIGlmIG51bGwgPT09IGJ1ZiB8fCB1bmRlZmluZWQgPT09IGJ1ZiA6OlxuICAgICAgcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNJbnRlZ2VyIEAgYnVmWzBdIDo6XG4gICAgICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oYnVmKS5idWZmZXJcbiAgICAgIHJldHVybiBjb25jYXQgQCBidWYubWFwIEAgYXNCdWZmZXJcblxuXG4gIGZ1bmN0aW9uIGNvbmNhdEJ1ZmZlcnMobHN0LCBsZW4pIDo6XG4gICAgaWYgMSA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbHN0WzBdXG4gICAgaWYgMCA9PT0gbHN0Lmxlbmd0aCA6OiByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiBudWxsID09IGxlbiA6OlxuICAgICAgbGVuID0gMFxuICAgICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgICAgbGVuICs9IGFyci5ieXRlTGVuZ3RoXG5cbiAgICBjb25zdCB1OCA9IG5ldyBVaW50OEFycmF5KGxlbilcbiAgICBsZXQgb2Zmc2V0ID0gMFxuICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICB1OC5zZXQgQCBuZXcgVWludDhBcnJheShhcnIpLCBvZmZzZXRcbiAgICAgIG9mZnNldCArPSBhcnIuYnl0ZUxlbmd0aFxuICAgIHJldHVybiB1OC5idWZmZXJcblxuIl0sIm5hbWVzIjpbImFzUGFja2V0UGFyc2VyQVBJIiwicGFja2V0X2ltcGxfbWV0aG9kcyIsInBhY2tQYWNrZXQiLCJmd2RIZWFkZXIiLCJjb25jYXRCdWZmZXJzIiwidW5wYWNrX3V0ZjgiLCJwa3Rfb2JqX3Byb3RvIiwiX3Jhd18iLCJzbGljZSIsImhlYWRlcl9vZmZzZXQiLCJib2R5X29mZnNldCIsImJ1ZiIsImhlYWRlcl9idWZmZXIiLCJKU09OIiwicGFyc2UiLCJoZWFkZXJfdXRmOCIsImJvZHlfYnVmZmVyIiwiYm9keV91dGY4IiwiZndkX2lkIiwiYXNGd2RQa3RPYmoiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tldFBhcnNlciIsInBhY2tQYWNrZXRPYmoiLCJhcmdzIiwicGt0X3JhdyIsInBrdCIsInBhcnNlSGVhZGVyIiwiYXNQa3RPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsInBrdF9vYmoiLCJ2YWx1ZSIsImlkX3JvdXRlciIsImlkX3RhcmdldCIsIkVycm9yIiwicmF3IiwiZndkX29iaiIsImlzX2Z3ZCIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcFBhY2tldCIsInVuZGVmaW5lZCIsImxlbmd0aCIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJkZWZhdWx0X3R0bCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsInBhY2tfdXRmOCIsImR2IiwiRGF0YVZpZXciLCJzaWciLCJnZXRVaW50MTYiLCJ0b1N0cmluZyIsInR5cGUiLCJnZXRVaW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJzZXRVaW50OCIsImdldEludDMyIiwiaGVhZGVyIiwiYm9keSIsIk51bWJlciIsImlzSW50ZWdlciIsInBrdGhkciIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0SW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJhcnJheSIsImJ1ZmZlciIsInBhY2tJZCIsImlkIiwic3RyIiwidGUiLCJlbmNvZGUiLCJ0ZCIsImRlY29kZSIsImlzVmlldyIsInJlYWRJbnQzMkxFIiwiZnJvbSIsIkFycmF5IiwiaXNBcnJheSIsImNvbmNhdCIsIm1hcCIsImxzdCIsImFyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBLEVBQ1NDLFVBRFQsRUFDcUJDLFNBRHJCO1lBQUEsRUFFTUMsYUFGTjtZQUFBLEVBR01DLFdBSE4sS0FJSkosbUJBSkY7O1FBTU1LLGdCQUFnQjtvQkFDSjthQUFVLEtBQUtDLEtBQUwsQ0FBV0MsS0FBWCxDQUFtQixLQUFLQyxhQUF4QixFQUF1QyxLQUFLQyxXQUE1QyxDQUFQO0tBREM7Z0JBRVJDLEdBQVosRUFBaUI7YUFBVU4sWUFBY00sT0FBTyxLQUFLQyxhQUFMLEVBQXJCLENBQVA7S0FGQTtnQkFHUkQsR0FBWixFQUFpQjthQUFVRSxLQUFLQyxLQUFMLENBQWEsS0FBS0MsV0FBTCxDQUFpQkosR0FBakIsS0FB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
