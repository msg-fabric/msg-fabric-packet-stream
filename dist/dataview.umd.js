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

  function packPacketObj(pkt_info) {
    const pkt_raw = packPacket(pkt_info);
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

  function packPacket(pkt_info) {
    let { type, ttl, id_router, id_target, header, body } = pkt_info;

    if (Number.isNaN(+id_router)) {
      throw new Error(`Invalid id_router`);
    }
    if (id_target && Number.isNaN(+id_target)) {
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
    return pkthdr;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyLCBwYWNrUGFja2V0LCBmd2RIZWFkZXJcbiAgICBhc0J1ZmZlciwgY29uY2F0QnVmZmVyc1xuICAgIHVucGFja0lkLCB1bnBhY2tfdXRmOFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBwa3Rfb2JqX3Byb3RvID0gQHt9XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoYnVmKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCBidWYgfHwgdGhpcy5oZWFkZXJfYnVmZmVyKClcbiAgICBoZWFkZXJfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5oZWFkZXJfdXRmOChidWYpIHx8IG51bGxcblxuICAgIGJvZHlfYnVmZmVyKCkgOjogcmV0dXJuIHRoaXMuX3Jhd18uc2xpY2UgQCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgYm9keV91dGY4KGJ1ZikgOjogcmV0dXJuIHVucGFja191dGY4IEAgYnVmIHx8IHRoaXMuYm9keV9idWZmZXIoKVxuICAgIGJvZHlfanNvbihidWYpIDo6IHJldHVybiBKU09OLnBhcnNlIEAgdGhpcy5ib2R5X3V0ZjgoYnVmKSB8fCBudWxsXG5cbiAgICBmd2RfdG8oZndkX2lkKSA6OiByZXR1cm4gYXNGd2RQa3RPYmogQCB0aGlzLCBmd2RfaWRcbiAgICB1bnBhY2tJZChidWYsIG9mZnNldD04KSA6OiByZXR1cm4gdW5wYWNrSWQoYnVmIHx8IHRoaXMuX3Jhd18sIG9mZnNldClcbiAgICB1bnBhY2tfdXRmOFxuXG4gIGNvbnN0IHBhY2tldFBhcnNlckFQSSA9IE9iamVjdC5hc3NpZ24gQFxuICAgIE9iamVjdC5jcmVhdGUobnVsbClcbiAgICBwYWNrZXRfaW1wbF9tZXRob2RzXG4gICAgQHt9XG4gICAgICBpc1BhY2tldFBhcnNlcigpIDo6IHJldHVybiB0cnVlXG4gICAgICBwYWNrUGFja2V0T2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzUGt0T2JqLCBhc0Z3ZFBrdE9ialxuICAgICAgcGt0X29ial9wcm90b1xuXG4gIHBrdF9vYmpfcHJvdG8ucGFja2V0UGFyc2VyID0gcGFja2V0UGFyc2VyQVBJXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXRPYmoocGt0X2luZm8pIDo6XG4gICAgY29uc3QgcGt0X3JhdyA9IHBhY2tQYWNrZXQgQCBwa3RfaW5mb1xuICAgIGNvbnN0IHBrdCA9IHBhcnNlSGVhZGVyIEAgcGt0X3Jhd1xuICAgIHBrdC5fcmF3XyA9IHBrdF9yYXdcbiAgICByZXR1cm4gYXNQa3RPYmoocGt0KVxuXG5cbiAgZnVuY3Rpb24gYXNQa3RPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBwYWNrZXQgY29uc3RydWN0aW9uXG5cbiAgICBjb25zdCBwa3Rfb2JqID0gT2JqZWN0LmNyZWF0ZSBAIHBrdF9vYmpfcHJvdG8sIEB7fVxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgcGt0X29iaiwgaW5mb1xuXG4gIGZ1bmN0aW9uIGFzRndkUGt0T2JqKHBrdF9vYmosIHtpZF9yb3V0ZXIsIGlkX3RhcmdldH0pIDo6XG4gICAgaWYgbnVsbCA9PSBpZF90YXJnZXQgOjogdGhyb3cgbmV3IEVycm9yIEAgJ2lkX3RhcmdldCByZXF1aXJlZCdcbiAgICBjb25zdCByYXcgPSBmd2RIZWFkZXIgQCBwa3Rfb2JqLl9yYXdfLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIGNvbnN0IGZ3ZF9vYmogPSBPYmplY3QuY3JlYXRlIEAgcGt0X29iaiwgQHt9IF9yYXdfOiBAe30gdmFsdWU6IF9yYXdfXG4gICAgaWYgbnVsbCAhPSBpZF9yb3V0ZXIgOjogZndkX29iai5pZF9yb3V0ZXIgPSBpZF9yb3V0ZXJcbiAgICBpZiBudWxsICE9IGlkX3RhcmdldCA6OiBmd2Rfb2JqLmlkX3RhcmdldCA9IGlkX3RhcmdldFxuICAgIGZ3ZF9vYmouaXNfZndkID0gdHJ1ZVxuICAgIHJldHVybiBmd2Rfb2JqXG5cblxuICBmdW5jdGlvbiBwYWNrZXRTdHJlYW0ob3B0aW9ucykgOjpcbiAgICBpZiAhIG9wdGlvbnMgOjogb3B0aW9ucyA9IHt9XG5cbiAgICBjb25zdCBkZWNyZW1lbnRfdHRsID1cbiAgICAgIG51bGwgPT0gb3B0aW9ucy5kZWNyZW1lbnRfdHRsXG4gICAgICAgID8gdHJ1ZSA6ICEhIG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuXG4gICAgbGV0IHRpcD1udWxsLCBxQnl0ZUxlbiA9IDAsIHEgPSBbXVxuICAgIHJldHVybiBmZWVkXG5cbiAgICBmdW5jdGlvbiBmZWVkKGRhdGEsIGNvbXBsZXRlPVtdKSA6OlxuICAgICAgZGF0YSA9IGFzQnVmZmVyKGRhdGEpXG4gICAgICBxLnB1c2ggQCBkYXRhXG4gICAgICBxQnl0ZUxlbiArPSBkYXRhLmJ5dGVMZW5ndGhcblxuICAgICAgd2hpbGUgMSA6OlxuICAgICAgICBjb25zdCBwa3QgPSBwYXJzZVRpcFBhY2tldCgpXG4gICAgICAgIGlmIHVuZGVmaW5lZCAhPT0gcGt0IDo6XG4gICAgICAgICAgY29tcGxldGUucHVzaCBAIHBrdFxuICAgICAgICBlbHNlIHJldHVybiBjb21wbGV0ZVxuXG5cbiAgICBmdW5jdGlvbiBwYXJzZVRpcFBhY2tldCgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgcGt0X29iaiA9IGFzUGt0T2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gcGt0X29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuICAuLi4uNDUuLi4uLi4uLi4uIC0tIHVpbnQxNiBoZWFkZXIgbGVuZ3RoXG4gIC4uLi4uLjYuLi4uLi4uLi4gLS0gdWludDggaGVhZGVyIHR5cGVcbiAgLi4uLi4uLjcuLi4uLi4uLiAtLSB1aW50OCB0dGwgaG9wc1xuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gaW50MzIgaWRfcm91dGVyXG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuXG4gIC4uLi4uLi4uLi4uLmNkZWYgLS0gaW50MzIgaWRfdGFyZ2V0XG4gICAgICAgICAgICAgICAgICAgICAgNC1ieXRlIHJhbmRvbSBzcGFjZSBhbGxvd3MgMSBtaWxsaW9uIG5vZGVzIHdpdGhcbiAgICAgICAgICAgICAgICAgICAgICAwLjAyJSBjaGFuY2Ugb2YgdHdvIG5vZGVzIHNlbGVjdGluZyB0aGUgc2FtZSBpZFxuICovXG5cbmltcG9ydCBhc1BhY2tldFBhcnNlckFQSSBmcm9tICcuL2Jhc2ljJ1xuXG5jb25zdCBzaWduYXR1cmUgPSAweGVkZmVcbmNvbnN0IHBrdF9oZWFkZXJfbGVuID0gMTZcbmNvbnN0IGRlZmF1bHRfdHRsID0gMzFcblxuY29uc3QgbGl0dGxlX2VuZGlhbiA9IHRydWVcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIob3B0aW9ucz17fSkgOjpcbiAgY29uc3QgX1RleHRFbmNvZGVyXyA9IG9wdGlvbnMuVGV4dEVuY29kZXIgfHwgVGV4dEVuY29kZXJcbiAgY29uc3QgX1RleHREZWNvZGVyXyA9IG9wdGlvbnMuVGV4dERlY29kZXIgfHwgVGV4dERlY29kZXJcblxuICByZXR1cm4gYXNQYWNrZXRQYXJzZXJBUEkgQDpcbiAgICBwYXJzZUhlYWRlciwgcGFja1BhY2tldCwgZndkSGVhZGVyXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBpZiBwa3RfaGVhZGVyX2xlbiA+IGJ1Zi5ieXRlTGVuZ3RoIDo6IHJldHVybiBudWxsXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaGVhZGVyX2xlbiA9IGR2LmdldFVpbnQxNiBAIDQsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCB0eXBlID0gZHYuZ2V0VWludDggQCA2LCBsaXR0bGVfZW5kaWFuXG5cbiAgICBsZXQgdHRsID0gZHYuZ2V0VWludDggQCA3LCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgZGVjcmVtZW50X3R0bCA6OlxuICAgICAgdHRsID0gTWF0aC5tYXggQCAwLCB0dGwgLSAxXG4gICAgICBkdi5zZXRVaW50OCBAIDcsIHR0bCwgbGl0dGxlX2VuZGlhblxuXG4gICAgY29uc3QgaWRfcm91dGVyID0gZHYuZ2V0SW50MzIgQCA4LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgaWRfdGFyZ2V0ID0gZHYuZ2V0SW50MzIgQCAxMiwgbGl0dGxlX2VuZGlhblxuICAgIGNvbnN0IGluZm8gPSBAe30gdHlwZSwgdHRsLCBpZF9yb3V0ZXIsIGlkX3RhcmdldFxuICAgIHJldHVybiBAe30gaW5mbywgcGt0X2hlYWRlcl9sZW4sIHBhY2tldF9sZW4sIGhlYWRlcl9sZW5cblxuXG4gIGZ1bmN0aW9uIHBhY2tQYWNrZXQocGt0X2luZm8pIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gcGt0X2luZm9cblxuICAgIGlmIE51bWJlci5pc05hTigraWRfcm91dGVyKSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF9yb3V0ZXJgXG4gICAgaWYgaWRfdGFyZ2V0ICYmIE51bWJlci5pc05hTigraWRfdGFyZ2V0KSA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgSW52YWxpZCBpZF90YXJnZXRgXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXIuYnl0ZUxlbmd0aCArIGJvZHkuYnl0ZUxlbmd0aFxuICAgIGlmIGxlbiA+IDB4ZmZmZiA6OiB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHRvbyBsYXJnZWBcblxuICAgIGNvbnN0IHBrdGhkciA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG4gICAgY29uc3QgZHYgPSBuZXcgRGF0YVZpZXcgQCBwa3RoZHIsIDAsIHBrdF9oZWFkZXJfbGVuXG4gICAgZHYuc2V0VWludDE2IEAgIDAsIHNpZ25hdHVyZSwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICAyLCBsZW4sIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50MTYgQCAgNCwgaGVhZGVyLmJ5dGVMZW5ndGgsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNiwgdHlwZSB8fCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDggIEAgIDcsIHR0bCB8fCBkZWZhdWx0X3R0bCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkocGt0aGRyKVxuICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGhlYWRlciksIHBrdF9oZWFkZXJfbGVuXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfbGVuICsgaGVhZGVyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gcGt0aGRyXG5cblxuICBmdW5jdGlvbiBmd2RIZWFkZXIoYnVmLCBpZF9yb3V0ZXIsIGlkX3RhcmdldCkgOjpcbiAgICBidWYgPSBuZXcgVWludDhBcnJheShidWYpLmJ1ZmZlclxuICAgIGNvbnN0IGR2ID0gbmV3IERhdGFWaWV3IEAgYnVmLCAwLCBwa3RfaGVhZGVyX2xlblxuICAgIGlmIG51bGwgIT0gaWRfcm91dGVyIDo6IGR2LnNldEludDMyICBAICA4LCAwIHwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgbnVsbCAhPSBpZF90YXJnZXQgOjogZHYuc2V0SW50MzIgIEAgMTIsIDAgfCBpZF90YXJnZXQsIGxpdHRsZV9lbmRpYW5cbiAgICByZXR1cm4gYnVmXG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRJbnQzMiBAIG9mZnNldHx8MCwgMCB8IGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0SW50MzIgQCBvZmZzZXR8fDAsIGxpdHRsZV9lbmRpYW5cblxuICBmdW5jdGlvbiBwYWNrX3V0Zjgoc3RyKSA6OlxuICAgIGNvbnN0IHRlID0gbmV3IF9UZXh0RW5jb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGUuZW5jb2RlKHN0ci50b1N0cmluZygpKS5idWZmZXJcbiAgZnVuY3Rpb24gdW5wYWNrX3V0ZjgoYnVmKSA6OlxuICAgIGNvbnN0IHRkID0gbmV3IF9UZXh0RGVjb2Rlcl8oJ3V0Zi04JylcbiAgICByZXR1cm4gdGQuZGVjb2RlIEAgYXNCdWZmZXIgQCBidWZcblxuXG4gIGZ1bmN0aW9uIGFzQnVmZmVyKGJ1ZikgOjpcbiAgICBpZiBudWxsID09PSBidWYgfHwgdW5kZWZpbmVkID09PSBidWYgOjpcbiAgICAgIHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIHVuZGVmaW5lZCAhPT0gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIGlmIHVuZGVmaW5lZCA9PT0gYnVmLmJ1ZmZlciA6OlxuICAgICAgICByZXR1cm4gYnVmXG5cbiAgICAgIGlmIEFycmF5QnVmZmVyLmlzVmlldyhidWYpIDo6XG4gICAgICAgIHJldHVybiBidWYuYnVmZmVyXG5cbiAgICAgIGlmICdmdW5jdGlvbicgPT09IHR5cGVvZiBidWYucmVhZEludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJwYWNrUGFja2V0IiwiZndkSGVhZGVyIiwiY29uY2F0QnVmZmVycyIsInVucGFja191dGY4IiwicGt0X29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJoZWFkZXJfb2Zmc2V0IiwiYm9keV9vZmZzZXQiLCJidWYiLCJoZWFkZXJfYnVmZmVyIiwiSlNPTiIsInBhcnNlIiwiaGVhZGVyX3V0ZjgiLCJib2R5X2J1ZmZlciIsImJvZHlfdXRmOCIsImZ3ZF9pZCIsImFzRndkUGt0T2JqIiwib2Zmc2V0IiwidW5wYWNrSWQiLCJwYWNrZXRQYXJzZXJBUEkiLCJPYmplY3QiLCJhc3NpZ24iLCJjcmVhdGUiLCJwYWNrZXRQYXJzZXIiLCJwYWNrUGFja2V0T2JqIiwicGt0X2luZm8iLCJwa3RfcmF3IiwicGt0IiwicGFyc2VIZWFkZXIiLCJhc1BrdE9iaiIsImluZm8iLCJwa3RfaGVhZGVyX2xlbiIsInBhY2tldF9sZW4iLCJoZWFkZXJfbGVuIiwicGt0X29iaiIsInZhbHVlIiwiaWRfcm91dGVyIiwiaWRfdGFyZ2V0IiwiRXJyb3IiLCJyYXciLCJmd2Rfb2JqIiwiaXNfZndkIiwicGFja2V0U3RyZWFtIiwib3B0aW9ucyIsImRlY3JlbWVudF90dGwiLCJ0aXAiLCJxQnl0ZUxlbiIsInEiLCJmZWVkIiwiZGF0YSIsImNvbXBsZXRlIiwiYXNCdWZmZXIiLCJwdXNoIiwiYnl0ZUxlbmd0aCIsInBhcnNlVGlwUGFja2V0IiwidW5kZWZpbmVkIiwibGVuZ3RoIiwibGVuIiwiYnl0ZXMiLCJuIiwidHJhaWxpbmdCeXRlcyIsInBhcnRzIiwic3BsaWNlIiwidGFpbCIsInNpZ25hdHVyZSIsImRlZmF1bHRfdHRsIiwibGl0dGxlX2VuZGlhbiIsImNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyIiwiX1RleHRFbmNvZGVyXyIsIlRleHRFbmNvZGVyIiwiX1RleHREZWNvZGVyXyIsIlRleHREZWNvZGVyIiwicGFja191dGY4IiwiZHYiLCJEYXRhVmlldyIsInNpZyIsImdldFVpbnQxNiIsInRvU3RyaW5nIiwidHlwZSIsImdldFVpbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsInNldFVpbnQ4IiwiZ2V0SW50MzIiLCJoZWFkZXIiLCJib2R5IiwiTnVtYmVyIiwiaXNOYU4iLCJwa3RoZHIiLCJBcnJheUJ1ZmZlciIsInNldFVpbnQxNiIsInNldEludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwiYnVmZmVyIiwicGFja0lkIiwiaWQiLCJzdHIiLCJ0ZSIsImVuY29kZSIsInRkIiwiZGVjb2RlIiwiaXNWaWV3IiwicmVhZEludDMyTEUiLCJmcm9tIiwiQXJyYXkiLCJpc0FycmF5IiwiaXNJbnRlZ2VyIiwiY29uY2F0IiwibWFwIiwibHN0IiwiYXJyIl0sIm1hcHBpbmdzIjoiOzs7Ozs7QUFDZSxTQUFTQSxpQkFBVCxDQUEyQkMsbUJBQTNCLEVBQWdEO1FBQ3ZEO2VBQUEsRUFDU0MsVUFEVCxFQUNxQkMsU0FEckI7WUFBQSxFQUVNQyxhQUZOO1lBQUEsRUFHTUMsV0FITixLQUlKSixtQkFKRjs7UUFNTUssZ0JBQWdCO29CQUNKO2FBQVUsS0FBS0MsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtDLGFBQXhCLEVBQXVDLEtBQUtDLFdBQTVDLENBQVA7S0FEQztnQkFFUkMsR0FBWixFQUFpQjthQUFVTixZQUFjTSxPQUFPLEtBQUtDLGFBQUwsRUFBckIsQ0FBUDtLQUZBO2dCQUdSRCxHQUFaLEVBQWlCO2FBQVVFLEtBQUtDLEtBQUwsQ0FBYSxLQUFLQyxXQUFMLENBQWlCSixHQUFqQixLQUF5QixJQUF0QyxDQUFQO0tBSEE7O2tCQUtOO2FBQVUsS0FBS0osS0FBTCxDQUFXQyxLQUFYLENBQW1C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
