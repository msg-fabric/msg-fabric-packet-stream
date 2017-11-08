(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
	typeof define === 'function' && define.amd ? define(factory) :
	(global['msg-fabric-packet-stream/dataview'] = factory());
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
    if (signature !== sig) {
      throw new Error(`Packet stream framing error (found: ${sig.toString(16)} expected: ${signature.toString(16)})`);
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
      return { info, packet_len, header_len, pkt_header_len: pkt_control_header_size };
    } else if (pkt_routing_header_size > buf.byteLength) {
      return null; // this buffer is fragmented before id_target
    } else {
        info.id_target = dv.getUint32(12, little_endian);
        return { info, packet_len, header_len, pkt_header_len: pkt_routing_header_size };
      }
  }

  function packMessage(...args) {
    let { type, ttl, id_router, id_target, header, body } = Object.assign({}, ...args);
    header = asBuffer(header, 'header');
    body = asBuffer(body, 'body');

    const pkt_header_size = id_router ? pkt_routing_header_size : pkt_control_header_size;
    const len = pkt_header_size + header.byteLength + body.byteLength;
    if (len > 0xffff) {
      throw new Error(`Packet too large`);
    }

    const array = new ArrayBuffer(len);

    const dv = new DataView(array, 0, pkt_header_size);
    dv.setUint16(0, signature, little_endian);
    dv.setUint16(2, len, little_endian);
    dv.setUint16(4, header.byteLength, little_endian);
    dv.setUint8(6, type || 0, little_endian);
    dv.setUint8(7, ttl || default_ttl, little_endian);
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

return createDataViewPacketParser;

})));
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKCkgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KCkgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmJvZHlfYnVmZmVyKClcbiAgICBib2R5X2pzb24oKSA6OiByZXR1cm4gSlNPTi5wYXJzZSBAIHRoaXMuYm9keV91dGY4KCkgfHwgbnVsbFxuXG4gICAgdW5wYWNrSWQoYnVmLCBvZmZzZXQ9OCkgOjogcmV0dXJuIHVucGFja0lkKGJ1ZiB8fCB0aGlzLl9yYXdfLCBvZmZzZXQpXG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZ19vYmogPSBhc01zZ09iaiBAIHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0aWVzIEAgbXNnX29iaiwgQDpcbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IG1zZ19yYXdcbiAgICByZXR1cm4gbXNnX29ialxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldFVpbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gZHYuZ2V0VWludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX3NpemVcbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBkdi5zZXRVaW50MzIgQCAgOCwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgICBkdi5zZXRVaW50MzIgQCAxMiwgaWRfdGFyZ2V0IHx8IDAsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9zaXplXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIGFycmF5XG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRVaW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0VWludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRVSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNTYWZlSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJ1bnBhY2tfdXRmOCIsIm1zZ19vYmpfcHJvdG8iLCJfcmF3XyIsInNsaWNlIiwiaGVhZGVyX29mZnNldCIsImJvZHlfb2Zmc2V0IiwiaGVhZGVyX2J1ZmZlciIsIkpTT04iLCJwYXJzZSIsImhlYWRlcl91dGY4IiwiYm9keV9idWZmZXIiLCJib2R5X3V0ZjgiLCJidWYiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tNZXNzYWdlT2JqIiwiYXJncyIsIm1zZ19yYXciLCJwYWNrTWVzc2FnZSIsIm1zZ19vYmoiLCJhc01zZ09iaiIsInBhcnNlSGVhZGVyIiwiZGVmaW5lUHJvcGVydGllcyIsInZhbHVlIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwibXNnIiwicGFyc2VUaXBNZXNzYWdlIiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSIsInBrdF9yb3V0aW5nX2hlYWRlcl9zaXplIiwiZGVmYXVsdF90dGwiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJwYWNrX3V0ZjgiLCJkdiIsIkRhdGFWaWV3Iiwic2lnIiwiZ2V0VWludDE2IiwiRXJyb3IiLCJ0b1N0cmluZyIsInR5cGUiLCJnZXRVaW50OCIsInR0bCIsIk1hdGgiLCJtYXgiLCJzZXRVaW50OCIsImlkX3JvdXRlciIsImdldFVpbnQzMiIsImlkX3RhcmdldCIsImhlYWRlciIsImJvZHkiLCJwa3RfaGVhZGVyX3NpemUiLCJhcnJheSIsIkFycmF5QnVmZmVyIiwic2V0VWludDE2Iiwic2V0VWludDMyIiwidTgiLCJVaW50OEFycmF5Iiwic2V0IiwicGFja0lkIiwiaWQiLCJzdHIiLCJ0ZSIsImVuY29kZSIsImJ1ZmZlciIsInRkIiwiZGVjb2RlIiwiaXNWaWV3IiwicmVhZFVJbnQzMkxFIiwiZnJvbSIsIkFycmF5IiwiaXNBcnJheSIsIk51bWJlciIsImlzU2FmZUludGVnZXIiLCJjb25jYXQiLCJtYXAiLCJsc3QiLCJh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
