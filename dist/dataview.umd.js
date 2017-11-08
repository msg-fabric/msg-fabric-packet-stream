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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZCwgdW5wYWNrX3V0ZjhcbiAgPSBwYWNrZXRfaW1wbF9tZXRob2RzXG5cbiAgY29uc3QgbXNnX29ial9wcm90byA9IEA6XG4gICAgaGVhZGVyX2J1ZmZlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgaGVhZGVyX3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmhlYWRlcl9idWZmZXIoKVxuICAgIGhlYWRlcl9qc29uKCkgOjogcmV0dXJuIEpTT04ucGFyc2UgQCB0aGlzLmhlYWRlcl91dGY4KCkgfHwgbnVsbFxuXG4gICAgYm9keV9idWZmZXIoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBib2R5X3V0ZjgoKSA6OiByZXR1cm4gdW5wYWNrX3V0ZjggQCB0aGlzLmJvZHlfYnVmZmVyKClcbiAgICBib2R5X2pzb24oKSA6OiByZXR1cm4gSlNPTi5wYXJzZSBAIHRoaXMuYm9keV91dGY4KCkgfHwgbnVsbFxuXG4gICAgdW5wYWNrSWQoYnVmLCBvZmZzZXQ9OCkgOjogcmV0dXJuIHVucGFja0lkKGJ1ZiB8fCB0aGlzLl9yYXdfLCBvZmZzZXQpXG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZyA9IHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIG1zZy5fcmF3XyA9IG1zZ19yYXdcbiAgICByZXR1cm4gYXNNc2dPYmoobXNnKVxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldFVpbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gZHYuZ2V0VWludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX3NpemVcbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBkdi5zZXRVaW50MzIgQCAgOCwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgICBkdi5zZXRVaW50MzIgQCAxMiwgaWRfdGFyZ2V0IHx8IDAsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9zaXplXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIGFycmF5XG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRVaW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0VWludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgbnVsbCA9PT0gYnVmIHx8IHVuZGVmaW5lZCA9PT0gYnVmIDo6XG4gICAgICByZXR1cm4gbmV3IEFycmF5QnVmZmVyKDApXG5cbiAgICBpZiB1bmRlZmluZWQgIT09IGJ1Zi5ieXRlTGVuZ3RoIDo6XG4gICAgICBpZiB1bmRlZmluZWQgPT09IGJ1Zi5idWZmZXIgOjpcbiAgICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgICBpZiBBcnJheUJ1ZmZlci5pc1ZpZXcoYnVmKSA6OlxuICAgICAgICByZXR1cm4gYnVmLmJ1ZmZlclxuXG4gICAgICBpZiAnZnVuY3Rpb24nID09PSB0eXBlb2YgYnVmLnJlYWRVSW50MzJMRSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyIC8vIE5vZGVKUyBCdWZmZXJcblxuICAgICAgcmV0dXJuIGJ1ZlxuXG4gICAgaWYgJ3N0cmluZycgPT09IHR5cGVvZiBidWYgOjpcbiAgICAgIHJldHVybiBwYWNrX3V0ZjgoYnVmKVxuXG4gICAgaWYgQXJyYXkuaXNBcnJheShidWYpIDo6XG4gICAgICBpZiBOdW1iZXIuaXNTYWZlSW50ZWdlciBAIGJ1ZlswXSA6OlxuICAgICAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ1ZikuYnVmZmVyXG4gICAgICByZXR1cm4gY29uY2F0IEAgYnVmLm1hcCBAIGFzQnVmZmVyXG5cblxuICBmdW5jdGlvbiBjb25jYXRCdWZmZXJzKGxzdCwgbGVuKSA6OlxuICAgIGlmIDEgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIGxzdFswXVxuICAgIGlmIDAgPT09IGxzdC5sZW5ndGggOjogcmV0dXJuIG5ldyBBcnJheUJ1ZmZlcigwKVxuXG4gICAgaWYgbnVsbCA9PSBsZW4gOjpcbiAgICAgIGxlbiA9IDBcbiAgICAgIGZvciBjb25zdCBhcnIgb2YgbHN0IDo6XG4gICAgICAgIGxlbiArPSBhcnIuYnl0ZUxlbmd0aFxuXG4gICAgY29uc3QgdTggPSBuZXcgVWludDhBcnJheShsZW4pXG4gICAgbGV0IG9mZnNldCA9IDBcbiAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYXJyKSwgb2Zmc2V0XG4gICAgICBvZmZzZXQgKz0gYXJyLmJ5dGVMZW5ndGhcbiAgICByZXR1cm4gdTguYnVmZmVyXG5cbiJdLCJuYW1lcyI6WyJhc1BhY2tldFBhcnNlckFQSSIsInBhY2tldF9pbXBsX21ldGhvZHMiLCJ1bnBhY2tfdXRmOCIsIm1zZ19vYmpfcHJvdG8iLCJfcmF3XyIsInNsaWNlIiwiaGVhZGVyX29mZnNldCIsImJvZHlfb2Zmc2V0IiwiaGVhZGVyX2J1ZmZlciIsIkpTT04iLCJwYXJzZSIsImhlYWRlcl91dGY4IiwiYm9keV9idWZmZXIiLCJib2R5X3V0ZjgiLCJidWYiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tNZXNzYWdlT2JqIiwiYXJncyIsIm1zZ19yYXciLCJwYWNrTWVzc2FnZSIsIm1zZyIsInBhcnNlSGVhZGVyIiwiYXNNc2dPYmoiLCJpbmZvIiwicGt0X2hlYWRlcl9sZW4iLCJwYWNrZXRfbGVuIiwiaGVhZGVyX2xlbiIsIm1zZ19vYmoiLCJ2YWx1ZSIsInBhY2tldFN0cmVhbSIsIm9wdGlvbnMiLCJkZWNyZW1lbnRfdHRsIiwidGlwIiwicUJ5dGVMZW4iLCJxIiwiZmVlZCIsImRhdGEiLCJjb21wbGV0ZSIsImFzQnVmZmVyIiwicHVzaCIsImJ5dGVMZW5ndGgiLCJwYXJzZVRpcE1lc3NhZ2UiLCJ1bmRlZmluZWQiLCJsZW5ndGgiLCJjb25jYXRCdWZmZXJzIiwibGVuIiwiYnl0ZXMiLCJuIiwidHJhaWxpbmdCeXRlcyIsInBhcnRzIiwic3BsaWNlIiwidGFpbCIsInNpZ25hdHVyZSIsInBrdF9jb250cm9sX2hlYWRlcl9zaXplIiwicGt0X3JvdXRpbmdfaGVhZGVyX3NpemUiLCJkZWZhdWx0X3R0bCIsImxpdHRsZV9lbmRpYW4iLCJjcmVhdGVEYXRhVmlld1BhY2tldFBhcnNlciIsIl9UZXh0RW5jb2Rlcl8iLCJUZXh0RW5jb2RlciIsIl9UZXh0RGVjb2Rlcl8iLCJUZXh0RGVjb2RlciIsInBhY2tfdXRmOCIsImR2IiwiRGF0YVZpZXciLCJzaWciLCJnZXRVaW50MTYiLCJFcnJvciIsInRvU3RyaW5nIiwidHlwZSIsImdldFVpbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsInNldFVpbnQ4IiwiaWRfcm91dGVyIiwiZ2V0VWludDMyIiwiaWRfdGFyZ2V0IiwiaGVhZGVyIiwiYm9keSIsInBrdF9oZWFkZXJfc2l6ZSIsImFycmF5IiwiQXJyYXlCdWZmZXIiLCJzZXRVaW50MTYiLCJzZXRVaW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsInRlIiwiZW5jb2RlIiwiYnVmZmVyIiwidGQiLCJkZWNvZGUiLCJpc1ZpZXciLCJyZWFkVUludDMyTEUiLCJmcm9tIiwiQXJyYXkiLCJpc0FycmF5IiwiTnVtYmVyIiwiaXNTYWZlSW50ZWdlciIsImNvbmNhdCIsIm1hcCIsImxzdCIsImFyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFB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
