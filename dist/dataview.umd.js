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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGF0YXZpZXcudW1kLmpzIiwic291cmNlcyI6WyIuLi9jb2RlL2Jhc2ljLmpzIiwiLi4vY29kZS9kYXRhdmlldy5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGFzUGFja2V0UGFyc2VyQVBJKHBhY2tldF9pbXBsX21ldGhvZHMpIDo6XG4gIGNvbnN0IEB7fVxuICAgIHBhcnNlSGVhZGVyXG4gICAgcGFja01lc3NhZ2VcbiAgICBhc0J1ZmZlclxuICAgIGNvbmNhdEJ1ZmZlcnNcbiAgICB1bnBhY2tJZFxuICA9IHBhY2tldF9pbXBsX21ldGhvZHNcblxuICBjb25zdCBtc2dfb2JqX3Byb3RvID0gQDpcbiAgICBzbGljZUJvZHkoKSA6OiByZXR1cm4gdGhpcy5fcmF3Xy5zbGljZSBAIHRoaXMuYm9keV9vZmZzZXRcbiAgICBzbGljZUhlYWRlcigpIDo6IHJldHVybiB0aGlzLl9yYXdfLnNsaWNlIEAgdGhpcy5oZWFkZXJfb2Zmc2V0LCB0aGlzLmJvZHlfb2Zmc2V0XG4gICAgdW5wYWNrSWQoYnVmLCBvZmZzZXQ9OCkgOjogcmV0dXJuIHVucGFja0lkKGJ1ZiB8fCB0aGlzLl9yYXdfLCBvZmZzZXQpXG5cbiAgY29uc3QgcGFja2V0UGFyc2VyQVBJID0gT2JqZWN0LmFzc2lnbiBAXG4gICAgT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHBhY2tldF9pbXBsX21ldGhvZHNcbiAgICBAe31cbiAgICAgIHBhY2tNZXNzYWdlT2JqXG4gICAgICBwYWNrZXRTdHJlYW1cbiAgICAgIGFzTXNnT2JqXG4gICAgICBtc2dfb2JqX3Byb3RvXG4gIHJldHVybiBwYWNrZXRQYXJzZXJBUElcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlT2JqKC4uLmFyZ3MpIDo6XG4gICAgY29uc3QgbXNnX3JhdyA9IHBhY2tNZXNzYWdlIEAgLi4uYXJnc1xuICAgIGNvbnN0IG1zZ19vYmogPSBhc01zZ09iaiBAIHBhcnNlSGVhZGVyIEAgbXNnX3Jhd1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0aWVzIEAgbXNnX29iaiwgQDpcbiAgICAgIF9yYXdfOiBAe30gdmFsdWU6IG1zZ19yYXdcbiAgICByZXR1cm4gbXNnX29ialxuXG5cbiAgZnVuY3Rpb24gYXNNc2dPYmooe2luZm8sIHBrdF9oZWFkZXJfbGVuLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBfcmF3X30pIDo6XG4gICAgbGV0IGJvZHlfb2Zmc2V0ID0gcGt0X2hlYWRlcl9sZW4gKyBoZWFkZXJfbGVuXG4gICAgaWYgYm9keV9vZmZzZXQgPiBwYWNrZXRfbGVuIDo6XG4gICAgICBib2R5X29mZnNldCA9IG51bGwgLy8gaW52YWxpZCBtZXNzYWdlIGNvbnN0cnVjdGlvblxuXG4gICAgY29uc3QgbXNnX29iaiA9IE9iamVjdC5jcmVhdGUgQCBtc2dfb2JqX3Byb3RvLCBAOlxuICAgICAgaGVhZGVyX29mZnNldDogQHt9IHZhbHVlOiBwa3RfaGVhZGVyX2xlblxuICAgICAgYm9keV9vZmZzZXQ6IEB7fSB2YWx1ZTogYm9keV9vZmZzZXRcbiAgICAgIHBhY2tldF9sZW46IEB7fSB2YWx1ZTogcGFja2V0X2xlblxuICAgICAgX3Jhd186IEB7fSB2YWx1ZTogX3Jhd19cblxuICAgIHJldHVybiBPYmplY3QuYXNzaWduIEAgbXNnX29iaiwgaW5mb1xuXG5cbiAgZnVuY3Rpb24gcGFja2V0U3RyZWFtKG9wdGlvbnMpIDo6XG4gICAgaWYgISBvcHRpb25zIDo6IG9wdGlvbnMgPSB7fVxuXG4gICAgY29uc3QgZGVjcmVtZW50X3R0bCA9XG4gICAgICBudWxsID09IG9wdGlvbnMuZGVjcmVtZW50X3R0bFxuICAgICAgICA/IHRydWUgOiAhISBvcHRpb25zLmRlY3JlbWVudF90dGxcblxuICAgIGxldCB0aXA9bnVsbCwgcUJ5dGVMZW4gPSAwLCBxID0gW11cbiAgICByZXR1cm4gZmVlZFxuXG4gICAgZnVuY3Rpb24gZmVlZChkYXRhLCBjb21wbGV0ZT1bXSkgOjpcbiAgICAgIGRhdGEgPSBhc0J1ZmZlcihkYXRhKVxuICAgICAgcS5wdXNoIEAgZGF0YVxuICAgICAgcUJ5dGVMZW4gKz0gZGF0YS5ieXRlTGVuZ3RoXG5cbiAgICAgIHdoaWxlIDEgOjpcbiAgICAgICAgY29uc3QgbXNnID0gcGFyc2VUaXBNZXNzYWdlKClcbiAgICAgICAgaWYgdW5kZWZpbmVkICE9PSBtc2cgOjpcbiAgICAgICAgICBjb21wbGV0ZS5wdXNoIEAgbXNnXG4gICAgICAgIGVsc2UgcmV0dXJuIGNvbXBsZXRlXG5cblxuICAgIGZ1bmN0aW9uIHBhcnNlVGlwTWVzc2FnZSgpIDo6XG4gICAgICBpZiBudWxsID09PSB0aXAgOjpcbiAgICAgICAgaWYgMCA9PT0gcS5sZW5ndGggOjpcbiAgICAgICAgICByZXR1cm5cbiAgICAgICAgaWYgMSA8IHEubGVuZ3RoIDo6XG4gICAgICAgICAgcSA9IEBbXSBjb25jYXRCdWZmZXJzIEAgcSwgcUJ5dGVMZW5cblxuICAgICAgICB0aXAgPSBwYXJzZUhlYWRlciBAIHFbMF0sIGRlY3JlbWVudF90dGxcbiAgICAgICAgaWYgbnVsbCA9PT0gdGlwIDo6IHJldHVyblxuXG4gICAgICBjb25zdCBsZW4gPSB0aXAucGFja2V0X2xlblxuICAgICAgaWYgcUJ5dGVMZW4gPCBsZW4gOjpcbiAgICAgICAgcmV0dXJuXG5cbiAgICAgIGxldCBieXRlcyA9IDAsIG4gPSAwXG4gICAgICB3aGlsZSBieXRlcyA8IGxlbiA6OlxuICAgICAgICBieXRlcyArPSBxW24rK10uYnl0ZUxlbmd0aFxuXG4gICAgICBjb25zdCB0cmFpbGluZ0J5dGVzID0gYnl0ZXMgLSBsZW5cbiAgICAgIGlmIDAgPT09IHRyYWlsaW5nQnl0ZXMgOjogLy8gd2UgaGF2ZSBhbiBleGFjdCBsZW5ndGggbWF0Y2hcbiAgICAgICAgY29uc3QgcGFydHMgPSBxLnNwbGljZSgwLCBuKVxuICAgICAgICBxQnl0ZUxlbiAtPSBsZW5cblxuICAgICAgICB0aXAuX3Jhd18gPSBjb25jYXRCdWZmZXJzIEAgcGFydHMsIGxlblxuXG4gICAgICBlbHNlIDo6IC8vIHdlIGhhdmUgdHJhaWxpbmcgYnl0ZXMgb24gdGhlIGxhc3QgYXJyYXlcbiAgICAgICAgY29uc3QgcGFydHMgPSAxID09PSBxLmxlbmd0aCA/IFtdIDogcS5zcGxpY2UoMCwgbi0xKVxuICAgICAgICBjb25zdCB0YWlsID0gcVswXVxuXG4gICAgICAgIHBhcnRzLnB1c2ggQCB0YWlsLnNsaWNlKDAsIC10cmFpbGluZ0J5dGVzKVxuICAgICAgICBxWzBdID0gdGFpbC5zbGljZSgtdHJhaWxpbmdCeXRlcylcbiAgICAgICAgcUJ5dGVMZW4gLT0gbGVuXG5cbiAgICAgICAgdGlwLl9yYXdfID0gY29uY2F0QnVmZmVycyBAIHBhcnRzLCBsZW5cblxuICAgICAgOjpcbiAgICAgICAgY29uc3QgbXNnX29iaiA9IGFzTXNnT2JqKHRpcClcbiAgICAgICAgdGlwID0gbnVsbFxuICAgICAgICByZXR1cm4gbXNnX29ialxuXG4iLCIvKlxuICAwMTIzNDU2Nzg5YWIgICAgIC0tIDEyLWJ5dGUgcGFja2V0IGhlYWRlciAoY29udHJvbClcbiAgMDEyMzQ1Njc4OWFiY2RlZiAtLSAxNi1ieXRlIHBhY2tldCBoZWFkZXIgKHJvdXRpbmcpXG4gIFxuICAwMS4uLi4uLi4uLi4uLi4uIC0tIHVpbnQxNiBzaWduYXR1cmUgPSAweEZFIDB4RURcbiAgLi4yMyAuLi4uLi4uLi4uLiAtLSB1aW50MTYgcGFja2V0IGxlbmd0aFxuXG4gIC4uLi40Li4uLi4uLi4uLi4gLS0gdWludDggdHRsIGhvcHNcblxuICAuLi4uLjUuLi4uLi4uLi4uIC0tIHVpbnQ4IGhlYWRlciB0eXBlXG4gIC4uLi4uLjY3Li4uLi4uLi4gLS0gdWludDggaGVhZGVyIGxlbmd0aFxuXG4gIC4uLi4uLi4uODlhYi4uLi4gLS0gdWludDMyIGlkX3JvdXRlclxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcblxuICAuLi4uLi4uLi4uLi5jZGVmIC0tIHVpbnQzMiBpZF90YXJnZXQgKHdoZW4gaWRfcm91dGVyICE9PSAwKVxuICAgICAgICAgICAgICAgICAgICAgIDQtYnl0ZSByYW5kb20gc3BhY2UgYWxsb3dzIDEgbWlsbGlvbiBub2RlcyB3aXRoXG4gICAgICAgICAgICAgICAgICAgICAgMC4wMiUgY2hhbmNlIG9mIHR3byBub2RlcyBzZWxlY3RpbmcgdGhlIHNhbWUgaWRcbiAqL1xuXG5pbXBvcnQgYXNQYWNrZXRQYXJzZXJBUEkgZnJvbSAnLi9iYXNpYydcblxuY29uc3Qgc2lnbmF0dXJlID0gMHhlZGZlXG5jb25zdCBwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSA9IDEyXG5jb25zdCBwa3Rfcm91dGluZ19oZWFkZXJfc2l6ZSA9IDE2XG5jb25zdCBkZWZhdWx0X3R0bCA9IDMxXG5cbmNvbnN0IGxpdHRsZV9lbmRpYW4gPSB0cnVlXG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNyZWF0ZURhdGFWaWV3UGFja2V0UGFyc2VyKG9wdGlvbnM9e30pIDo6XG4gIGNvbnN0IF9UZXh0RW5jb2Rlcl8gPSBvcHRpb25zLlRleHRFbmNvZGVyIHx8IFRleHRFbmNvZGVyXG4gIGNvbnN0IF9UZXh0RGVjb2Rlcl8gPSBvcHRpb25zLlRleHREZWNvZGVyIHx8IFRleHREZWNvZGVyXG5cbiAgcmV0dXJuIGFzUGFja2V0UGFyc2VyQVBJIEA6XG4gICAgcGFyc2VIZWFkZXIsIHBhY2tNZXNzYWdlXG4gICAgcGFja0lkLCB1bnBhY2tJZCwgcGFja191dGY4LCB1bnBhY2tfdXRmOFxuXG4gICAgYXNCdWZmZXIsIGNvbmNhdEJ1ZmZlcnNcblxuXG4gIGZ1bmN0aW9uIHBhcnNlSGVhZGVyKGJ1ZiwgZGVjcmVtZW50X3R0bCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGJ1ZlxuXG4gICAgY29uc3Qgc2lnID0gZHYuZ2V0VWludDE2IEAgMCwgbGl0dGxlX2VuZGlhblxuICAgIGlmIHNpZ25hdHVyZSAhPT0gc2lnIDo6XG4gICAgICB0aHJvdyBuZXcgRXJyb3IgQCBgUGFja2V0IHN0cmVhbSBmcmFtaW5nIGVycm9yIChmb3VuZDogJHtzaWcudG9TdHJpbmcoMTYpfSBleHBlY3RlZDogJHtzaWduYXR1cmUudG9TdHJpbmcoMTYpfSlgXG5cbiAgICAvLyB1cCB0byA2NGsgcGFja2V0IGxlbmd0aDsgbGVuZ3RoIGluY2x1ZGVzIGhlYWRlclxuICAgIGNvbnN0IHBhY2tldF9sZW4gPSBkdi5nZXRVaW50MTYgQCAyLCBsaXR0bGVfZW5kaWFuXG4gICAgbGV0IGhlYWRlcl9sZW4gPSBkdi5nZXRVaW50MTYgQCA0LCBsaXR0bGVfZW5kaWFuXG4gICAgY29uc3QgdHlwZSA9IGR2LmdldFVpbnQ4IEAgNiwgbGl0dGxlX2VuZGlhblxuXG4gICAgbGV0IHR0bCA9IGR2LmdldFVpbnQ4IEAgNywgbGl0dGxlX2VuZGlhblxuICAgIGlmIGRlY3JlbWVudF90dGwgOjpcbiAgICAgIHR0bCA9IE1hdGgubWF4IEAgMCwgdHRsIC0gMVxuICAgICAgZHYuc2V0VWludDggQCA3LCB0dGwsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IGlkX3JvdXRlciA9IGR2LmdldFVpbnQzMiBAIDgsIGxpdHRsZV9lbmRpYW5cbiAgICBjb25zdCBpbmZvID0gQHt9IHR5cGUsIHR0bCwgaWRfcm91dGVyXG5cbiAgICBpZiAwID09PSBpZF9yb3V0ZXIgOjpcbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X2NvbnRyb2xfaGVhZGVyX3NpemVcbiAgICBlbHNlIGlmIHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplID4gYnVmLmJ5dGVMZW5ndGggOjpcbiAgICAgIHJldHVybiBudWxsIC8vIHRoaXMgYnVmZmVyIGlzIGZyYWdtZW50ZWQgYmVmb3JlIGlkX3RhcmdldFxuICAgIGVsc2UgOjpcbiAgICAgIGluZm8uaWRfdGFyZ2V0ID0gZHYuZ2V0VWludDMyIEAgMTIsIGxpdHRsZV9lbmRpYW5cbiAgICAgIHJldHVybiBAOiBpbmZvLCBwYWNrZXRfbGVuLCBoZWFkZXJfbGVuLCBwa3RfaGVhZGVyX2xlbjogcGt0X3JvdXRpbmdfaGVhZGVyX3NpemVcblxuXG4gIGZ1bmN0aW9uIHBhY2tNZXNzYWdlKC4uLmFyZ3MpIDo6XG4gICAgbGV0IHt0eXBlLCB0dGwsIGlkX3JvdXRlciwgaWRfdGFyZ2V0LCBoZWFkZXIsIGJvZHl9ID0gT2JqZWN0LmFzc2lnbiBAIHt9LCAuLi5hcmdzXG4gICAgaGVhZGVyID0gYXNCdWZmZXIoaGVhZGVyLCAnaGVhZGVyJylcbiAgICBib2R5ID0gYXNCdWZmZXIoYm9keSwgJ2JvZHknKVxuXG4gICAgY29uc3QgcGt0X2hlYWRlcl9zaXplID0gaWRfcm91dGVyXG4gICAgICA/IHBrdF9yb3V0aW5nX2hlYWRlcl9zaXplXG4gICAgICA6IHBrdF9jb250cm9sX2hlYWRlcl9zaXplXG4gICAgY29uc3QgbGVuID0gcGt0X2hlYWRlcl9zaXplICsgaGVhZGVyLmJ5dGVMZW5ndGggKyBib2R5LmJ5dGVMZW5ndGhcbiAgICBpZiBsZW4gPiAweGZmZmYgOjogdGhyb3cgbmV3IEVycm9yIEAgYFBhY2tldCB0b28gbGFyZ2VgXG5cbiAgICBjb25zdCBhcnJheSA9IG5ldyBBcnJheUJ1ZmZlcihsZW4pXG5cbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFycmF5LCAwLCBwa3RfaGVhZGVyX3NpemVcbiAgICBkdi5zZXRVaW50MTYgQCAgMCwgc2lnbmF0dXJlLCBsaXR0bGVfZW5kaWFuXG4gICAgZHYuc2V0VWludDE2IEAgIDIsIGxlbiwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQxNiBAICA0LCBoZWFkZXIuYnl0ZUxlbmd0aCwgbGl0dGxlX2VuZGlhblxuICAgIGR2LnNldFVpbnQ4ICBAICA2LCB0eXBlIHx8IDAsIGxpdHRsZV9lbmRpYW5cbiAgICBkdi5zZXRVaW50OCAgQCAgNywgdHRsIHx8IGRlZmF1bHRfdHRsLCBsaXR0bGVfZW5kaWFuXG4gICAgaWYgISBpZF9yb3V0ZXIgOjpcbiAgICAgIGR2LnNldFVpbnQzMiBAICA4LCAwLCBsaXR0bGVfZW5kaWFuXG4gICAgICBpZiBpZF90YXJnZXQgOjpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yIEAgYEludmFsaWQgaWRfdGFyZ2V0IGZvciBjb250cm9sIHBhY2tldGBcbiAgICBlbHNlIDo6XG4gICAgICBkdi5zZXRVaW50MzIgQCAgOCwgaWRfcm91dGVyLCBsaXR0bGVfZW5kaWFuXG4gICAgICBkdi5zZXRVaW50MzIgQCAxMiwgaWRfdGFyZ2V0IHx8IDAsIGxpdHRsZV9lbmRpYW5cblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXkpXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoaGVhZGVyKSwgcGt0X2hlYWRlcl9zaXplXG4gICAgdTguc2V0IEAgbmV3IFVpbnQ4QXJyYXkoYm9keSksIHBrdF9oZWFkZXJfc2l6ZSArIGhlYWRlci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIGFycmF5XG5cblxuICBmdW5jdGlvbiBwYWNrSWQoaWQsIG9mZnNldCkgOjpcbiAgICBjb25zdCBidWYgPSBuZXcgQXJyYXlCdWZmZXIoNClcbiAgICBuZXcgRGF0YVZpZXcoYnVmKS5zZXRVaW50MzIgQCBvZmZzZXR8fDAsIGlkLCBsaXR0bGVfZW5kaWFuXG4gICAgcmV0dXJuIGJ1ZlxuICBmdW5jdGlvbiB1bnBhY2tJZChidWYsIG9mZnNldCkgOjpcbiAgICBjb25zdCBkdiA9IG5ldyBEYXRhVmlldyBAIGFzQnVmZmVyKGJ1ZilcbiAgICByZXR1cm4gZHYuZ2V0VWludDMyIEAgb2Zmc2V0fHwwLCBsaXR0bGVfZW5kaWFuXG5cbiAgZnVuY3Rpb24gcGFja191dGY4KHN0cikgOjpcbiAgICBjb25zdCB0ZSA9IG5ldyBfVGV4dEVuY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRlLmVuY29kZShzdHIudG9TdHJpbmcoKSkuYnVmZmVyXG4gIGZ1bmN0aW9uIHVucGFja191dGY4KGJ1ZikgOjpcbiAgICBjb25zdCB0ZCA9IG5ldyBfVGV4dERlY29kZXJfKCd1dGYtOCcpXG4gICAgcmV0dXJuIHRkLmRlY29kZSBAIGFzQnVmZmVyIEAgYnVmXG5cblxuICBmdW5jdGlvbiBhc0J1ZmZlcihidWYpIDo6XG4gICAgaWYgdW5kZWZpbmVkICE9PSBidWYuYnl0ZUxlbmd0aCA6OlxuICAgICAgaWYgdW5kZWZpbmVkID09PSBidWYuYnVmZmVyIDo6XG4gICAgICAgIHJldHVybiBidWZcblxuICAgICAgaWYgQXJyYXlCdWZmZXIuaXNWaWV3KGJ1ZikgOjpcbiAgICAgICAgcmV0dXJuIGJ1Zi5idWZmZXJcblxuICAgICAgaWYgJ2Z1bmN0aW9uJyA9PT0gdHlwZW9mIGJ1Zi5yZWFkVUludDMyTEUgOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlciAvLyBOb2RlSlMgQnVmZmVyXG5cbiAgICAgIHJldHVybiBidWZcblxuICAgIGlmICdzdHJpbmcnID09PSB0eXBlb2YgYnVmIDo6XG4gICAgICByZXR1cm4gcGFja191dGY4KGJ1ZilcblxuICAgIGlmIEFycmF5LmlzQXJyYXkoYnVmKSA6OlxuICAgICAgaWYgTnVtYmVyLmlzU2FmZUludGVnZXIgQCBidWZbMF0gOjpcbiAgICAgICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShidWYpLmJ1ZmZlclxuICAgICAgcmV0dXJuIGNvbmNhdCBAIGJ1Zi5tYXAgQCBhc0J1ZmZlclxuXG5cbiAgZnVuY3Rpb24gY29uY2F0QnVmZmVycyhsc3QsIGxlbikgOjpcbiAgICBpZiAxID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBsc3RbMF1cbiAgICBpZiAwID09PSBsc3QubGVuZ3RoIDo6IHJldHVybiBuZXcgQXJyYXlCdWZmZXIoMClcblxuICAgIGlmIG51bGwgPT0gbGVuIDo6XG4gICAgICBsZW4gPSAwXG4gICAgICBmb3IgY29uc3QgYXJyIG9mIGxzdCA6OlxuICAgICAgICBsZW4gKz0gYXJyLmJ5dGVMZW5ndGhcblxuICAgIGNvbnN0IHU4ID0gbmV3IFVpbnQ4QXJyYXkobGVuKVxuICAgIGxldCBvZmZzZXQgPSAwXG4gICAgZm9yIGNvbnN0IGFyciBvZiBsc3QgOjpcbiAgICAgIHU4LnNldCBAIG5ldyBVaW50OEFycmF5KGFyciksIG9mZnNldFxuICAgICAgb2Zmc2V0ICs9IGFyci5ieXRlTGVuZ3RoXG4gICAgcmV0dXJuIHU4LmJ1ZmZlclxuXG4iXSwibmFtZXMiOlsiYXNQYWNrZXRQYXJzZXJBUEkiLCJwYWNrZXRfaW1wbF9tZXRob2RzIiwibXNnX29ial9wcm90byIsIl9yYXdfIiwic2xpY2UiLCJib2R5X29mZnNldCIsImhlYWRlcl9vZmZzZXQiLCJidWYiLCJvZmZzZXQiLCJ1bnBhY2tJZCIsInBhY2tldFBhcnNlckFQSSIsIk9iamVjdCIsImFzc2lnbiIsImNyZWF0ZSIsInBhY2tNZXNzYWdlT2JqIiwiYXJncyIsIm1zZ19yYXciLCJwYWNrTWVzc2FnZSIsIm1zZ19vYmoiLCJhc01zZ09iaiIsInBhcnNlSGVhZGVyIiwiZGVmaW5lUHJvcGVydGllcyIsInZhbHVlIiwiaW5mbyIsInBrdF9oZWFkZXJfbGVuIiwicGFja2V0X2xlbiIsImhlYWRlcl9sZW4iLCJwYWNrZXRTdHJlYW0iLCJvcHRpb25zIiwiZGVjcmVtZW50X3R0bCIsInRpcCIsInFCeXRlTGVuIiwicSIsImZlZWQiLCJkYXRhIiwiY29tcGxldGUiLCJhc0J1ZmZlciIsInB1c2giLCJieXRlTGVuZ3RoIiwibXNnIiwicGFyc2VUaXBNZXNzYWdlIiwidW5kZWZpbmVkIiwibGVuZ3RoIiwiY29uY2F0QnVmZmVycyIsImxlbiIsImJ5dGVzIiwibiIsInRyYWlsaW5nQnl0ZXMiLCJwYXJ0cyIsInNwbGljZSIsInRhaWwiLCJzaWduYXR1cmUiLCJwa3RfY29udHJvbF9oZWFkZXJfc2l6ZSIsInBrdF9yb3V0aW5nX2hlYWRlcl9zaXplIiwiZGVmYXVsdF90dGwiLCJsaXR0bGVfZW5kaWFuIiwiY3JlYXRlRGF0YVZpZXdQYWNrZXRQYXJzZXIiLCJfVGV4dEVuY29kZXJfIiwiVGV4dEVuY29kZXIiLCJfVGV4dERlY29kZXJfIiwiVGV4dERlY29kZXIiLCJwYWNrX3V0ZjgiLCJ1bnBhY2tfdXRmOCIsImR2IiwiRGF0YVZpZXciLCJzaWciLCJnZXRVaW50MTYiLCJFcnJvciIsInRvU3RyaW5nIiwidHlwZSIsImdldFVpbnQ4IiwidHRsIiwiTWF0aCIsIm1heCIsInNldFVpbnQ4IiwiaWRfcm91dGVyIiwiZ2V0VWludDMyIiwiaWRfdGFyZ2V0IiwiaGVhZGVyIiwiYm9keSIsInBrdF9oZWFkZXJfc2l6ZSIsImFycmF5IiwiQXJyYXlCdWZmZXIiLCJzZXRVaW50MTYiLCJzZXRVaW50MzIiLCJ1OCIsIlVpbnQ4QXJyYXkiLCJzZXQiLCJwYWNrSWQiLCJpZCIsInN0ciIsInRlIiwiZW5jb2RlIiwiYnVmZmVyIiwidGQiLCJkZWNvZGUiLCJpc1ZpZXciLCJyZWFkVUludDMyTEUiLCJmcm9tIiwiQXJyYXkiLCJpc0FycmF5IiwiTnVtYmVyIiwiaXNTYWZlSW50ZWdlciIsImNvbmNhdCIsIm1hcCIsImxzdCIsImFyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7O0FBQ2UsU0FBU0EsaUJBQVQsQ0FBMkJDLG1CQUEzQixFQUFnRDtRQUN2RDtlQUFBO2VBQUE7WUFBQTtpQkFBQTtZQUFBLEtBTUpBLG1CQU5GOztRQVFNQyxnQkFBa0I7Z0JBQ1Y7YUFBVSxLQUFLQyxLQUFMLENBQVdDLEtBQVgsQ0FBbUIsS0FBS0MsV0FBeEIsQ0FBUDtLQURPO2tCQUVSO2FBQVUsS0FBS0YsS0FBTCxDQUFXQyxLQUFYLENBQW1CLEtBQUtFLGFBQXhCLEVBQXVDLEtBQUtELFdBQTVDLENBQVA7S0FGSzthQUdiRSxHQUFULEVBQWNDLFNBQU8sQ0FBckIsRUFBd0I7YUFBVUMsU0FBU0YsT0FBTyxLQUFLSixLQUFyQixFQUE0QkssTUFBNUIsQ0FBUDtLQUhMLEVBQXhCOztRQUtNRSxrQkFBa0JDLE9BQU9DLE1BQVAsQ0FDdEJELE9BQU9FLE1BQVAsQ0FBYyxJQUFkLENBRHNCLEVBRXRCWixtQkFGc0IsRUFHdEI7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
