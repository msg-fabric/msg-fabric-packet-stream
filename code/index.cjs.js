import asPacketParserAPI from './basic'
import createBufferPacketParser from './buffer'
import createDataViewPacketParser from './dataview'

export default function createPacketParser(...args) ::
  return createBufferPacketParser(...args)

Object.assign @ createPacketParser, @{}
  asPacketParserAPI
  createBufferPacketParser
  createDataViewPacketParser

