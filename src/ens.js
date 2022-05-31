import has from 'lodash/has'
import { Contract, utils } from 'ethers'
import {
  getWeb3,
  getNetworkId,
  getProvider,
  getAccount,
  getSigner
} from './web3'
import { normalize } from 'eth-ens-namehash'
import { formatsByName } from '@ensdomains/address-encoder'
import { abi as ensContract } from '@ensdomains/contracts/abis/ens/ENS.json'
import bns from 'bns'
import { BufferReader, BufferWriter } from 'bufio'
import { decryptHashes } from './preimage'

import {
  uniq,
  getEnsStartBlock,
  checkLabels,
  mergeLabels,
  emptyAddress,
  isDecrypted,
  namehash,
  labelhash
} from './utils'
import { encodeLabelhash } from './utils/labelhash'

import {
  getTestRegistrarContract,
  getReverseRegistrarContract,
  getENSContract,
  getResolverContract,
  getDNSResolverContract,
  getOldResolverContract
} from './contracts'

import {
  isValidContenthash,
  encodeContenthash,
  decodeContenthash
} from './utils/contents'

/* Utils */

export function getNamehash(name) {
  return namehash(name)
}

async function getNamehashWithLabelHash(labelHash, nodeHash) {
  let node = utils.keccak256(nodeHash + labelHash.slice(2))
  return node.toString()
}

function getLabelhash(label) {
  return labelhash(label)
}

function hashDNSName(name) {
  const dnsName = bns.encoding.packName(bns.util.fqdn(name))
  return utils.keccak256(dnsName)
}

// Parse a DNS record in text format and writes to a buffer
// Accepts rrs with empty rdata (ttl will always be 0 if rdata is empty):
// name.eth.    200 IN  A 127.0.0.1
// name.eth.      0 IN  A
function writeDNSRecordFromZone(bw, rr) {
  try {
    const record = bns.wire.Record.fromString(rr)
    bw.writeBytes(record.encode())
  } catch (e) {
    // this record may have empty rdata
    // [owner_name] [ttl] [class] [type] [rdata]
    const parts = rr.trim().split(/[\s]+/)
    if (parts.length !== 4) {
      // doesn't seem like a valid record
      throw new Error('unable to parse record')
    }

    const rname = parts[0]
    if (!bns.util.isFQDN(rname)) {
      throw new Error('owner name must be a fully qualified domain name')
    }

    const rtype = bns.wire.stringToType(parts[3])
    const rclass = bns.wire.stringToClass(parts[2])

    // manually encode the record
    // since bns errors on empty rdata
    bw.writeBytes(bns.encoding.packName(rname))
    bw.writeU16BE(rtype)
    bw.writeU16BE(rclass)
    bw.writeU32BE(0) // zero TTL
    bw.writeU16BE(0) // zero RDLENGTH
  }
}

function decodeDNSRecords(data) {
  const br = new BufferReader(data)
  const records = []

  while (br.left() > 0) {
    let str = bns.wire.Record.read(br).toString()
    records.push(str)
  }

  return records
}

const contracts = {
  1: {
    registry: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
  },
  3: {
    registry: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
  },
  4: {
    registry: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
  },
  43113: {
    registry: '0x4f980F4819b2B4bDc15c00cD9E8718D77f7b54bB'
  }
}

export class ENS {
  constructor({ networkId, registryAddress, provider }) {
    this.contracts = contracts
    const hasRegistry =
      this.contracts[networkId] &&
      Object.keys(this.contracts[networkId]).includes('registry')

    if (!hasRegistry && !registryAddress) {
      throw new Error(`Unsupported network ${networkId}`)
    } else if (this.contracts[networkId] && !registryAddress) {
      registryAddress = contracts[networkId].registry
    }

    this.registryAddress = registryAddress

    const ENSContract = getENSContract({ address: registryAddress, provider })
    this.ENS = ENSContract
  }

  /* Get the raw Ethers contract object */
  getENSContractInstance() {
    return this.ENS
  }
  /* Main methods */

  async getOwner(name) {
    const namehash = getNamehash(name)
    const owner = await this.ENS.owner(namehash)
    return owner
  }

  async getResolver(name) {
    const namehash = getNamehash(name)
    return this.ENS.resolver(namehash)
  }

  async getTTL(name) {
    const namehash = getNamehash(name)
    return this.ENS.ttl(namehash)
  }

  async getResolverWithLabelhash(labelhash, nodehash) {
    const namehash = await getNamehashWithLabelHash(labelhash, nodehash)
    return this.ENS.resolver(namehash)
  }

  async getOwnerWithLabelHash(labelhash, nodeHash) {
    const namehash = await getNamehashWithLabelHash(labelhash, nodeHash)
    return this.ENS.owner(namehash)
  }

  async getEthAddressWithResolver(name, resolverAddr) {
    if (parseInt(resolverAddr, 16) === 0) {
      return emptyAddress
    }
    const namehash = getNamehash(name)
    try {
      const provider = await getProvider()
      const Resolver = getResolverContract({
        address: resolverAddr,
        provider
      })
      const addr = await Resolver['addr(bytes32)'](namehash)
      return addr
    } catch (e) {
      console.warn(
        'Error getting addr on the resolver contract, are you sure the resolver address is a resolver contract?'
      )
      return emptyAddress
    }
  }

  async getAddress(name) {
    const resolverAddr = await this.getResolver(name)
    return this.getEthAddressWithResolver(name, resolverAddr)
  }

  async getAddr(name, key) {
    const resolverAddr = await this.getResolver(name)
    if (parseInt(resolverAddr, 16) === 0) return emptyAddress
    return this.getAddrWithResolver(name, key, resolverAddr)
  }

  async getAddrWithResolver(name, key, resolverAddr) {
    const namehash = getNamehash(name)
    try {
      const provider = await getProvider()
      const Resolver = getResolverContract({
        address: resolverAddr,
        provider
      })
      const { coinType, encoder } = formatsByName[key]
      const addr = await Resolver['addr(bytes32,uint256)'](namehash, coinType)
      if (addr === '0x') return emptyAddress

      return encoder(Buffer.from(addr.slice(2), 'hex'))
    } catch (e) {
      console.log(e)
      console.warn(
        'Error getting addr on the resolver contract, are you sure the resolver address is a resolver contract?'
      )
      return emptyAddress
    }
  }

  async getContent(name) {
    const resolverAddr = await this.getResolver(name)
    return this.getContentWithResolver(name, resolverAddr)
  }

  async getContentWithResolver(name, resolverAddr) {
    if (parseInt(resolverAddr, 16) === 0) {
      return emptyAddress
    }
    try {
      const namehash = getNamehash(name)
      const provider = await getProvider()
      const Resolver = getResolverContract({
        address: resolverAddr,
        provider
      })
      const contentHashSignature = utils
        .solidityKeccak256(['string'], ['contenthash(bytes32)'])
        .slice(0, 10)

      const isContentHashSupported = await Resolver.supportsInterface(
        contentHashSignature
      )

      if (isContentHashSupported) {
        const { protocolType, decoded, error } = decodeContenthash(
          await Resolver.contenthash(namehash)
        )
        if (error) {
          return {
            value: emptyAddress,
            contentType: 'contenthash'
          }
        }
        return {
          value: `${protocolType}://${decoded}`,
          contentType: 'contenthash'
        }
      } else {
        const value = await Resolver.content(namehash)
        return {
          value,
          contentType: 'oldcontent'
        }
      }
    } catch (e) {
      const message =
        'Error getting content on the resolver contract, are you sure the resolver address is a resolver contract?'
      console.warn(message, e)
      return { value: message, contentType: 'error' }
    }
  }

  async getText(name, key) {
    const resolverAddr = await this.getResolver(name)
    return this.getTextWithResolver(name, key, resolverAddr)
  }

  async getTextWithResolver(name, key, resolverAddr) {
    if (parseInt(resolverAddr, 16) === 0) {
      return ''
    }
    const namehash = getNamehash(name)
    try {
      const provider = await getProvider()
      const Resolver = getResolverContract({
        address: resolverAddr,
        provider
      })
      const addr = await Resolver.text(namehash, key)
      return addr
    } catch (e) {
      console.warn(
        'Error getting text record on the resolver contract, are you sure the resolver address is a resolver contract?'
      )
      return ''
    }
  }

  async getDNSRecordsZoneFormat(nodeName, dnsName, dnsType) {
    const data = await this.getRawDNSRecords(nodeName, dnsName, dnsType)
    return decodeDNSRecords(data)
  }

  async getRawDNSRecords(nodeName, dnsName, dnsType) {
    const resolverAddr = await this.getResolver(nodeName)
    return this.getRawDNSRecordsWithResolver(
      nodeName,
      dnsName,
      dnsType,
      resolverAddr
    )
  }

  async getRawDNSRecordsWithResolver(nodeName, dnsName, dnsType, resolverAddr) {
    if (parseInt(resolverAddr, 16) === 0) {
      return []
    }

    const type = bns.wire.stringToType(dnsType)
    const namehash = getNamehash(bns.util.trimFQDN(nodeName))

    try {
      const provider = await getProvider()
      const Resolver = getDNSResolverContract({
        address: resolverAddr,
        provider
      })

      const data = await Resolver.dnsRecord(
        namehash,
        hashDNSName(dnsName),
        type
      )
      return Buffer.from(data.substr(2), 'hex')
    } catch (e) {
      console.warn(
        'Error getting dns record on the dns resolver contract, are you sure the resolver address is a resolver contract?',
        e
      )
      return []
    }
  }

  async getName(address) {
    const reverseNode = `${address.slice(2)}.addr.reverse`
    const resolverAddr = await this.getResolver(reverseNode)
    return this.getNameWithResolver(address, resolverAddr)
  }

  async getNameWithResolver(address, resolverAddr) {
    const reverseNode = `${address.slice(2)}.addr.reverse`
    const reverseNamehash = getNamehash(reverseNode)
    if (parseInt(resolverAddr, 16) === 0) {
      return {
        name: null
      }
    }

    try {
      const provider = await getProvider()
      const Resolver = getResolverContract({
        address: resolverAddr,
        provider
      })
      const name = await Resolver.name(reverseNamehash)
      return {
        name
      }
    } catch (e) {
      console.log(`Error getting name for reverse record of ${address}`, e)
    }
  }

  async isMigrated(name) {
    const namehash = getNamehash(name)
    return this.ENS.recordExists(namehash)
  }

  async getResolverDetails(node) {
    try {
      const addrPromise = this.getAddress(node.name)
      const contentPromise = this.getContent(node.name)
      const [addr, content] = await Promise.all([addrPromise, contentPromise])
      return {
        ...node,
        addr,
        content: content.value,
        contentType: content.contentType
      }
    } catch (e) {
      return {
        ...node,
        addr: '0x0',
        content: '0x0',
        contentType: 'error'
      }
    }
  }

  async getSubdomains(name) {
    const startBlock = await getEnsStartBlock()
    const namehash = getNamehash(name)
    const rawLogs = await this.getENSEvent('NewOwner', {
      topics: [namehash],
      fromBlock: startBlock
    })
    const flattenedLogs = rawLogs.map((log) => log.values)
    flattenedLogs.reverse()
    const logs = uniq(flattenedLogs, 'label')
    const labelhashes = logs.map((log) => log.label)
    const remoteLabels = await decryptHashes(...labelhashes)
    const localLabels = checkLabels(...labelhashes)
    const labels = mergeLabels(localLabels, remoteLabels)
    const ownerPromises = labels.map((label) =>
      this.getOwner(`${label}.${name}`)
    )

    return Promise.all(ownerPromises).then((owners) =>
      owners.map((owner, index) => {
        return {
          label: labels[index],
          labelhash: logs[index].label,
          decrypted: labels[index] !== null,
          node: name,
          name: `${
            labels[index] || encodeLabelhash(logs[index].label)
          }.${name}`,
          owner
        }
      })
    )
  }

  async getDomainDetails(name) {
    const nameArray = name.split('.')
    const labelhash = getLabelhash(nameArray[0])
    const [owner, resolver] = await Promise.all([
      this.getOwner(name),
      this.getResolver(name)
    ])
    const node = {
      name,
      label: nameArray[0],
      labelhash,
      owner,
      resolver
    }

    const hasResolver = parseInt(node.resolver, 16) !== 0

    if (hasResolver) {
      return this.getResolverDetails(node)
    }

    return {
      ...node,
      addr: null,
      content: null
    }
  }

  /* non-constant functions */

  async setOwner(name, newOwner) {
    const ENSWithoutSigner = this.ENS
    const signer = await getSigner()
    const ENS = ENSWithoutSigner.connect(signer)
    const namehash = getNamehash(name)
    return ENS.setOwner(namehash, newOwner)
  }

  async setSubnodeOwner(name, newOwner) {
    const ENSWithoutSigner = this.ENS
    const signer = await getSigner()
    const ENS = ENSWithoutSigner.connect(signer)
    const nameArray = name.split('.')
    const label = nameArray[0]
    const node = nameArray.slice(1).join('.')
    const labelhash = getLabelhash(label)
    const parentNamehash = getNamehash(node)
    return ENS.setSubnodeOwner(parentNamehash, labelhash, newOwner)
  }

  async setSubnodeRecord(name, newOwner, resolver) {
    const ENSWithoutSigner = this.ENS
    const signer = await getSigner()
    const ENS = ENSWithoutSigner.connect(signer)
    const nameArray = name.split('.')
    const label = nameArray[0]
    const node = nameArray.slice(1).join('.')
    const labelhash = getLabelhash(label)
    const parentNamehash = getNamehash(node)
    const ttl = await this.getTTL(name)
    return ENS.setSubnodeRecord(
      parentNamehash,
      labelhash,
      newOwner,
      resolver,
      ttl
    )
  }

  async setResolver(name, resolver) {
    const namehash = getNamehash(name)
    const ENSWithoutSigner = this.ENS
    const signer = await getSigner()
    const ENS = ENSWithoutSigner.connect(signer)
    return ENS.setResolver(namehash, resolver)
  }

  async setAddress(name, address) {
    const resolverAddr = await this.getResolver(name)
    return this.setAddressWithResolver(name, address, resolverAddr)
  }

  async setAddressWithResolver(name, address, resolverAddr) {
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    return Resolver['setAddr(bytes32,address)'](namehash, address)
  }

  async setAddr(name, key, address) {
    const resolverAddr = await this.getResolver(name)
    return this.setAddrWithResolver(name, key, address, resolverAddr)
  }

  async setAddrWithResolver(name, key, address, resolverAddr) {
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    const { decoder, coinType } = formatsByName[key]
    let addressAsBytes
    if (!address || address === '') {
      addressAsBytes = Buffer.from('')
    } else {
      addressAsBytes = decoder(address)
    }
    return Resolver['setAddr(bytes32,uint256,bytes)'](
      namehash,
      coinType,
      addressAsBytes
    )
  }

  async setContent(name, content) {
    const resolverAddr = await this.getResolver(name)
    return this.setContentWithResolver(name, content, resolverAddr)
  }

  async setContentWithResolver(name, content, resolverAddr) {
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    return Resolver.setContent(namehash, content)
  }

  async setContenthash(name, content) {
    const resolverAddr = await this.getResolver(name)
    return this.setContenthashWithResolver(name, content, resolverAddr)
  }

  async setContenthashWithResolver(name, content, resolverAddr) {
    let encodedContenthash = content
    if (parseInt(content, 16) !== 0) {
      encodedContenthash = encodeContenthash(content)
    }
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    return Resolver.setContenthash(namehash, encodedContenthash)
  }

  async setText(name, key, recordValue) {
    const resolverAddr = await this.getResolver(name)
    return this.setTextWithResolver(name, key, recordValue, resolverAddr)
  }

  async setTextWithResolver(name, key, recordValue, resolverAddr) {
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    return Resolver.setText(namehash, key, recordValue)
  }

  // Sets DNS records from an array of rrs in zone format
  //
  // rrs example: [
  //   hello.eth.           300  IN     A    127.0.0.1
  //   hello.eth.           300  IN     A    127.0.0.2
  //   hello.eth.           300  IN     TXT
  //  _443._tcp.hello.eth.  300  IN     TLSA 3 1 1 [HASH]
  // ]
  //
  // This will:
  // 1. Add two A records
  // 2. Remove any TXT records from hello.eth.
  // 3. Add a TLSA record
  async setDNSRecordsFromZone(name, rrs) {
    const bw = new BufferWriter()
    for (const rr of rrs) {
      writeDNSRecordFromZone(bw, rr)
    }

    const data = bw.render()
    return this.setRawDNSRecords(name, data)
  }

  async setRawDNSRecords(name, data) {
    const resolverAddr = await this.getResolver(name)
    return this.setRawDNSRecordsWithResolver(name, data, resolverAddr)
  }

  async setRawDNSRecordsWithResolver(name, data, resolverAddr) {
    const namehash = getNamehash(name)
    const provider = await getProvider()
    const ResolverWithoutSigner = getDNSResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    return Resolver.setDNSRecords(namehash, data)
  }

  async createSubdomain(name) {
    const account = await getAccount()
    const publicResolverAddress =
      process.env.REACT_APP_TLD_RESOLVER ||
      (await this.getAddress('resolver.' + process.env.REACT_APP_REGISTRAR_TLD))
    try {
      return this.setSubnodeRecord(name, account, publicResolverAddress)
    } catch (e) {
      console.log('error creating subdomain', e)
    }
  }

  async deleteSubdomain(name) {
    try {
      return this.setSubnodeRecord(name, emptyAddress, emptyAddress)
    } catch (e) {
      console.log('error deleting subdomain', e)
    }
  }

  async claimAndSetReverseRecordName(name, overrides = {}) {
    const reverseRegistrarAddr = await this.getOwner('addr.reverse')
    const provider = await getProvider(0)
    const reverseRegistrarWithoutSigner = getReverseRegistrarContract({
      address: reverseRegistrarAddr,
      provider
    })
    const signer = await getSigner()
    const reverseRegistrar = reverseRegistrarWithoutSigner.connect(signer)
    const networkId = await getNetworkId()

    if (parseInt(networkId) > 1000) {
      const gasLimit = await reverseRegistrar.estimate.setName(name)
      overrides = {
        gasLimit: gasLimit.toNumber() * 2,
        ...overrides
      }
    }

    return reverseRegistrar.setName(name, overrides)
  }

  async setReverseRecordName(name) {
    const account = await getAccount()
    const provider = await getProvider()
    const reverseNode = `${account.slice(2)}.addr.reverse`
    const resolverAddr = await this.getResolver(reverseNode)
    const ResolverWithoutSigner = getResolverContract({
      address: resolverAddr,
      provider
    })
    const signer = await getSigner()
    const Resolver = ResolverWithoutSigner.connect(signer)
    let namehash = getNamehash(reverseNode)
    return Resolver.setName(namehash, name)
  }

  // Events

  async getENSEvent(event, { topics, fromBlock }) {
    const provider = await getWeb3()
    const { ENS } = this
    const ensInterface = new utils.Interface(ensContract)
    let Event = ENS.filters[event]()

    const filter = {
      fromBlock,
      toBlock: 'latest',
      address: Event.address,
      topics: [...Event.topics, ...topics]
    }

    const logs = await provider.getLogs(filter)

    const parsed = logs.map((log) => {
      const parsedLog = ensInterface.parseLog(log)
      return parsedLog
    })

    return parsed
  }
}
