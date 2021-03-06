#if 0
Copyright (c) 2020, Sergey Ilinykh <rion4ik@gmail.com>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#endif

#include "sctp_common.h"
#include "sctp_chunk.h"
#include "sctp_crc32.h"

#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QRandomGenerator>
#endif

namespace SctpDc { namespace Sctp {
    int Packet::allocChunk(quint8 type, quint16 headerSize, quint16 extraSpace)
    {
        int offset = data_.size();
        if (!offset) {
            offset += HeaderSize;
        }
        data_.resize(offset + (headerSize + extraSpace + 3) & ~3);
        data_[offset]     = type;
        data_[offset + 1] = 0;
        quint16 chunkSize = quint16(headerSize + extraSpace);
        qToBigEndian(chunkSize, data_.data() + offset + 2);
        // ensure last 3 bytes are zeroed (any padding has to be zeroed)
        if (extraSpace) {
            data_[data_.size() - 1] = 0;
            data_[data_.size() - 2] = 0;
            data_[data_.size() - 3] = 0;
        }
        return offset;
    }

    void Packet::appendRawChunk(const QByteArray &rawChunk)
    {
        Q_ASSERT(rawChunk.size() % 4 == 0);
        int offset = data_.size();
        if (!offset) {
            offset += HeaderSize;
        }
        data_.resize(offset + rawChunk.size());
        data_.replace(offset, rawChunk.size(), rawChunk);
    }

    int Chunk::allocParameter(quint16 type, quint16 extraSpace)
    {
        int paramOffset = data.size();
        // 4 - header size. remaining magic is for padding to 4 bytes
        data.resize(paramOffset + (4 + extraSpace + 3) & ~3);
        qToBigEndian(type, data.data() + paramOffset);
        quint16 paramSize = quint16(4 + extraSpace);
        qToBigEndian(paramSize, data.data() + paramOffset + 2);
        size = paramOffset + paramSize - offset;
        qToBigEndian(size, data.data() + offset + 2); // update chunk size
        // ensure last 3 bytes are zeroed (any padding has to be zeroed)
        if (extraSpace) {
            data[data.size() - 1] = 0;
            data[data.size() - 2] = 0;
            data[data.size() - 3] = 0;
        }
        return paramOffset;
    }

    quint32 Packet::computeChecksum() const
    {
        quint32 zero = 0;
        quint32 base = 0xffffffff;

        base = calculate_crc32c(base, reinterpret_cast<const unsigned char *>(data_.constData()), 8);
        base = calculate_crc32c(base, reinterpret_cast<const unsigned char *>(&zero), 4);
        base = calculate_crc32c(base, reinterpret_cast<const unsigned char *>(data_.constData() + 12),
                                data_.size() - 12);
        base = sctp_finalize_crc32c(base);
        return base;
    }

    void Iterable::setData(int relOffset, const QByteArray &newData)
    {
        int dstPos = offset + relOffset;
        ensureCapacity(dstPos + newData.size());
        data.replace(dstPos, newData.size(), newData);
    }

    bool Packet::minimalValidation(uint16_t *sourcePort, uint16_t *destinationPort) const
    {
        if (data_.size() < Packet::HeaderSize)
            return false;

        auto sp = this->sourcePort();
        auto dp = this->destinationPort();
        if (!sp && !dp)
            return false;

        const_chunk_iterator b = begin();
        const_chunk_iterator e = end();
        if (b == e || !(*b).isValid())
            return false;

        if (sourcePort)
            *sourcePort = sp;
        if (destinationPort)
            *destinationPort = dp;
        return true;
    }

}}
