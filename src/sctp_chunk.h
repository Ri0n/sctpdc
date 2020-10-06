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

#pragma once

#include "sctp_common.h"

namespace SctpDc { namespace Sctp {
    class DataChunk : public Chunk {
    public:
        constexpr static quint8  Type          = 0;
        constexpr static quint16 MinHeaderSize = 16;

        using Chunk::Chunk;

        inline bool isValid() const { return Chunk::isValid(16); }

        inline bool isUnordered() const { return flags() & 0x4; }
        inline bool isBeginning() const { return flags() & 0x2; }
        inline bool isEnding() const { return flags() & 0x1; }
        inline bool isFragmented() const { return (flags() & 0x3) != 0x3; }

        inline void setUnordered(bool value) { setFlag(0x4, value); }
        inline void setBeginning(bool value) { setFlag(0x2, value); }
        inline void setEnding(bool value) { setFlag(0x1, value); }

        inline quint32 tsn() const { return qFromBigEndian<quint32>(data.constData() + offset + 4); }
        inline quint16 streamIdentifier() const { return qFromBigEndian<quint16>(data.constData() + offset + 8); }
        inline quint16 streamSequenceNumber() const { return qFromBigEndian<quint16>(data.constData() + offset + 10); }

        inline const QByteArray payloadProtocol() const { return getData(12, 4); }
        inline void             setPayloadProtocol(const QByteArray &proto) { setData(12, proto); }

        inline const QByteArray userData() const { return getData(16, length() - 16); }
        inline void             setUserData(const QByteArray &userData)
        {
            setData(16, userData);
            setLength(userData.size() + 16);
        }
    };

    class InitChunk : public Chunk {
    public:
        constexpr static quint8 Type          = 1;
        constexpr static int    MinHeaderSize = 16;

        using Chunk::Chunk;

        inline bool isValid() const { return Chunk::isValid(16); }

        inline quint32 initiateTag() const { return qFromBigEndian<quint32>(data.constData() + offset + 4); }
        inline void    setInitiateTag(quint32 tag) { qToBigEndian(tag, data.data() + offset + 4); }

        inline quint32 receiverWindowCredit() const { return qFromBigEndian<quint32>(data.constData() + offset + 8); }
        inline void    setReceiverWindowCredit(quint32 tag) { qToBigEndian(tag, data.data() + offset + 8); }

        inline quint16 outboundStreamsCount() const { return qFromBigEndian<quint16>(data.constData() + offset + 12); }
        inline void    setOutboundStreamsCount(quint16 count) { qToBigEndian(count, data.data() + offset + 12); }

        inline quint16 inboundStreamsCount() const { return qFromBigEndian<quint16>(data.constData() + offset + 14); }
        inline void    setInboundStreamsCount(quint16 count) { qToBigEndian(count, data.data() + offset + 14); }

        inline quint32 initialTsn() const { return qFromBigEndian<quint32>(data.constData() + offset + 16); }
        inline void    setInitialTsn(quint32 tsn) { qToBigEndian(tsn, data.data() + offset + 16); }

        inline parameter_iterator       begin() { return Chunk::begin<InitChunk>(); }
        inline const_parameter_iterator begin() const { return Chunk::begin<InitChunk>(); }
    };

    class InitAckChunk : public InitChunk {
    public:
        constexpr static quint8 Type = 2;

        using InitChunk::InitChunk;
        inline parameter_iterator       begin() { return Chunk::begin<InitAckChunk>(); }
        inline const_parameter_iterator begin() const { return Chunk::begin<InitAckChunk>(); }
    };

    class CookieEchoChunk : public Chunk {
    public:
        constexpr static quint8 Type          = 10;
        constexpr static int    MinHeaderSize = 4;
        using Chunk::Chunk;
    };

    class CookieAckChunk : public Chunk {
    public:
        constexpr static quint8 Type          = 11;
        constexpr static int    MinHeaderSize = 4;
        using Chunk::Chunk;
    };
}}
