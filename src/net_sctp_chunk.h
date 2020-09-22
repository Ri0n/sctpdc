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

#include "net_sctp_common.h"

namespace SctpDc { namespace Sctp {
    class DataChunk : public Chunk {
        inline bool isUnordered() const { return flags() & 0x4; }
        inline bool isBeginning() const { return flags() & 0x2; }
        inline bool isEnding() const { return flags() & 0x1; }

        inline void setUnordered(bool value) { setFlag(0x4, value); }
        inline void setBeginning(bool value) { setFlag(0x2, value); }
        inline void setEnding(bool value) { setFlag(0x1, value); }

        inline quint32 tsn() const { return qFromBigEndian<quint32>(data.constData() + offset + 4); }
        inline quint16 streamIdentifier() const { return qFromBigEndian<quint16>(data.constData() + offset + 8); }
        inline quint16 streamSequenceNumber() const { return qFromBigEndian<quint16>(data.constData() + offset + 10); }
        inline quint32 payloadProtocol() const { return qFromBigEndian<quint32>(data.constData() + offset + 12); }
    };
}}
