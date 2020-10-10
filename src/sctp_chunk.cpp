/*
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
*/

#include "sctp_chunk.h"

namespace SctpDc { namespace Sctp {

    void SackChunk::setData(const QList<SackChunk::Gap> &gaps, const QList<quint32> &dups)
    {
        ensureCapacity(offset + MinHeaderSize + (gaps.size() + dups.size()) * 4);
        char *ptr = data.data() + offset + MinHeaderSize;
        for (const auto &gap : gaps) {
            qToBigEndian(gap.begin, ptr);
            qToBigEndian(gap.end, ptr + 2);
            ptr += 4;
        }
        for (const auto &dup : dups) {
            qToBigEndian(dup, ptr);
            ptr += 4;
        }
    }

    QList<SackChunk::Gap> SackChunk::gaps() const
    {
        QList<SackChunk::Gap> ret;
        char *                ptr = data.data() + offset + MinHeaderSize;
        int                   cnt = gapAckBlocksCount();
        for (int i = 0; i < cnt; i++) {
            Gap g;
            g.begin = qFromBigEndian<quint16>(ptr);
            g.end   = qFromBigEndian<quint16>(ptr + 2);
            ret.append(g);
            ptr += 4;
        }
        return ret;
    }

    QList<quint32> SackChunk::dups() const
    {
        QList<quint32> ret;
        int            cnt = gapAckBlocksCount();
        char *         ptr = data.data() + offset + MinHeaderSize + cnt * 4;
        cnt                = duplicateTSNCount();

        for (int i = 0; i < cnt; i++) {
            ret.append(qFromBigEndian<quint32>(ptr));
            ptr += 4;
        }
        return ret;
    }
}}
