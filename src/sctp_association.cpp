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

#include "sctp_association.h"
#include "sctp_chunk.h"

#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QRandomGenerator>
#endif

namespace SctpDc { namespace Sctp {
    void Association::populateHeader(Packet &packet)
    {
        packet.setVerificationTag(verificationTag);
        packet.setSourcePort(sourcePort);
        packet.setDestinationPort(destinationPort);
        packet.setChecksum();
    }

    Association::Association(quint16 sourcePort, quint16 destinationPort) :
        sourcePort(sourcePort), destinationPort(destinationPort)
    {
    }

    void Association::associate()
    {
        if (state_ != State::Closed) {
            qWarning("can't started associate on unclosed connection");
            return;
        }

        Packet initPacket;
        auto   chunk = initPacket.appendChunk<InitChunk>();
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
        chunk.setInitiateTag(QRandomGenerator::global()->generate());
#else
        chunk.setInitiateTag(quint32(qrand());
#endif
        populateHeader(initPacket);
        outgoingPackets_.push_back(std::move(initPacket));
        emit readyReadOutgoing();
    }

    QByteArray Association::readOutgoing()
    {
        if (outgoingPackets_.empty()) {
            return QByteArray();
        }
        QByteArray data = outgoingPackets_.front().takeData();
        outgoingPackets_.pop_front();
        return data;
    }

    void Association::writeIncoming(const QByteArray &data) { }

}}
