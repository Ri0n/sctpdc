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

#include <QByteArray>
#include <QObject>
#include <QtEndian>

#include <deque>

namespace SctpDc { namespace Sctp {

    class InitChunk;
    class InitAckChunk;

    class Association : public QObject {
        Q_OBJECT
    public:
        enum class State {
            Closed,
            CookieWait,
            CookieEchoed,
            Established,
            ShutdownPending,
            ShutdownSentReceived,
            ShutdownAckSent
        };

        enum class Error { None, ProtocolViolation };

        Association(quint16 sourcePort, quint16 destinationPort);

        void associate();

        QByteArray readOutgoing();
        void       writeIncoming(const QByteArray &data);

    signals:
        void readyReadOutgoing();
        void errorOccured();

    private:
        void populateHeader(Packet &packet);
        void incomingChunk(const InitChunk &chunk);
        void incomingChunk(const InitAckChunk &chunk);

    private:
        State              state_ = State::Closed;
        std::deque<Packet> incomingPackets_;
        std::deque<Packet> outgoingPackets_;
        quint32            tag_                  = 0;
        quint32            tsn_                  = 0;
        quint32            verificationTag_      = 0;
        quint16            sourcePort_           = 0;
        quint16            destinationPort_      = 0;
        quint16            inboundStreamsCount_  = 65535;
        quint16            outboundStreamsCount_ = 65535;
        quint32            receiverWindowCredit_ = 512 * 1024;
        Error              error_                = Error::None;
    };

} // namespace Sctp
} // namespace SctpDc
