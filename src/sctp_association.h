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
#include <QElapsedTimer>
#include <QObject>
#include <QtEndian>

#include <deque>

namespace SctpDc { namespace Sctp {

    class InitChunk;
    class InitAckChunk;
    class CookieEchoChunk;
    class CookieAckChunk;
    class SackChunk;
    class DataChunk;

    class Association : public QObject {
        Q_OBJECT
    public:
        enum class State {
            Closed,
            CookieWait,
            CookieEchoed,
            Established,
            ShutdownPending,
            ShutdownSent,
            ShutdownReceived,
            ShutdownAckSent
        };

        enum class Error { None, WrongState, ProtocolViolation, VerificationTag, InvalidCookie, Unknown };

        Association(quint16 sourcePort, quint16 destinationPort, QObject *parent = nullptr);

        void  associate();
        void  abort(Error error);
        State state() const { return state_; }

        // read payload extracted from sctp
        QByteArray readOutgoing();

        // data - an sctp packet right from network. note only sctp and its payload, nothing else
        void writeIncoming(const QByteArray &data);

        void write(quint16 streamId, bool unordered, const QByteArray &payloadProto, const QByteArray &data);

    signals:
        void readyReadOutgoing();
        void errorOccured();
        void established();

    private:
        void       populateHeader(Packet &packet);
        void       sendFirstPriority(Packet &packet);
        void       trySend();
        QByteArray makeStateCookie();
        void       setError(Error error);
        void       initRemote(const InitChunk &chunk);

        void incomingChunk(const InitChunk &chunk);
        void incomingChunk(const InitAckChunk &chunk);
        void incomingChunk(const CookieEchoChunk &chunk);
        void incomingChunk(const CookieAckChunk &chunk);
        void incomingChunk(const SackChunk &);
        void incomingChunk(const DataChunk &);

    private:
        struct UnackChunk {
            quint32    timestamp; // monotonic time
            quint32    tsn;
            QByteArray data;
        };

        State                         state_   = State::Closed;
        quint8                        ackState = 0;
        QByteArray                    privKey; // for cookie HMAC
        QElapsedTimer                 timer_;
        std::deque<Packet>            incomingPackets_;
        std::deque<Packet>            outgoingPackets_;
        std::deque<UnackChunk>        dataSendQueue_;
        std::deque<UnackChunk>        controlSendQueue_;
        std::map<quint32, UnackChunk> unacknowledgedChunks;   // outgoing chunks timestamp => chunk
        std::map<quint16, quint16>    stream2ssn_;            // stream id to stream seqnum
        quint32                       myVerificationTag_ = 0; // in incoming packets. local-generated.
        quint32 peerVerificationTag_  = 0; // with each outgoing sctp packet. to be checked on remote side
        quint32 nextTsn_              = 0;
        quint32 lastRcvdTsn_          = 0;
        quint16 sourcePort_           = 0;
        quint16 destinationPort_      = 0;
        quint16 inboundStreamsCount_  = 65535;
        quint16 outboundStreamsCount_ = 65535;
        quint32 localWindowCredit_    = 512 * 1024;
        quint32 localUsedCredit_      = 0; // total bytes we not yet acknowledged
        quint32 remoteWindowCredit_   = 512 * 1024;
        quint32 remoteUsedCredit_     = 0;    // total sent but not yet aknowledged bytes
        quint32 mtu_                  = 1400; // for loopback may be way more
        quint32 cwnd_;                        // Congestion control window
        quint32 ssthresh_;                    // Slow-start threshold
        quint32 partialBytesAcked;            // TODO not used?
        Error   error_ = Error::None;
    };

} // namespace Sctp
} // namespace SctpDc
