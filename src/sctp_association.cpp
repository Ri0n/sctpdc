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

#include "sctp_association.h"
#include "sctp_chunk.h"
#include "sctp_parameter.h"

#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QRandomGenerator>
#endif
#include <QDataStream>
#include <QIODevice>
#include <QMessageAuthenticationCode>

namespace SctpDc { namespace Sctp {
    void Association::populateHeader(Packet &packet)
    {
        packet.setVerificationTag(peerVerificationTag_);
        packet.setSourcePort(sourcePort_);
        packet.setDestinationPort(destinationPort_);
        packet.setChecksum();
    }

    void Association::sendFirstPriority(Packet &packet)
    {
        populateHeader(packet);
        outgoingPackets_.push_front(std::move(packet));
        emit readyReadOutgoing();
    }

    void Association::trySend()
    {
        if (!(state_ == State::Established || state_ == State::CookieEchoed))
            return;

        auto now = timer_.elapsed();

        bool dataSent = false;
        while (remoteUsedCredit_ < remoteWindowCredit_) {
            Packet pkt;
            while (controlSendQueue_.size() && (pkt.size() <= Packet::HeaderSize || pkt.size() < int(mtu_))) {
                auto const &chunk = controlSendQueue_.front();
                pkt.appendRawChunk(chunk.data);
                controlSendQueue_.pop_front();
            }

            // if have soemthing to send and the packet is empty (rely on ip fragmentation) or it's not empty,
            // but it still can fit more, and adding a chunk won't overflow remote receiver window credit
            while (dataSendQueue_.size() && (pkt.size() <= Packet::HeaderSize || pkt.size() < int(mtu_))
                   && (pkt.size() + dataSendQueue_.front().data.size() + remoteUsedCredit_) < remoteWindowCredit_) {
                auto const &chunk = dataSendQueue_.front();
                remoteUsedCredit_ += chunk.data.size();
                pkt.appendRawChunk(chunk.data);
                unacknowledgedChunks.emplace(now, chunk);
                dataSendQueue_.pop_front();
            }
            if (pkt.size() <= Packet::HeaderSize)
                break; // nothing to send
            populateHeader(pkt);
            outgoingPackets_.push_back(std::move(pkt));
            emit readyReadOutgoing();
            dataSent = true;
        }

        if (!dataSent && (controlSendQueue_.size() || dataSendQueue_.size())) {
            // credit overflow? remote sack lost? TODO 6.1.A
        }
    }

    QByteArray Association::makeStateCookie()
    {
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
        quint64 privKey64 = QRandomGenerator::global()->generate64();
#else
        quint64 privKey64  = quint32(qrand()) << 32 + quint32(qrand());
#endif
        privKey = QByteArray(reinterpret_cast<const char *>(&privKey64), sizeof(privKey64));
        QByteArray  tcb;
        QDataStream tcbStream(&tcb, QIODevice::WriteOnly);
        tcbStream << myVerificationTag_ << peerVerificationTag_ << nextTsn_ << lastRcvdTsn_ << inboundStreamsCount_
                  << outboundStreamsCount_;
        return tcb + QMessageAuthenticationCode::hash(tcb, privKey, QCryptographicHash::Sha1);
    }

    Association::Association(quint16 sourcePort, quint16 destinationPort, QObject *parent) :
        QObject(parent), sourcePort_(sourcePort), destinationPort_(destinationPort)
    {
        timer_.start();
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
        myVerificationTag_ = QRandomGenerator::global()->generate();
#else
        myVerificationTag_ = quint32(qrand());
#endif
        if (!myVerificationTag_)
            myVerificationTag_++;
        nextTsn_ = myVerificationTag_;
    }

    void Association::associate()
    {
        if (state_ != State::Closed) {
            qWarning("can't started associate on unclosed connection");
            return;
        }

        Packet packet;
        auto   chunk = packet.appendChunk<InitChunk>();

        chunk.setInitiateTag(myVerificationTag_);
        chunk.setInitialTsn(nextTsn_);
        chunk.setReceiverWindowCredit(localWindowCredit_);
        chunk.setInboundStreamsCount(inboundStreamsCount_);
        chunk.setOutboundStreamsCount(outboundStreamsCount_);
        state_ = State::CookieWait;
        sendFirstPriority(packet);
    }

    void Association::abort(Error error)
    {
        error_ = error;
        // TODO send abort
        emit errorOccured();
    }

    void Association::setError(Error error)
    {
        error_ = error;
        emit errorOccured();
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

    void Association::writeIncoming(const QByteArray &data)
    {
        const Packet pkt(data);
        if (!pkt.isValidSctp()) {
            return; // ignore non-sctp or broken sctp
        }
        auto verificationTag = pkt.verificationTag();
        if (state_ != State::Closed && verificationTag != myVerificationTag_) {
            return; // 8.5 discard silently. TODO review exception rules 8.5.1
        }
        bool allowMoreChunks = true;
        int  hundledChunks   = 0;
        for (const auto &chunk : pkt) {
            if (!chunk.isValid() || !allowMoreChunks) {
                abort(Error::ProtocolViolation);
                return;
            }
            switch (chunk.type()) {
            case InitChunk::Type:
                if (verificationTag) {
                    abort(Error::VerificationTag);
                    return;
                }
                if (hundledChunks) {
                    abort(Error::ProtocolViolation);
                    return;
                }
                allowMoreChunks  = false;
                sourcePort_      = pkt.destinationPort();
                destinationPort_ = pkt.sourcePort();
                incomingChunk(chunk.as<InitChunk>());
                break;
            case InitAckChunk::Type:
                if (hundledChunks) {
                    abort(Error::ProtocolViolation);
                    return;
                }
                allowMoreChunks = false;
                incomingChunk(chunk.as<InitAckChunk>());
                break;
            case CookieEchoChunk::Type:
                incomingChunk(chunk.as<CookieEchoChunk>());
                break;
            case CookieAckChunk::Type:
                incomingChunk(chunk.as<CookieAckChunk>());
                break;
            case SackChunk::Type:
                incomingChunk(chunk.as<SackChunk>());
                break;
            }

            hundledChunks++;
        }
    }

    void Association::write(quint16 streamId, bool unordered, const QByteArray &payloadProto, const QByteArray &data)
    {
        if (state_ == State::Closed || state_ == State::ShutdownSent || state_ == State::ShutdownAckSent) {
            setError(Error::WrongState);
            return;
        }
        int   offset = 0;
        auto &ssn    = stream2ssn_[streamId];
        while (offset < data.size()) {
            auto       toTake = std::min(data.size(), int(mtu_) - Packet::HeaderSize - DataChunk::MinHeaderSize);
            UnackChunk transfer;
            transfer.data.resize(toTake + DataChunk::MinHeaderSize);
            DataChunk chunk { transfer.data, 0, transfer.data.size() };
            chunk.setUnordered(unordered);
            chunk.setBeginning(offset == 0);
            chunk.setEnding(offset + toTake == data.size());
            chunk.setUserData(QByteArray::fromRawData(data.constData() + offset, toTake));
            chunk.setPayloadProtocol(payloadProto);
            chunk.setStreamIdentifier(streamId);
            chunk.setTsn(nextTsn_);
            if (!unordered) {
                chunk.setStreamSequenceNumber(ssn);
            }
            dataSendQueue_.push_back(transfer);
            nextTsn_++;
        }
        ssn++;
        trySend();
    }

    void Association::incomingChunk(const InitChunk &chunk)
    {
        initRemote(chunk);
        if (peerVerificationTag_ == 0) {
            abort(Error::VerificationTag);
            return;
        }

        Packet packet;
        auto   ack = packet.appendChunk<InitAckChunk>();

        ack.setInitiateTag(myVerificationTag_);
        ack.setInitialTsn(nextTsn_);
        ack.setReceiverWindowCredit(localWindowCredit_);
        ack.setInboundStreamsCount(inboundStreamsCount_);
        ack.setOutboundStreamsCount(outboundStreamsCount_);
        ack.appendParameter<CookieParameter>(makeStateCookie());

        // after sending this packet we can theoretically free asociation and recreate it later from the cookie,
        // but it's not really necessary when we work in bundle with DataChannel which already provides decent level
        // of security and reliability
        sendFirstPriority(packet);
    }

    void Association::initRemote(const InitChunk &chunk)
    {
        lastRcvdTsn_          = chunk.initialTsn() - 1;
        peerVerificationTag_  = chunk.initiateTag();
        remoteWindowCredit_   = chunk.receiverWindowCredit();
        ssthresh_             = remoteWindowCredit_;
        inboundStreamsCount_  = chunk.inboundStreamsCount();
        outboundStreamsCount_ = chunk.outboundStreamsCount();
        cwnd_                 = std::min(4 * mtu_, std::max(2 * mtu_, 4380u));
        // TODO make congestion window controller
    }

    void Association::incomingChunk(const InitAckChunk &chunk)
    {
        const auto cookie = chunk.parameter<CookieParameter>();
        if (!cookie.isValid()) {
            abort(Error::InvalidCookie);
            return;
        }

        initRemote(chunk);

        Packet packet;
        packet.appendChunk<CookieEchoChunk>(cookie.value());
        state_ = State::CookieEchoed;
        sendFirstPriority(packet);
    }

    void Association::incomingChunk(const CookieEchoChunk &chunk)
    {
        const auto cookie   = chunk.value();
        auto       hashSize = QCryptographicHash::hashLength(QCryptographicHash::Sha1);
        if (cookie.size() < hashSize) {
            abort(Error::InvalidCookie);
            return;
        }
        const auto msg = QByteArray::fromRawData(cookie.constData(), cookie.size() - hashSize);
        if (QMessageAuthenticationCode::hash(msg, privKey, QCryptographicHash::Sha1)
            != QByteArray::fromRawData(cookie.constData() + cookie.size() - hashSize, hashSize)) {
            abort(Error::InvalidCookie);
            return;
        }

        Packet packet;
        packet.appendChunk<CookieAckChunk>();
        sendFirstPriority(packet);

        state_ = State::Established;
        emit established();
    }

    void Association::incomingChunk(const CookieAckChunk &)
    {
        state_ = State::Established;
        emit established();
    }

    void Association::incomingChunk(const SackChunk &chunk)
    {
        if (!(state_ == State::Established || state_ == State::ShutdownPending || state_ == State::ShutdownReceived)) {
            return; // we don't care
        }
        auto gaps = chunk.gaps();
        auto dups = chunk.dups();
        // TODO
    }

    void Association::incomingChunk(const DataChunk &chunk)
    {
        if (!(state_ == State::Established || state_ == State::ShutdownPending || state_ == State::ShutdownSent)) {
            return; // we don't care
        }
        // - defragmentation
        // - reorderingController
    }

}}
