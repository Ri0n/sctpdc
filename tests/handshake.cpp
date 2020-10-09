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

#include <QTest>

class HandshakeTest : public QObject {
    Q_OBJECT

    SctpDc::Sctp::Association *local  = nullptr;
    SctpDc::Sctp::Association *remote = nullptr;

private slots:
    void init()
    {
        local  = new SctpDc::Sctp::Association(1, 2, this);
        remote = new SctpDc::Sctp::Association(2, 1, this);
    }

    void initLocalTest()
    {
        local->associate();
        QByteArray data = local->readOutgoing();
        QVERIFY(!data.isEmpty());
        QCOMPARE(local->state(), SctpDc::Sctp::Association::State::CookieWait);
    }

    void remoteReceiveInitTest()
    {
        // previous
        local->associate();
        QByteArray data = local->readOutgoing();

        remote->writeIncoming(data);   // init from local
        data = remote->readOutgoing(); // read init-ack
        QVERIFY(!data.isEmpty());
        QCOMPARE(remote->state(), SctpDc::Sctp::Association::State::Closed);
    }

    void localReceiveInitAckTest()
    {
        // previous
        local->associate();
        QByteArray data = local->readOutgoing();
        remote->writeIncoming(data);
        data = remote->readOutgoing();

        local->writeIncoming(data);   // init-ack from remote
        data = local->readOutgoing(); // read cookie-echoed
        QVERIFY(!data.isEmpty());
        QCOMPARE(local->state(), SctpDc::Sctp::Association::State::CookieEchoed);
    }

    void remoteReceiveCookieEchoedTest()
    {
        // previous
        local->associate();
        QByteArray data = local->readOutgoing();
        remote->writeIncoming(data);
        data = remote->readOutgoing();
        local->writeIncoming(data);
        data = local->readOutgoing();

        remote->writeIncoming(data);   // cookie-echoed from local
        data = remote->readOutgoing(); // read cookie-ack
        QVERIFY(!data.isEmpty());
        QCOMPARE(remote->state(), SctpDc::Sctp::Association::State::Established);
    }

    void localReceiveCookieAckTest()
    {
        // previous
        local->associate();
        QByteArray data = local->readOutgoing();
        remote->writeIncoming(data);
        data = remote->readOutgoing();
        local->writeIncoming(data);
        data = local->readOutgoing();
        remote->writeIncoming(data);
        data = remote->readOutgoing();

        local->writeIncoming(data);   // cookie-ack from remote
        data = local->readOutgoing(); // read nothing
        QVERIFY(data.isEmpty());
        QCOMPARE(local->state(), SctpDc::Sctp::Association::State::Established);
    }

    void cleanup()
    {
        delete local;
        delete remote;
    }
};

QTEST_MAIN(HandshakeTest)

#include "handshake.moc"
