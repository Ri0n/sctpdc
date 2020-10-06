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

#include <QTest>

void testHandshake()
{
    SctpDc::Sctp::Association local(1, 2);
    local.associate();
    auto data = local.readOutgoing();
    QVERIFY(!data.isEmpty());
    QCOMPARE(local.state(), SctpDc::Sctp::Association::State::CookieWait);

    // remote receives init, remote sends init-ack with cookie, local receives init-ack, local sends cookie-echo
    SctpDc::Sctp::Association remote(2, 1);
    remote.writeIncoming(data);
    local.writeIncoming(remote.readOutgoing());
    data = local.readOutgoing();
    QVERIFY(!data.isEmpty());
    QCOMPARE(remote.state(), SctpDc::Sctp::Association::State::Closed);
    QCOMPARE(local.state(), SctpDc::Sctp::Association::State::CookieEchoed);

    // remote receive CookieEchoed, remote send CookieAck and comes to established. Local receives CookieAck
    remote.writeIncoming(data);
    local.writeIncoming(remote.readOutgoing());
    data = local.readOutgoing();
    QVERIFY(data.isEmpty());
    QCOMPARE(local.state(), SctpDc::Sctp::Association::State::Established);
    QCOMPARE(remote.state(), SctpDc::Sctp::Association::State::Established);
}

int main()
{
    testHandshake();
    return 0;
}
