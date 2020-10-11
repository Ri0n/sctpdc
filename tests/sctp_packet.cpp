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

#include "sctp_chunk.h"
#include "sctp_common.h"
#include "sctp_parameter.h"

#include <QTest>

using namespace SctpDc::Sctp;

class PacketTest : public QObject {
    Q_OBJECT

private slots:
    void headerTest()
    {
        const char arr[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
        auto       data  = QByteArray::fromRawData(arr, sizeof(arr));

        SctpDc::Sctp::Packet packet(data);
        QVERIFY(!packet.isValidSctp()); // hashsum isn't valid definitely
        QCOMPARE(packet.sourcePort(), 0x0102);
        QCOMPARE(packet.destinationPort(), 0x0304);
        QCOMPARE(packet.verificationTag(), 0x05060708);

        packet.setSourcePort(0x1122);
        packet.setDestinationPort(0x3344);
        packet.setVerificationTag(0x55667788);
        packet.setChecksum(0x99AABBCC);
        const unsigned char verarr[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC };
        data                         = QByteArray::fromRawData(reinterpret_cast<const char *>(verarr), sizeof(verarr));
        QCOMPARE(packet.takeData(), data);
    }

    void unalignedChunk()
    {
        const char arr[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };

        Packet packet;
        packet.appendChunk<DataChunk>(QByteArray::fromRawData(arr, 2));
        packet.appendChunk<DataChunk>(QByteArray::fromRawData(arr + 2, 7));
        auto it = packet.begin();
        QCOMPARE(it->as<DataChunk>().value(), QByteArray::fromRawData(arr, 2));
        QCOMPARE((++it)->as<DataChunk>().value(), QByteArray::fromRawData(arr + 2, 7));
        QCOMPARE(packet.takeData().size(), Packet::HeaderSize + DataChunk::MinHeaderSize * 2 + 4 + 8);
    }

    void unalignedParameter()
    {
        const char arr[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };

        Packet packet;
        auto   chunk = packet.appendChunk<InitChunk>();
        chunk.appendParameter<CookieParameter>(QByteArray::fromRawData(arr, 2));
        chunk.appendParameter<CookieParameter>(QByteArray::fromRawData(arr + 2, 7));
        auto it = chunk.begin();
        QCOMPARE((*it).value(), QByteArray::fromRawData(arr, 2));
        ++it;
        QCOMPARE((*it).value(), QByteArray::fromRawData(arr + 2, 7));
        QCOMPARE(packet.takeData().size(),
                 Packet::HeaderSize + InitChunk::MinHeaderSize + 4 * 2 /* headers */ + 4 + 8 /* payloads */);
    }
};

QTEST_MAIN(PacketTest)

#include "sctp_packet.moc"
