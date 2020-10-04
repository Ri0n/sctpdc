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

#include <QObject>

#include <memory>
#include <tuple>

namespace SctpDc {
class StreamChannel;
class DatagramChannel;

class Connection : public QObject {
    Q_OBJECT
public:
    Connection(QObject *parent);

    void associate();

    StreamChannel *  makeStreamChannel();
    DatagramChannel *makeDatagramChannel();

signals:
    void connected();
    void disconnected();

private:
    class Private;
    std::unique_ptr<Private> d;
};

/**
 * @brief minimalValidation very minimal and quick check if it's really a sctp packet
 * @param sourcePort - sctp source port from the packet
 * @param destinationPort - sctp destination port from the packet
 * @return true if the packet looks like sctp
 *
 * This function in general has to be called first if it's assumed the data has sctp packet.
 * The function does nothing CPU consuming. For example it doesn't check packet checksum but checks other header fields.
 *
 * Out parameters soure and destination ports will contain the port information from the sctp packet. If the packet is
 * not valid sctp the out parameters won't be changed.
 * The ports information later can be used by the caller to pass this packet to the corresponding association.
 *
 * The function is thread-safe.
 */
bool minimalValidation(const QByteArray &data, std::uint16_t &sourcePort, std::uint16_t &destinationPort);
}
