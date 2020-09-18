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

#include <QByteArray>
#include <QtEndian>

namespace SctpDc { namespace Net {
    class Packet;
    class Chunk {
    public:
        Chunk(const QByteArray &&data) : data(std::move(data)) { }

        inline bool       isValid() const { return data.size() >= 4 && length() <= data.size(); }
        inline quint8     type() const { return data[0]; }
        inline quint8     flags() const { return data[1]; }
        inline quint16    length() const { return qFromBigEndian<quint16>(data.constData() + 2); }
        inline QByteArray value() const
        {
            int sz = data.size() > 4 ? length() : 0;
            return sz > 4 ? QByteArray::fromRawData(data.constData() + 4, qMin(sz, data.size())) : QByteArray();
        }

    private:
        QByteArray data; // usually a raw data ref while iterating over the packet
    };

    template <class PacketT> class ChunkIterator {
    public:
        PacketT &packet;
        int      offset;

        Chunk operator*() const
        {
            int tail = packet.data.size() - offset;
            return Chunk { QByteArray::fromRawData(packet.data.constData() + offset, tail > 0 ? tail : 0) };
        }
        ChunkIterator &operator++()
        {
            // it's up to the caller to take care of safety
            quint16 size = qFromBigEndian(packet.data.constData() + offset + 2) + 3;
            offset += (size & ~4);
            return *this;
        }
    };
    using iterator       = ChunkIterator<Packet>;
    using const_iterator = ChunkIterator<const Packet>;

    class Packet {
    public:
        Packet(const QByteArray &data) : data(data) { }
        bool isValidSctp() const
        {
            return data.size() >= 12 && sourcePort() != 0 && destinationPort() != 0 && checksum() == computeChecksum();
        }

        inline quint16 sourcePort() const { return qFromBigEndian<quint16>(data.data()); }
        inline quint16 destinationPort() const { return qFromBigEndian<quint16>(data.data() + 2); }
        inline quint32 verificationTag() const { return qFromBigEndian<quint32>(data.data() + 4); }
        inline quint32 checksum() const { return qFromBigEndian<quint32>(data.data() + 8); }
        inline void    setChecksum(quint32 cs) { qToBigEndian(cs, data.data() + 8); }

        inline iterator begin()
        {
            int start = qMin(12, data.size());
            return iterator { *this, start };
        };
        inline iterator end() { return iterator { *this, data.size() }; }

        inline const_iterator begin() const
        {
            int start = qMin(12, data.size());
            return const_iterator { *this, start };
        };
        inline const_iterator end() const { return const_iterator { *this, data.size() }; }

    private:
        friend iterator;
        friend const_iterator;

        quint32 computeChecksum() const;

        QByteArray data;
    };
} // namespace Net
} // namespace SctpDc
