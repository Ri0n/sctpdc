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

namespace SctpDc { namespace Sctp {
    template <class Item, class Data> class Iterator {
    public:
        Data &data;
        int   offset;
        int   size;

        Item operator*() const
        {
            int tail = size - offset;
            return Item { data, offset, tail > 0 ? tail : 0 };
        }
        Iterator &operator++()
        {
            // it's up to the caller to take care of safety
            quint16 size = qFromBigEndian<quint16>(data.constData() + offset + 2) + 3;
            offset += (size & ~4);
            return *this;
        }
    };

    class Iterable {
    public:
        QByteArray &data;
        int         offset;
        int         size;

        inline bool isValid() const
        {
            auto tail = data.size() - offset;
            return tail >= 4 && length() <= tail;
        }
        inline quint16    length() const { return qFromBigEndian<quint16>(data.constData() + offset + 2); }
        inline QByteArray value() const { return QByteArray::fromRawData(data.constData() + offset + 4, length() - 4); }
    };

    class Chunk : public Iterable {
    public:
        inline quint8 type() const { return data[offset]; }
        inline quint8 flags() const { return data[offset + 1]; }
        inline void   setFlags(quint8 value) { data[offset + 1] = value; }
        inline void   setFlag(quint8 flag, bool value)
        {
            data[offset + 1] = value ? (data[offset + 1] | flag) : (data[offset + 1] & ~flag);
        }
    };

    class Parameter : public Iterable {
    public:
        inline quint16 type() const { return qFromBigEndian<quint16>(data.constData() + offset); }
    };

    using chunk_iterator       = Iterator<Chunk, QByteArray>;
    using const_chunk_iterator = Iterator<const Chunk, const QByteArray>;

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

        // Note, it's undefined behaviour to iterate over invalid packet
        inline chunk_iterator begin() { return { data, 12, data.size() }; };
        inline chunk_iterator end() { return { data, data.size(), 0 }; }

        inline const_chunk_iterator begin() const { return { data, 12, data.size() }; };
        inline const_chunk_iterator end() const { return { data, data.size(), 0 }; }

    private:
        friend chunk_iterator;
        friend const_chunk_iterator;

        quint32 computeChecksum() const;

        QByteArray data;
    };

} // namespace Sctp
} // namespace SctpDc
