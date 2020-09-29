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

#include <QByteArray>
#include <QObject>
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

        constexpr Iterable(QByteArray &data, int offset, int size) : data(data), offset(offset), size(size) { }

        inline bool isValid(int headerSize = 4) const
        {
            auto tail = data.size() - offset;
            return tail >= headerSize && length() <= tail;
        }

        inline void ensureCapacity(int capacity)
        {
            if (data.size() < capacity) {
                data.resize(capacity);
            }
        }

        /**
         * @brief setData sets data at offset + relOffset to newData
         * @param relOffset
         * @param newData
         */
        inline void             setData(int relOffset, const QByteArray &newData);
        inline const QByteArray getData(int relOffset, int size) const
        {
            return QByteArray::fromRawData(data.constData() + offset + relOffset, size);
        }

        inline quint16 length() const { return qFromBigEndian<quint16>(data.constData() + offset + 2); }
        inline void    setLength(quint16 value)
        {
            ensureCapacity(4);
            qToBigEndian(value, data.data() + offset + 2);
        }

        inline QByteArray value() const { return QByteArray::fromRawData(data.constData() + offset + 4, length() - 4); }
    };

    class Parameter : public Iterable {
    public:
        inline quint16 type() const { return qFromBigEndian<quint16>(data.constData() + offset); }
    };

    using parameter_iterator       = Iterator<Parameter, QByteArray>;
    using const_parameter_iterator = Iterator<const Parameter, const QByteArray>;

    class Chunk : public Iterable {
    public:
        using Iterable::Iterable;

        inline quint8 type() const { return data[offset]; }
        inline quint8 flags() const { return data[offset + 1]; }
        inline void   setFlags(quint8 value) { data[offset + 1] = value; }
        inline void   setFlag(quint8 flag, bool value)
        {
            data[offset + 1] = value ? (data[offset + 1] | flag) : (data[offset + 1] & ~flag);
        }

        inline parameter_iterator       end() { return { data, data.size(), 0 }; }
        inline const_parameter_iterator end() const { return { data, data.size(), 0 }; }

        template <class T> parameter_iterator       begin() { return { data, offset + T::MinHeaderSize, data.size() }; }
        template <class T> const_parameter_iterator begin() const
        {
            return { data, offset + T::MinHeaderSize, data.size() };
        }
    };

    using chunk_iterator       = Iterator<Chunk, QByteArray>;
    using const_chunk_iterator = Iterator<const Chunk, const QByteArray>;

    class Packet {
    public:
        constexpr static int HeaderSize = 12;

        Packet() = default;
        Packet(const QByteArray &data) : data_(data) { }
        bool isValidSctp() const
        {
            return data_.size() >= 12 && sourcePort() != 0 && destinationPort() != 0 && checksum() == computeChecksum();
        }

        inline quint16 sourcePort() const { return qFromBigEndian<quint16>(data_.data()); }
        inline void    setSourcePort(quint16 port) { qToBigEndian(port, data_.data()); }
        inline quint16 destinationPort() const { return qFromBigEndian<quint16>(data_.data() + 2); }
        inline void    setDestinationPort(quint16 port) { qToBigEndian(port, data_.data() + 2); }
        inline quint32 verificationTag() const { return qFromBigEndian<quint32>(data_.data() + 4); }
        inline void    setVerificationTag(quint32 vt) { qToBigEndian(vt, data_.data() + 4); }
        inline quint32 checksum() const { return qFromBigEndian<quint32>(data_.data() + 8); }
        inline void    setChecksum(quint32 cs) { qToBigEndian(cs, data_.data() + 8); }
        inline void    setChecksum() { setChecksum(computeChecksum()); }

        // Note, it's undefined behaviour to iterate over invalid packet
        inline chunk_iterator begin() { return { data_, HeaderSize, data_.size() }; };
        inline chunk_iterator end() { return { data_, data_.size(), 0 }; }

        inline const_chunk_iterator begin() const { return { data_, HeaderSize, data_.size() }; };
        inline const_chunk_iterator end() const { return { data_, data_.size(), 0 }; }

        // extra space for tlv parameters or payload
        // header size + extraSpace will be set as chunk length
        int                  allocChunk(quint8 type, quint16 headerSize, quint16 extraSpace);
        template <class T> T appendChunk(quint16 extraSpace = 0)
        {
            auto offset = allocChunk(T::Type, T::MinHeaderSize, extraSpace);
            return T { this->data_, offset, this->data_.size() };
        }

        inline QByteArray takeData()
        {
            QByteArray d(std::move(data_));
            return d;
        }

    private:
        friend chunk_iterator;
        friend const_chunk_iterator;

        quint32 computeChecksum() const;

        QByteArray data_;
    };

} // namespace Sctp
} // namespace SctpDc
