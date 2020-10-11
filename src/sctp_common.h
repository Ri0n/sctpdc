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

#include <type_traits>

namespace SctpDc { namespace Sctp {
    template <class Item, class Data> class Iterator {
    public:
        Item item;
        int  maxOffset; // size of packet for a chunk or size of chunk for a parameter

        Iterator(Data &data, int offset, int maxOffset) :
            item(data, offset, ((maxOffset - offset) < 4 ? 0 : qFromBigEndian<quint16>(data.constData() + offset + 2))),
            maxOffset(maxOffset)
        {
            if (item.size + offset > maxOffset) {
                item.size = 0;
            }
        }

        // inline quint16 fetchSize() { return (item.size = qFromBigEndian<quint16>(data.constData() + offset + 2)); }

        inline Item        operator*() const { return item; }
        inline Item        value() const { return item; }
        inline const Item *operator->() const { return &item; } // don't store the returned pointer. it will change.
        Iterator &         operator++()
        {
            if (item.size < 4) { // less than header size => invalid
                item.offset = maxOffset;
                return *this;
            }
            item.offset += ((item.size + 3) & ~3);
            if ((maxOffset - item.offset) < 4
                || ((item.size = qFromBigEndian<quint16>(item.data.constData() + item.offset + 2)) + item.offset)
                    > maxOffset) {
                item.size = 0;
            }
            return *this;
        }
        bool operator!=(const Iterator &other) const { return item.offset != other.item.offset; }
        bool operator==(const Iterator &other) const { return item.offset == other.item.offset; }
    };

    template <class Item> class ConstIterator {
    public:
        Item item;
        int  maxOffset; // size of packet for a chunk or size of chunk for a parameter

        ConstIterator(const QByteArray &data, int offset, int maxOffset) :
            item(const_cast<QByteArray &>(data), offset,
                 ((maxOffset - offset) < 4 ? 0 : qFromBigEndian<quint16>(data.constData() + offset + 2))),
            maxOffset(maxOffset)
        {
            if (item.size + offset > maxOffset) {
                item.size = 0;
            }
        }

        // inline quint16 fetchSize() { return (item.size = qFromBigEndian<quint16>(data.constData() + offset + 2)); }

        inline const Item operator*() const { return item; }
        inline const Item value() const { return item; }
        ConstIterator &   operator++()
        {
            if (item.size < 4) { // less than header size => invalid
                item.offset = maxOffset;
                return *this;
            }
            item.offset += ((item.size + 3) & ~3);
            if ((maxOffset - item.offset) < 4
                || ((item.size = qFromBigEndian<quint16>(item.data.constData() + item.offset + 2)) + item.offset)
                    > maxOffset) {
                item.size = 0;
            }
            return *this;
        }
        bool operator!=(const ConstIterator &other) const { return item.offset != other.item.offset; }
        bool operator==(const ConstIterator &other) const { return item.offset == other.item.offset; }
    };

    class Iterable {
    public:
        QByteArray &data;
        int         offset;
        quint16     size;

        constexpr Iterable(QByteArray &data, int offset, int size) : data(data), offset(offset), size(size) { }
        constexpr Iterable(const Iterable &other) : data(other.data), offset(other.offset), size(other.size) { }
        Iterable &operator=(const Iterable &other)
        {
            offset = other.offset;
            size   = other.size;
            return *this;
        }

        inline bool isValid(int headerSize = 4) const { return size >= headerSize; }

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
        void                    setData(int relOffset, const QByteArray &newData);
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
    };

    class Parameter : public Iterable {
    public:
        using Iterable::Iterable;

        inline quint16    type() const { return qFromBigEndian<quint16>(data.constData() + offset); }
        inline QByteArray value() const { return QByteArray::fromRawData(data.constData() + offset + 4, length() - 4); }
    };

    using parameter_iterator       = Iterator<Parameter, QByteArray &>;
    using const_parameter_iterator = ConstIterator<Parameter>;

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
        int allocParameter(quint16 type, quint16 extraSpace);

        template <class ChunkType> ChunkType &      as() { return *static_cast<ChunkType *>(this); }
        template <class ChunkType> const ChunkType &as() const { return *static_cast<const ChunkType *>(this); }
    };

    template <class ChunkType> class ChunkWithPayload : public Chunk {
    public:
        using Chunk::Chunk;
        inline QByteArray value() const
        {
            return QByteArray::fromRawData(data.constData() + offset + ChunkType::MinHeaderSize,
                                           length() - ChunkType::MinHeaderSize);
        }
    };

    using chunk_iterator       = Iterator<Chunk, QByteArray>;
    using const_chunk_iterator = ConstIterator<Chunk>;

    template <class ChunkType> class ChunkWithParameters : public Chunk {
    public:
        using Chunk::Chunk;

        // works similar to allocChunk.
        template <class T> T appendParameter(int payloadSize)
        {
            auto offset = allocParameter(T::Type, payloadSize);
            return T { this->data, offset, payloadSize + 4 };
        }
        template <class T> T appendParameter(const QByteArray &payload)
        {
            auto offset = allocParameter(T::Type, payload.size());
            data.replace(offset + 4, payload.size(), payload);
            return T { this->data, offset, payload.size() + 4 };
        }
        template <class T> T parameter() const
        {
            for (auto const &param : static_cast<const ChunkType &>(*this)) {
                if (!param.isValid())
                    return static_cast<const T &>(param);
                if (param.type() == T::Type) {
                    return static_cast<const T &>(param);
                }
            }
            return { data, 0, 0 };
        }

        inline parameter_iterator       end() { return { data, offset + size, offset + size }; }
        inline const_parameter_iterator end() const { return { data, offset + size, offset + size }; }

        inline parameter_iterator       begin() { return { data, offset + ChunkType::MinHeaderSize, offset + size }; }
        inline const_parameter_iterator begin() const
        {
            // data, parameters offset, max offset
            return { data, offset + ChunkType::MinHeaderSize, offset + size };
        }
    };

    class Packet {
    public:
        constexpr static int HeaderSize = 12;

        Packet() = default;
        Packet(const QByteArray &data) : data_(data) { }

        bool minimalValidation(uint16_t *sourcePort = nullptr, uint16_t *destinationPort = nullptr) const;
        bool isValidSctp() const { return minimalValidation() && checksum() == computeChecksum(); }

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
        inline chunk_iterator begin() { return { data_, HeaderSize, data_.size() }; }
        inline chunk_iterator end() { return { data_, data_.size(), data_.size() }; }

        inline const_chunk_iterator begin() const { return { data_, HeaderSize, data_.size() }; }
        inline const_chunk_iterator end() const { return { data_, data_.size(), data_.size() }; }

        // extra space for tlv parameters or payload
        // header size + extraSpace will be set as chunk length
        int                  allocChunk(quint8 type, quint16 headerSize, quint16 extraSpace);
        template <class T> T appendChunk(quint16 extraSpace = 0)
        {
            auto offset = allocChunk(T::Type, T::MinHeaderSize, extraSpace);
            return T { this->data_, offset, extraSpace + T::MinHeaderSize };
        }
        template <class T> T appendChunk(const QByteArray &payload)
        {
            auto offset = allocChunk(T::Type, T::MinHeaderSize, payload.size());
            data_.replace(offset + T::MinHeaderSize, payload.size(), payload);
            return T { this->data_, offset, payload.size() + T::MinHeaderSize };
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
