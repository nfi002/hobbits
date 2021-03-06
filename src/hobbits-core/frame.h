#ifndef FRAME_H
#define FRAME_H

#include "bitarray.h"
#include "range.h"
#include <QSharedPointer>

#include "hobbits-core_global.h"

class HOBBITSCORESHARED_EXPORT Frame : public Range
{
public:
    Frame();
    Frame(QSharedPointer<const BitArray> bits, qint64 start, qint64 end);
    Frame(QSharedPointer<const BitArray> bits, Range range);
    Frame(const Frame &other) = default;

    bool at(qint64 i) const;

private:
    QSharedPointer<const BitArray> m_bits;
};

#endif // FRAME_H
