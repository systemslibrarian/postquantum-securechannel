using System.Buffers.Binary;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// Minimal, allocation-light, length-prefixed binary writer/reader used to serialize handshake
/// messages in a self-describing, version-tolerant way. All multi-byte integers are big-endian.
/// </summary>
internal sealed class WireWriter
{
    private readonly List<byte> _buffer = new(256);

    internal WireWriter WriteByte(byte value)
    {
        _buffer.Add(value);
        return this;
    }

    internal WireWriter WriteUInt16(ushort value)
    {
        Span<byte> tmp = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(tmp, value);
        _buffer.AddRange(tmp.ToArray());
        return this;
    }

    /// <summary>Writes a 16-bit length prefix followed by the raw bytes.</summary>
    internal WireWriter WriteBlock(ReadOnlySpan<byte> value)
    {
        if (value.Length > ushort.MaxValue)
        {
            throw new ArgumentException($"Block length {value.Length} exceeds the 65535-byte wire limit.", nameof(value));
        }

        WriteUInt16((ushort)value.Length);
        _buffer.AddRange(value.ToArray());
        return this;
    }

    internal byte[] ToArray() => _buffer.ToArray();
}

/// <summary>Companion reader for <see cref="WireWriter"/>. Throws <see cref="FormatException"/> on truncation.</summary>
internal ref struct WireReader
{
    private ReadOnlySpan<byte> _data;

    internal WireReader(ReadOnlySpan<byte> data) => _data = data;

    internal readonly bool IsEmpty => _data.IsEmpty;

    internal byte ReadByte()
    {
        Require(1);
        var value = _data[0];
        _data = _data[1..];
        return value;
    }

    internal ushort ReadUInt16()
    {
        Require(2);
        var value = BinaryPrimitives.ReadUInt16BigEndian(_data);
        _data = _data[2..];
        return value;
    }

    internal byte[] ReadBlock()
    {
        int length = ReadUInt16();
        Require(length);
        var value = _data[..length].ToArray();
        _data = _data[length..];
        return value;
    }

    private readonly void Require(int count)
    {
        if (_data.Length < count)
        {
            throw new FormatException("Malformed message: unexpected end of data.");
        }
    }
}
