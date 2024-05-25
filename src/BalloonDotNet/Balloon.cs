using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Numerics;

namespace BalloonDotNet;

public static class Balloon
{
    public const int HashSize = 32;
    public const int SaltSize = 16;
    public const int MinDelta = 3;

    public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int spaceCost, int timeCost, int delta = MinDelta)
    {
        if (hash.Length != HashSize) { throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"{nameof(hash)} must be {HashSize} bytes long."); }
        if (spaceCost < 1) { throw new ArgumentOutOfRangeException(nameof(spaceCost), spaceCost, $"{nameof(spaceCost)} must be greater than 0."); }
        if (timeCost < 1) { throw new ArgumentOutOfRangeException(nameof(timeCost), timeCost, $"{nameof(timeCost)} must be greater than 0."); }
        if (delta < MinDelta) { throw new ArgumentOutOfRangeException(nameof(delta), delta, $"{nameof(delta)} must be greater than or equal to {MinDelta}."); }

        Span<byte> buffer = new byte[spaceCost * HashSize];
        Span<byte> counter = stackalloc byte[8];
        Span<byte> idxBlock = stackalloc byte[HashSize];

        Hash(buffer[..HashSize], counter, password, salt);
        for (int m = 1; m < spaceCost; m++) {
            Hash(buffer.Slice(m * HashSize, HashSize), counter, buffer.Slice((m - 1) * HashSize, HashSize));
        }

        for (int t = 0; t < timeCost; t++) {
            for (int m = 0; m < spaceCost; m++) {
                Span<byte> previous = buffer.Slice(m == 0 ? (spaceCost - 1) * HashSize : (m - 1) * HashSize, HashSize);
                Span<byte> current = buffer.Slice(m * HashSize, HashSize);
                Hash(current, counter, previous, current);

                for (int i = 0; i < delta; i++) {
                    IntsToBlock(idxBlock, t, m, i);
                    Hash(idxBlock, counter, salt, idxBlock);
                    var other = new BigInteger(idxBlock, isUnsigned: true, isBigEndian: false) % spaceCost;
                    Hash(current, counter, current, buffer.Slice((int)other * HashSize, HashSize));
                }
            }
        }

        buffer[^HashSize..].CopyTo(hash);
        CryptographicOperations.ZeroMemory(buffer);
    }

    private static void Hash(Span<byte> buffer, Span<byte> counter, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt = default)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha256.AppendData(counter);
        sha256.AppendData(password);
        sha256.AppendData(salt);
        sha256.GetCurrentHash(buffer);

        for (int i = 0; i < counter.Length; i++) {
            counter[i]++;
            if (counter[i] != 0) {
                break;
            }
        }
    }

    private static void IntsToBlock(Span<byte> idxBlock, int t, int m, int i)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(idxBlock[..8], (ulong)t);
        BinaryPrimitives.WriteUInt64LittleEndian(idxBlock[8..16], (ulong)m);
        BinaryPrimitives.WriteUInt64LittleEndian(idxBlock[16..24], (ulong)i);

        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha256.AppendData(idxBlock[..24]);
        sha256.GetCurrentHash(idxBlock);
    }
}
