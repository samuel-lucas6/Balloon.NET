using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Numerics;

namespace BalloonDotNet;

public static class Balloon
{
    public const int HashSize = 32;
    public const int SaltSize = 16;
    public const int MinDelta = 3;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int spaceCost, int timeCost, int delta = MinDelta)
    {
        if (outputKeyingMaterial.Length != HashSize) { throw new ArgumentOutOfRangeException(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, $"{nameof(outputKeyingMaterial)} must be {HashSize} bytes long."); }
        if (spaceCost < 1) { throw new ArgumentOutOfRangeException(nameof(spaceCost), spaceCost, $"{nameof(spaceCost)} must be greater than 0."); }
        if (timeCost < 1) { throw new ArgumentOutOfRangeException(nameof(timeCost), timeCost, $"{nameof(timeCost)} must be greater than 0."); }
        if (delta < MinDelta) { throw new ArgumentOutOfRangeException(nameof(delta), delta, $"{nameof(delta)} must be greater than or equal to {MinDelta}."); }

        var buffer = new List<byte[]>();
        for (int i = 0; i < spaceCost; i++) {
            buffer.Add(new byte[HashSize]);
        }
        ulong counter = 0;
        Span<byte> idxBlock = stackalloc byte[HashSize];

        Hash(buffer[0], counter++, password, salt);
        for (int m = 1; m < spaceCost; m++) {
            Hash(buffer[m], counter++, buffer[m - 1]);
        }

        for (int t = 0; t < timeCost; t++) {
            for (int m = 0; m < spaceCost; m++) {
                Span<byte> previous = buffer[m == 0 ? spaceCost - 1 : m - 1];
                Hash(buffer[m], counter++, previous, buffer[m]);

                for (int i = 0; i < delta; i++) {
                    IntsToBlock(idxBlock, t, m, i);
                    Hash(idxBlock, counter++, salt, idxBlock);
                    var other = new BigInteger(idxBlock, isUnsigned: true, isBigEndian: false) % spaceCost;
                    Hash(buffer[m], counter++, buffer[m], buffer[(int)other]);
                }
            }
        }

        buffer[spaceCost - 1].AsSpan()[..outputKeyingMaterial.Length].CopyTo(outputKeyingMaterial);
        CryptographicOperations.ZeroMemory(buffer[spaceCost - 1]);
    }

    private static void Hash(Span<byte> buffer, ulong counter, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt = default)
    {
        Span<byte> ctr = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(ctr, counter);
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha256.AppendData(ctr);
        sha256.AppendData(password);
        sha256.AppendData(salt);
        sha256.GetCurrentHash(buffer);
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
