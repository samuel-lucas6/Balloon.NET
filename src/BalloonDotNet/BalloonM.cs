﻿using System.Security.Cryptography;
using System.Buffers.Binary;

namespace BalloonDotNet;

public static class BalloonM
{
    public const int HashSize = Balloon.HashSize;
    public const int SaltSize = Balloon.SaltSize;
    public const int MinDelta = Balloon.MinDelta;

    public static unsafe void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int spaceCost, int timeCost, int parallelism, int delta = MinDelta)
    {
        if (hash.Length != HashSize) { throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"{nameof(hash)} must be {HashSize} bytes long."); }
        if (spaceCost < 1) { throw new ArgumentOutOfRangeException(nameof(spaceCost), spaceCost, $"{nameof(spaceCost)} must be greater than 0."); }
        if (timeCost < 1) { throw new ArgumentOutOfRangeException(nameof(timeCost), timeCost, $"{nameof(timeCost)} must be greater than 0."); }
        if (parallelism < 1) { throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism, $"{nameof(parallelism)} must be greater than 0."); }
        if (delta < MinDelta) { throw new ArgumentOutOfRangeException(nameof(delta), delta, $"{nameof(delta)} must be greater than or equal to {MinDelta}."); }

        var outputs = new List<byte[]>();
        for (int i = 0; i < parallelism; i++) {
            outputs.Add(new byte[HashSize]);
        }
        int passwordLength = password.Length;
        int saltLength = salt.Length;
        fixed (byte* p = password, s = salt) {
            byte* pPtr = p, sPtr = s;
            Parallel.For(0, parallelism, i =>
            {
                var parallelSalt = new byte[saltLength + 8];
                new Span<byte>(sPtr, saltLength).CopyTo(parallelSalt);
                BinaryPrimitives.WriteUInt64LittleEndian(parallelSalt.AsSpan()[^8..], (ulong)i + 1);
                Balloon.ComputeHash(outputs[i], new Span<byte>(pPtr, passwordLength), parallelSalt, spaceCost, timeCost, delta);
            });
            foreach (var output in outputs) {
                for (int i = 0; i < hash.Length; i++) {
                    hash[i] ^= output[i];
                }
            }
            Hash(hash, password, salt);
        }
    }

    private static void Hash(Span<byte> hash, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha256.AppendData(password);
        sha256.AppendData(salt);
        sha256.AppendData(hash);
        sha256.GetCurrentHash(hash);
    }
}
