using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace BalloonDotNet.Tests;

[TestClass]
public class BalloonTests
{
    // https://github.com/RustCrypto/password-hashes/blob/master/balloon-hash/tests/balloon.rs
    // https://github.com/nachonavarro/balloon-hashing/blob/master/test_vectors.py
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb",
            "hunter42",
            "examplesalt",
            1024,
            3
        };
        yield return new object[]
        {
            "5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378",
            "",
            "salt",
            3,
            3
        };
        yield return new object[]
        {
            "20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc",
            "password",
            "",
            3,
            3
        };
        yield return new object[]
        {
            "4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4",
            "\0",
            "\0",
            3,
            3
        };
        yield return new object[]
        {
            "eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545",
            "password",
            "salt",
            1,
            1
        };
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string outputKeyingMaterial, string password, string salt, int spaceCost, int timeCost)
    {
        Span<byte> o = stackalloc byte[outputKeyingMaterial.Length / 2];
        Span<byte> p = Encoding.UTF8.GetBytes(password);
        Span<byte> s = Encoding.UTF8.GetBytes(salt);

        Balloon.DeriveKey(o, p, s, spaceCost, timeCost);

        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(o).ToLower());
    }

    [TestMethod]
    [DataRow(Balloon.HashSize + 1, 20, 16, 1, 1, 3)]
    [DataRow(Balloon.HashSize - 1, 20, 16, 1, 1, 3)]
    [DataRow(Balloon.HashSize, 20, 16, 0, 1, 3)]
    [DataRow(Balloon.HashSize, 20, 16, 1, 0, 3)]
    [DataRow(Balloon.HashSize, 20, 16, 1, 1, 2)]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int passwordSize, int saltSize, int spaceCost, int timeCost, int delta)
    {
        var o = new byte[outputKeyingMaterialSize];
        var p = new byte[passwordSize];
        var s = new byte[saltSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Balloon.DeriveKey(o, p, s, spaceCost, timeCost, delta));
    }
}
