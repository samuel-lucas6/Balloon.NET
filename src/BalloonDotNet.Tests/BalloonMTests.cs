using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace BalloonDotNet.Tests;

[TestClass]
public class BalloonMTests
{
    // https://github.com/RustCrypto/password-hashes/blob/master/balloon-hash/tests/balloon_m.rs
    // https://github.com/nachonavarro/balloon-hashing/blob/master/test_vectors.py
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f",
            "hunter42",
            "examplesalt",
            1024,
            3,
            4
        ];
        yield return
        [
            "f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23",
            "",
            "salt",
            3,
            3,
            2
        ];
        yield return
        [
            "bcad257eff3d1090b50276514857e60db5d0ec484129013ef3c88f7d36e438d6",
            "password",
            "",
            3,
            3,
            3
        ];
        yield return
        [
            "498344ee9d31baf82cc93ebb3874fe0b76e164302c1cefa1b63a90a69afb9b4d",
            "password",
            "",
            3,
            3,
            1
        ];
        yield return
        [
            "8a665611e40710ba1fd78c181549c750f17c12e423c11930ce997f04c7153e0c",
            "\0",
            "\0",
            3,
            3,
            4
        ];
        yield return
        [
            "d9e33c683451b21fb3720afbd78bf12518c1d4401fa39f054b052a145c968bb1",
            "\0",
            "\0",
            3,
            3,
            1
        ];
        yield return
        [
            "a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915",
            "password",
            "salt",
            1,
            1,
            16
        ];
        yield return
        [
            "97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d",
            "password",
            "salt",
            1,
            1,
            1
        ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeHash_Valid(string hash, string password, string salt, int spaceCost, int timeCost, int parallelism)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> p = Encoding.UTF8.GetBytes(password);
        Span<byte> s = Encoding.UTF8.GetBytes(salt);

        BalloonM.ComputeHash(h, p, s, spaceCost, timeCost, parallelism);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DataRow(BalloonM.HashSize + 1, 20, BalloonM.SaltSize, 1, 1, 1, BalloonM.MinDelta)]
    [DataRow(BalloonM.HashSize - 1, 20, BalloonM.SaltSize, 1, 1, 1, BalloonM.MinDelta)]
    [DataRow(BalloonM.HashSize, 20, BalloonM.SaltSize, 0, 1, 1, BalloonM.MinDelta)]
    [DataRow(BalloonM.HashSize, 20, BalloonM.SaltSize, 1, 0, 1, BalloonM.MinDelta)]
    [DataRow(BalloonM.HashSize, 20, BalloonM.SaltSize, 1, 1, 0, BalloonM.MinDelta)]
    [DataRow(BalloonM.HashSize, 20, BalloonM.SaltSize, 1, 1, 1, BalloonM.MinDelta - 1)]
    public void ComputeHash_Invalid(int hashSize, int passwordSize, int saltSize, int spaceCost, int timeCost, int parallelism, int delta)
    {
        var h = new byte[hashSize];
        var p = new byte[passwordSize];
        var s = new byte[saltSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => BalloonM.ComputeHash(h, p, s, spaceCost, timeCost, parallelism, delta));
    }
}
