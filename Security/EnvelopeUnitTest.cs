using SecurityPackage.SecurityPack;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;


namespace Security
{
    public class EnvelopeUnitTest
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void EnvelopeTest()
        {

            const string privateKey =
            "<RSAKeyValue><Modulus>xlDMmSkUMjmE3H/rtMzDa4gNEb1YtAKw61JSIMx/9/4HvXFqkK80Va1ItJAEeAu6B1gd+qdyu6hmMTrhUG0//RKymgTw43b7Al5d2rh5Cp73RaCf1Cs7lzbCyu45xcg9pbZYLx5pJDAs8YV0lf6bOCxs+hoIpOAec791OvSLcvQOBBA80GzheL/VvgrZVKQzNNy11KRA+9l3nOi/k+cHhmjziQiMM/7fGK/1lHwU6ukeAcaErsehtKeGgV9+KXqh425mT8+QOqygyWcE5ye0nTCZv8B8vCkOz288zvn9iZvOsUZrAD9UXZ/WPUXx2D18lgcYna1iINuP4R07jEgIyQ==</Modulus><Exponent>AQAB</Exponent><P>6xpiB0kDWyD2uOb9TTXO4lYjzA7krzdowVZhy4CGEcy/bB80BOaB2SHRJnBv/1eTiHooSuELzYCKsDhap809bmKK/O1m1KEjsOmnOfv9Ou/SPw19S/ODJgvM+CC7E/sMSTdZiYitbyQfOOsdy9E1X+QtN1gzzRR/BXFTPABHfDM=</P><Q>1/FXlPMvUCfIzoCXcsBi8ZHPNisktdVEO2Owa9a02Sz+/9CXyrq5SiY1t7y/6uEX62TaRBsv2WBTmn6dG6/2o4X4nBBNFree/HITONig7bZBe+pK7vFMKdDEgjplcwyt5cWJSmvA6/N8sBlMZ/a0NiJf/FQKPNdt/HDFw6Et6xM=</Q><DP>YS83xJEu/PWkZ4y8urT6f19iTtD9QVzjRcCCjo/jW+pKWtSPOVNb67jp7zzdXy0BhJISo9lheqKfMfcpqmHR+hZsI9+y+URfL5t2kCaVaE6Il53o5IOV/B02rn9BNiI50u45afwAzYeeDHZMi9tAeBInitBAIY9Obp6I7K2k3zc=</DP><DQ>KVQwffp5IK8smJE16yl1BmTwsp5ZPU/e6jrvJgSGwlYBS/ahRpSsJ8veVhcS6CJCkLPRrl1BsCnmdlgrO4RXAP8AEOZxyppEHG68zRFw424RZGT4CHk4KXyiT4ZbqkRP9/zxhMPQvZfxUkbVP8SQwxebJVD0UKaujzUKNKHhhu8=</DQ><InverseQ>WPVHzdbC1NbD/J/tEyUNLSJS2110v7nDGZuNyMGFBCqJpGxsObFHIXPalHJHTJ4T9MEgvw/+06YomG2JMcS0Rp6s4IxG9pYlka6C8wjjlOTfgnfFSWt9cEZbSPcb8oyvy2v5UQocz2oUxwxrMghdYyA5xkz3Mkzjx0Na1P8VKSw=</InverseQ><D>FPnu6jRiIn3bA8e0Esel0/XsC/hPLZsrQ3jNnxKCZqTEBNG+R9eAXZ+alR62mkwDPUugwCZ+CENjq8lik7M6lXYo1gm3wReQrUt1+fCRPQJbfU3kGfkIsJHmQLi5+6WWf7St1y4MSPufhVxsXIE1wddRH5MpXucl0XBq4fWD2oCuVV40VfliSel+X77WKBtI4UXG7Y97u+ykguHWPzSlQGu5NAgsmgmCECwSgaaYzYmgOVUo493Shhw+6sXWBOrhx9SWKx0pb4vjZ7JdMQDDgTvYhKZJsJGZlO7H5qEV298VmWr/SwyrkTBRIzZ7ABcfyAVIphD074RcGKFGBSyKUQ==</D></RSAKeyValue>";
            const string publicKey =
            "<RSAKeyValue><Modulus>xlDMmSkUMjmE3H/rtMzDa4gNEb1YtAKw61JSIMx/9/4HvXFqkK80Va1ItJAEeAu6B1gd+qdyu6hmMTrhUG0//RKymgTw43b7Al5d2rh5Cp73RaCf1Cs7lzbCyu45xcg9pbZYLx5pJDAs8YV0lf6bOCxs+hoIpOAec791OvSLcvQOBBA80GzheL/VvgrZVKQzNNy11KRA+9l3nOi/k+cHhmjziQiMM/7fGK/1lHwU6ukeAcaErsehtKeGgV9+KXqh425mT8+QOqygyWcE5ye0nTCZv8B8vCkOz288zvn9iZvOsUZrAD9UXZ/WPUXx2D18lgcYna1iINuP4R07jEgIyQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            //**create envelope**//
            const string sampleData = "920125000045601";

            //encrypt Plain Text
            var encryptData = Envelope.Encrypt(sampleData, null, null);
            //create envelope
            var envelope = Envelope.PackKeysAsEnvelopeData(publicKey, encryptData.SecretKey.HexStringToByteArray())
            .Select(t => t.ToString("X2")).Aggregate((a, b) => $"{a}{b}");
            //secret key
            var envelopeIv = encryptData.InitiatingVector;
            //encrypted data
            var encryptedData = encryptData.Result;


            //**decrypt data**//

            //unpackEnvelope
            Envelope.UnpackEnvelope(envelope, out var aesKey, out var timestamp, privateKey);

            //check time
            var calculateTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var nextTime = calculateTime + 180000;
            var beforeTime = calculateTime - 180000;

            if (timestamp > beforeTime && timestamp < nextTime)
            {
                var finalDecryptedResult = Envelope.Decrypt(encryptedData, aesKey.HexStringToByteArray(),
                       envelopeIv.HexStringToByteArray());
            }

            Assert.Pass();
        }
    }
}