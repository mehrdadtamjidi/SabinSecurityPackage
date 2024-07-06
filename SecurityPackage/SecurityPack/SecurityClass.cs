using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SecurityPackage.SecurityPack;

public static class SecurityClass
{

       public static string MakeSignature<T>(T obj, string privateKeyString, out string payloadAsJson)
       where T : class
       {
              using var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
              rsaCryptoServiceProvider.FromXml(privateKeyString);

              using var hashComputer = new SHA256CryptoServiceProvider();
              var standardStringHashBuffer =
                     hashComputer.ComputeHash(Encoding.UTF8.GetBytes(MakeStandardString(obj, out payloadAsJson)));

              return rsaCryptoServiceProvider
              .SignHash(standardStringHashBuffer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ToHesString();
       }

    public static string MakeSignatureWithPem<T>(T obj, string privateKeyString, out string payloadAsJson)
where T : class
    {
        using var rsaCryptoServiceProvider = new RSACryptoServiceProvider(1024);
        PemReader pr = new PemReader(new StringReader(privateKeyString));
        AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
        RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
        rsaCryptoServiceProvider.ImportParameters(rsaParams);

        using var hashComputer = new SHA256CryptoServiceProvider();
        var standardStringHashBuffer =
               hashComputer.ComputeHash(Encoding.UTF8.GetBytes(MakeStandardString(obj, out payloadAsJson)));

        var signatureBytes = rsaCryptoServiceProvider
        .SignHash(standardStringHashBuffer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Convert the signature to Base64
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        return signatureBase64;

    }

    public static bool CheckSignature(string request, string publicKey, string sign)
       {
           var canonicalBytes = Encoding.UTF8.GetBytes(request.TrimString());
           var verifier = new RSACryptoServiceProvider();
           verifier.FromXmlString(publicKey);
           return verifier.VerifyData(canonicalBytes, sign.HexStringToByteArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
       }

    public static bool CheckSignatureWithPem(string request, string publicKey, string sign)
    {
        var canonicalBytes = Encoding.UTF8.GetBytes(request.TrimString());

        PemReader pr = new PemReader(new StringReader(publicKey));
        AsymmetricKeyParameter publicKeyParam = (AsymmetricKeyParameter)pr.ReadObject();
        RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyParam);
        RSACryptoServiceProvider verifier = new RSACryptoServiceProvider(2048);
        verifier.ImportParameters(rsaParams);

        return verifier.VerifyData(canonicalBytes, sign.HexStringToByteArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static string TrimString(this string str)
           => str.Replace("\r\n", string.Empty)
           .Replace("\r", string.Empty)
           .Replace("\n", string.Empty)
           .Replace(Environment.NewLine, string.Empty)
           .Replace(" ", string.Empty)
           .Replace("\"", string.Empty)
           .Replace("'", string.Empty);

       private static void FromXml(this RSA rsa, string xmlString)
        {
            var parameters = new RSAParameters();

            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString ?? throw new ArgumentNullException(nameof(xmlString)));

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus":
                            parameters.Modulus = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "Exponent":
                            parameters.Exponent = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "P":
                            parameters.P = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "Q":
                            parameters.Q = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "DP":
                            parameters.DP = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "DQ":
                            parameters.DQ = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "InverseQ":
                            parameters.InverseQ = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                        case "D":
                            parameters.D = string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText);
                            break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }
       
       private static string MakeStandardString<T>(T obj, out string payloadAsJson) where T : class
             => (payloadAsJson = ToJsonString(obj))
             .Replace("\r\n", string.Empty)
             .Replace("\r", string.Empty)
             .Replace("\n", string.Empty)
             .Replace(Environment.NewLine, string.Empty)
             .Replace(" ", string.Empty)
             .Replace("\"", string.Empty)
             .Replace("'", string.Empty);
       public static byte[] HexStringToByteArray(this string hexString)
           => Enumerable.Range(0, hexString.Length)
           .Where(x => x % 2 == 0)
           .Select(x => Convert.ToByte(value: hexString.Substring(startIndex: x, length: 2), fromBase: 16))
           .ToArray();
         private static string ToJsonString<T>(T obj) where T : class
             => Encoding.UTF8.GetString(ToJsonBuffer(obj));
         private static byte[] ToJsonBuffer<T>(T obj) where T : class
         {
             var dataContractJsonSerializer = new DataContractJsonSerializer(typeof(T));
             using var mStream = new MemoryStream();
             dataContractJsonSerializer.WriteObject(mStream, obj);
             return mStream.ToArray();
         }
         private static string ToHesString(this byte[] buffer)
             => buffer.Select(t => t.ToString("X2")).Aggregate((i, j) => $"{i}{j}");

}