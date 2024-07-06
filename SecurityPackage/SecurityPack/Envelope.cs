using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SecurityPackage.SecurityPack;

public static class Envelope
{

       [DataContract]
       public class CryptoResponse
       {
              [DataMember(Name = "iv")] public string InitiatingVector { get; set; }
              public string SecretKey { get; set; }
              [DataMember(Name = "result")] public string Result { get; set; }

       }

       public static CryptoResponse Encrypt(string plainText, byte[]? key, byte[]? iv)
       {
              var response = new CryptoResponse();

              using var provider = new AesCryptoServiceProvider()
              {
                     Mode = CipherMode.CBC,
                     Padding = PaddingMode.PKCS7,
                     BlockSize = 128,
                     KeySize = 128
              };
              if (iv is null || iv.Length != 16)
              {
                     provider.GenerateIV();
              }
              else
                     provider.IV = iv;

              if (key is null || key.Length != 16)
              {
                     provider.GenerateKey();
              }
              else
                     provider.Key = key;

              response.InitiatingVector = ByteArrayToHexString(provider.IV);
              response.SecretKey = ByteArrayToHexString(provider.Key);

              using var encryptor = provider.CreateEncryptor();
              var toBeEncrypt = Encoding.UTF8.GetBytes(plainText);
              response.Result = encryptor.TransformFinalBlock(toBeEncrypt, 0, toBeEncrypt.Length)
              .ToHexString();
              return response;
       }

       public static string Decrypt(string encryptedHexString, byte[] key, byte[] initiatingVector)
       {
              if (key == null || key.Length == 0 || key.Length *8 != 128)
                     throw new ArgumentException(null, nameof(key));

              if (initiatingVector == null || initiatingVector.Length == 0 || initiatingVector.Length * 8 != 128)
                     throw new AggregateException(nameof(initiatingVector));

              using var alg = Aes.Create();

              using var decrypted = alg.CreateDecryptor(key, initiatingVector);
              using var msDecrypt = new MemoryStream(encryptedHexString.HexStringToByteArray());
              using var csDecrypt = new CryptoStream(msDecrypt, decrypted, CryptoStreamMode.Read);
              using var srDecrypt = new StreamReader(csDecrypt);
              return srDecrypt.ReadToEnd();
       }

    public static bool UnpackEnvelope(string envelope, out string aesKey, out long timestamp,
           string digitalEnvelopeRsaPrivateKey)
    {
        aesKey = null;
        timestamp = 0;
        var rsa = new RSACryptoServiceProvider();
        rsa.FromXml(digitalEnvelopeRsaPrivateKey);
        var decryptedData = rsa.Decrypt(envelope.HexStringToByteArray(), RSAEncryptionPadding.Pkcs1);
        if (decryptedData.Length != 26) return false;

        var dataSpan = decryptedData.AsSpan();

        aesKey = SpanToHexString(dataSpan[..16]);
        timestamp = long.Parse(SpanToHexString(dataSpan.Slice(16, 10)));
        //string temp = SpanToHexString(dataSpan.Slice(16, 10)); //00000001689677516871  //000000000189689EB7BD
        //timestamp = long.Parse(temp);

        return true;
    }

       public static string ToHexString(this byte[] buf) => ((IEnumerable<byte>) buf)
       .Select<byte, string>((Func<byte, string>) (t => t.ToString("X2")))
       .Aggregate<string>((Func<string, string, string>) ((a, b) => a + b));

       private static string ByteArrayToHexString(byte[] s)
       {
              if (s == null) throw new ArgumentNullException(nameof(s));
              var result = new string(c: '\0', count: s.Length * 2);
              var writable = MemoryMarshal.AsMemory(memory: result.AsMemory()).Span;
              var index = 0;
              foreach (var b in s)
              {
                     var hex = b.ToString(format: "X2");
                     writable[index: index++] = hex[index: 0];
                     writable[index: index++] = hex[index: 1];
              }

              return result;
       }

	private static byte[] HexStringToByteArray(string hexString)
              => Enumerable.Range(0, hexString.Length)
              .Where(x => x % 2 == 0)
              .Select(x => Convert.ToByte(value: hexString.Substring(startIndex: x, length: 2), fromBase: 16))
              .ToArray();

       private static void FromXml(this RSA rsa, string xmlString)
       {
              var parameters = new RSAParameters();

              var xmlDoc = new XmlDocument();
              xmlDoc.LoadXml(xmlString ?? throw new ArgumentNullException(nameof(xmlString)));

              if (xmlDoc.DocumentElement is {Name: "RSAKeyValue"})
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

       private static string SpanToHexString(Span<byte> s)
              => SpanToHexString(s: ref s);

       private static string SpanToHexString(ref Span<byte> s)
       {
              var result = new string(c: '\0', count: s.Length * 2);
              var writable = MemoryMarshal.AsMemory(memory: result.AsMemory()).Span;
              var index = 0;
              foreach (var b in s)
              {
                     var hex = b.ToString(format: "X2");
                     writable[index: index++] = hex[index: 0];
                     writable[index: index++] = hex[index: 1];
              }

              return result;
       }
	public static byte[] PackKeysAsEnvelopeData(string clientPublicRsaXmlKeyString, byte[] secretKey)
       {
              using var rsa = new RSACryptoServiceProvider();
              rsa.FromXmlString(clientPublicRsaXmlKeyString);
              var result = new byte[16 + 10];

              var timeStamp = HexStringToByteArray(Timestamp(DateTime.Now).ToString().PadLeft(20, '0'));
              Buffer.BlockCopy(secretKey, 0, result, 0, secretKey.Length);
              Buffer.BlockCopy(timeStamp, 0, result, result.Length - 10, timeStamp.Length);

              return rsa.Encrypt(result, RSAEncryptionPadding.Pkcs1);
       }

       private static readonly DateTime Epoch = new DateTime(year: 1970, month: 1, day: 1, hour: 0, minute: 0,
              second: 0, kind: DateTimeKind.Utc);
	private static long Timestamp(DateTime dateTime)
              => (long) (dateTime.ToUniversalTime() - Epoch).TotalMilliseconds;

}