using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace RSAcryptography
{

    public class RsaEnc
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RsaEnc()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }
        public string PublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();

        }
        public string Encrypt(string plainText)
        {
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);

            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);

            return Convert.ToBase64String(cypher);

        }
        public string Decrypt(string cypherText)
        {
            var dataBytes = Convert.FromBase64String(cypherText);
            csp.ImportParameters(_privateKey);

            var plainText = csp.Decrypt(dataBytes, false);

            return Encoding.Unicode.GetString(plainText);
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            RsaEnc rs = new RsaEnc();
            string cypher = String.Empty;
            Console.WriteLine($"PublicKey: \n { rs.PublicKeyString()}\n");

            Console.WriteLine("Ingresa tu texto para encryptar");
            var text = Console.ReadLine();
            if (text != String.Empty)
            {
                cypher = rs.Encrypt(text);
                Console.WriteLine($"Texto cifrado:\n {cypher}\n");
            }
            Console.WriteLine("Presione una tecla para desencrytar");
            Console.ReadLine();
            var plainText = rs.Decrypt(cypher);
            Console.WriteLine("Desencryptando texto... \n");
            Console.WriteLine(plainText);
            Console.ReadLine();
        }
    }
}

