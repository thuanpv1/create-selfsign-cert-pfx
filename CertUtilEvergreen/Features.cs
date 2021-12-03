using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertUtilEvergreen
{
    public class Features
    {
        public static byte[] CreatePfxWay4FromPrivateKey(string privateKeyPath, string outputFileNameIfWritten = "clientCert.pfx", bool isWrittenOutputToFile = false, string soCMND = "soCMND", string hoVaTen = "Nguyen Van A", string diaChi = "Hanoi")
        {
            string privateKeyStr = File.ReadAllText(privateKeyPath);
            AsymmetricKeyParameter privateKey = ReadPublicKey(privateKeyStr);
            var clientCert = CreateCertWay1.GenerateSelfSignedCertificate("CN=" + hoVaTen + "|" + soCMND + ",L=" + diaChi + ",OU=iGreens,O=iGreens,C=VN", "CN=iGreens,L=Hanoi,OU=iGreens,O=iGreens,C=VN", privateKey, 20);
            var p12 = clientCert.Export(X509ContentType.Pfx, "12345678");
            if (isWrittenOutputToFile) ByteArrayToFile(outputFileNameIfWritten, p12);

            return p12;
        }
        public static bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            try
            {
                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(byteArray, 0, byteArray.Length);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }

        public static Org.BouncyCastle.Crypto.AsymmetricKeyParameter ReadPublicKey(string publicKey)
        {
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter keyParameter = null;

            using (System.IO.TextReader reader = new System.IO.StringReader(publicKey))
            {
                Org.BouncyCastle.OpenSsl.PemReader pemReader =
                    new Org.BouncyCastle.OpenSsl.PemReader(reader);

                object obj = pemReader.ReadObject();

                if ((obj is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair))
                    throw new System.ArgumentException("The given publicKey is actually a private key.", "publicKey");

                if (!(obj is Org.BouncyCastle.Crypto.AsymmetricKeyParameter))
                    throw new System.ArgumentException("The given publicKey is not a valid assymetric key.", "publicKey");

                keyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)obj;
            }

            return keyParameter;
        } // End Function ReadPublicKey 
    }
}
