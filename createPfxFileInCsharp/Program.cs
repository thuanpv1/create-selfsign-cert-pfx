using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace createPfxFileInCsharp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test for way1

            //CreateCAAndClientCertWay1("iGreensCACertificate.cer", "iGreenClientCertificate.pfx", privateKeyPemFilePath: "iGreens_CA_PrivateKey_For_CreateOtherClientPFX.pem", subjectNameCA: "CN=iGreens,L=Hanoi,OU=iGreens,O=iGreens,C=VN", subjectNameClient: "CN=Tran Van Thiem,L=Hanoi,OU=iGreens,O=iGreens,C=VN");

            // Test for way2

            // Test for way3
            //CreatePfxWay3();

            // Test for way4
            CreatePfxWay4FromPrivateKey("iGreens_CA_PrivateKey_For_CreateOtherClientPFX.pem", outputFileNameIfWritten: "test.pfx", isWrittenOutputToFile: true);
        }


        public static byte[] CreatePfxWay4FromPrivateKey(string privateKeyPath, string outputFileNameIfWritten = "clientCert.pfx", bool isWrittenOutputToFile = false, string soCMND="soCMND", string hoVaTen="Nguyen Van A", string diaChi = "Hanoi")
        {
            string privateKeyStr = File.ReadAllText(privateKeyPath);
            AsymmetricKeyParameter privateKey = ReadPublicKey(privateKeyStr);
            var clientCert = CreateCertWay1.GenerateSelfSignedCertificate("CN=" + hoVaTen + "|" + soCMND + ",L=" + diaChi + ",OU=iGreens,O=iGreens,C=VN", "CN=iGreens,L=Hanoi,OU=iGreens,O=iGreens,C=VN", privateKey, 20);
            var p12 = clientCert.Export(X509ContentType.Pfx, "12345678");
            if (isWrittenOutputToFile) CreateCertWay2.ByteArrayToFile(outputFileNameIfWritten, p12);

            return p12;
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
        public static Org.BouncyCastle.Crypto.AsymmetricKeyParameter ReadPrivateKey(string privateKey)
        {
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = null;

            using (System.IO.TextReader reader = new System.IO.StringReader(privateKey))
            {
                Org.BouncyCastle.OpenSsl.PemReader pemReader =
                    new Org.BouncyCastle.OpenSsl.PemReader(reader);

                object obj = pemReader.ReadObject();

                if (obj is Org.BouncyCastle.Crypto.AsymmetricKeyParameter)
                    throw new System.ArgumentException("The given privateKey is a public key, not a privateKey...", "privateKey");

                if (!(obj is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair))
                    throw new System.ArgumentException("The given privateKey is not a valid assymetric key.", "privateKey");

                keyPair = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)obj;
            } // End using reader 

            // Org.BouncyCastle.Crypto.AsymmetricKeyParameter priv = keyPair.Private;
            // Org.BouncyCastle.Crypto.AsymmetricKeyParameter pub = keyPair.Public;

            // Note: 
            // cipher.Init(false, key);
            // !!!

            return keyPair.Private;
        } // End Function ReadPrivateKey


        public static void CreatePfxWay3()
        {
            byte[] newPfxData = CreateCertWay3.GeneratePFXFile("Evergreen", "Evergreen", "evergreen@egt.vn", "Ha Noi", "Ha Noi", "Nguyen Van A", "VN").Export(X509ContentType.Pfx, "12345678");
            CreateCertWay2.ByteArrayToFile("way3.pfx", newPfxData);
        }

        public static void CreatePfxFileWay2()
        {
            X509Certificate2 certtemp = CreateCertWay2.GenerateCertificate("Pham Van Thuan");
            byte[] data = certtemp.Export(X509ContentType.Pfx, "12345678");
            CreateCertWay2.ByteArrayToFile("thuanpv.pfx", data);
        }
        public static void CreateCAAndClientCertWay1(string fileNameCer, string fileNamePfx, string privateKeyPemFilePath, string subjectNameCA="CN=EvergreenCA", string subjectNameClient="CN=person1", string passwordForPFX = "12345678", bool isStoreToCertStore = false)
        {
            AsymmetricKeyParameter caPrivateKey = null;
            var caCert = CreateCertWay1.GenerateCACertificate(subjectNameCA, ref caPrivateKey, 20, privateKeyPemFilePath: privateKeyPemFilePath);
            var clientCert = CreateCertWay1.GenerateSelfSignedCertificate(subjectNameClient, subjectNameCA, caPrivateKey, 20);
            var p12 = clientCert.Export(X509ContentType.Pfx, passwordForPFX);

            CreateCertWay2.ByteArrayToFile(fileNameCer, caCert.RawData);
            CreateCertWay2.ByteArrayToFile(fileNamePfx, p12);

            if (isStoreToCertStore) CreateCertWay1.addCertToStore(caCert, StoreName.Root, StoreLocation.CurrentUser);
            if (isStoreToCertStore) CreateCertWay1.addCertToStore(new X509Certificate2(p12, (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet), StoreName.My, StoreLocation.CurrentUser);
        }

    }
}
