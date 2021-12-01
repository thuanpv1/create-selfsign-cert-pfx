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

            CreateCAAndClientCertWay1("test1.cer", "test1.pfx", subjectNameCA: "CN=Evergreen,L=Hanoi,OU=Evergreen,O=Evergreen,C=VN", subjectNameClient: "CN=Pham Van Thuan,L=Hanoi,OU=Evergreen,O=Evergreen,C=VN", IssuerName: "CN=Evergreen,O=Evergreen,C=VN");

            // Test for way2

            // Test for way3
            CreatePfxWay3();


        }

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
        public static void CreateCAAndClientCertWay1(string fileNameCer, string fileNamePfx, string subjectNameCA="CN=EvergreenCA", string subjectNameClient="CN=person1", string IssuerName = "CN=EvergreenCA", string passwordForPFX = "12345678", bool isStoreToCertStore = false)
        {
            AsymmetricKeyParameter caPrivateKey = null;
            var caCert = CreateCertWay1.GenerateCACertificate(subjectNameCA, ref caPrivateKey, 20);
            var clientCert = CreateCertWay1.GenerateSelfSignedCertificate(subjectNameClient, subjectNameCA, caPrivateKey, 20);
            var p12 = clientCert.Export(X509ContentType.Pfx, passwordForPFX);

            CreateCertWay2.ByteArrayToFile(fileNameCer, caCert.RawData);
            CreateCertWay2.ByteArrayToFile(fileNamePfx, p12);

            if (isStoreToCertStore) CreateCertWay1.addCertToStore(caCert, StoreName.Root, StoreLocation.CurrentUser);
            if (isStoreToCertStore) CreateCertWay1.addCertToStore(new X509Certificate2(p12, (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet), StoreName.My, StoreLocation.CurrentUser);
        }

    }
}
