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

            AsymmetricKeyParameter caPrivateKey = null;
            var caCert = CreateCertWay1.GenerateCACertificate("CN=MyROOTCA", ref caPrivateKey);
            CreateCertWay1.addCertToStore(caCert, StoreName.Root, StoreLocation.CurrentUser);

            var clientCert = CreateCertWay1.GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=MyROOTCA", caPrivateKey);

            var p12 = clientCert.Export(X509ContentType.Pfx);

            CreateCertWay1.addCertToStore(new X509Certificate2(p12, (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet), StoreName.My, StoreLocation.CurrentUser);


            // Test for way2

            return;
            Console.WriteLine("Hello World!");
            X509Certificate2 certtemp = CreateCertWay2.GenerateCertificate("Pham Van Thuan");
            byte[] data = certtemp.Export(X509ContentType.Pfx, "12345678");
            CreateCertWay2.ByteArrayToFile("thuanpv.pfx", data);

            string certPath = "test.pfx";
            string certPass = "11111111";

            // Create a collection object and populate it using the PFX file
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(certPath, certPass, X509KeyStorageFlags.PersistKeySet);

            foreach (X509Certificate2 cert in collection)
            {
                Console.WriteLine("Subject is: '{0}'", cert.Subject);
                Console.WriteLine("Issuer is:  '{0}'", cert.Issuer);

                // Import the certificate into an X509Store object
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                if (!store.Certificates.Contains(cert))
                {
                    store.Add(cert);
                }
                store.Close();
            }

        }

    }
}
