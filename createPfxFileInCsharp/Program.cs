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
            Console.WriteLine("Hello World!");
            X509Certificate2 certtemp = GenerateCertificate("Pham Van Thuan");
            byte[] data = certtemp.Export(X509ContentType.Pfx, "12345678");
            ByteArrayToFile("thuanpv.pfx", data);

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

        static X509Certificate2 GenerateCertificate(string certName)
        {
            var keypairgen = new RsaKeyPairGenerator();
            keypairgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048));

            var keypair = keypairgen.GenerateKeyPair();

            var gen = new X509V3CertificateGenerator();

            var CN = new X509Name("CN=" + certName);
            var IDN = new X509Name("CN=iGreens Company");
            var SN = BigInteger.ProbablePrime(120, new Random());

            gen.SetSerialNumber(SN);
            gen.SetSubjectDN(CN);
            gen.SetIssuerDN(IDN);
            gen.SetNotAfter(DateTime.Now.AddYears(30));
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(0, 0, 0, 0)));
            gen.SetSignatureAlgorithm("SHA256WithRSA");
            gen.SetPublicKey(keypair.Public);

            var newCert = gen.Generate(keypair.Private);

            return new X509Certificate2(DotNetUtilities.ToX509Certificate(newCert));
        }

        static bool ByteArrayToFile(string fileName, byte[] byteArray)
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
    }
}
