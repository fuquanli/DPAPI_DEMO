using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace ConsoleApp1
{
    public class TestXmlCrypt
    {
        enum PrintTypes
        {
            PrintOriginal,
            PrintEncrypt,
            PrintDecrypt
        }
        public static void UseDemo()
        {
            Console.WriteLine("Test Xml Crypt begin...");
            Console.WriteLine("Input file path: (You can drag a file into console without input file path)");
            String filePath = Console.ReadLine();
            if (File.Exists(filePath))
            {
                PrintXml(filePath, PrintTypes.PrintOriginal);
                Console.WriteLine("Select Symmetric/Asymmetric(RSA) Algorithm, 0: Symmetric, 1: Asymmetric (Default is Symmetric)");
                String alg = Console.ReadLine();
                int nAlg = alg.Equals("1") ? 1 : 0;
                switch (nAlg)
                {
                    case 0:
                        TestSymmetricAlgorithm(filePath);
                        break;
                    case 1:
                        TestAsymmetricAlgorithm(filePath);
                        break;
                    default:
                        break;
                }
            }
            Console.WriteLine("Test Xml Crypt end...");
        }
        private static void TestSymmetricAlgorithm(String filePath)
        {
            Console.WriteLine("Select the encrypt/decrypt algorithm: (Default is DES)");
            GTXXmlCrypt.SymmetricAlgTypes salTypeTemp = GTXXmlCrypt.SymmetricAlgTypes.DES;
            for (; salTypeTemp <= GTXXmlCrypt.SymmetricAlgTypes.TripleDES; ++salTypeTemp)
            {
                Console.WriteLine("{0} is {1}", (int)salTypeTemp, salTypeTemp.ToString());
            }
            // Read the symmetric algorithm command
            String algString = Console.ReadLine();
            GTXXmlCrypt.SymmetricAlgTypes salType = GTXXmlCrypt.SymmetricAlgTypes.DES;
            try
            {
                salType = (GTXXmlCrypt.SymmetricAlgTypes)Convert.ToInt32(algString);
                if (salType <= GTXXmlCrypt.SymmetricAlgTypes.DES &&
                    salType >= GTXXmlCrypt.SymmetricAlgTypes.TripleDES)
                {
                    salType = GTXXmlCrypt.SymmetricAlgTypes.DES;
                }
            }
            catch (System.Exception ex)
            {
                salType = GTXXmlCrypt.SymmetricAlgTypes.DES;
            }
            // Read the node which we want to encrypt/decrypt
            Console.WriteLine("Input the XML element node:");
            String elementName = Console.ReadLine();
            Console.WriteLine("Encrypt node element or its content, 0: Element, 1: Only content (Default is Element)");
            String content = Console.ReadLine();
            bool bContent = content.Equals("1") ? true : false;
            SymmetricAlgorithm sal = GTXXmlCrypt.CreateSymmetricAlgorithm(salType);
            if (GTXXmlCrypt.EncryptXmlFile(filePath, elementName, bContent, sal, "abc"))
            {
                // Print the encrypted XML to console
                Console.WriteLine("Encrypt XML with {0} algorithm Succeed!", salType);
                PrintXml(filePath, PrintTypes.PrintEncrypt);
                if (GTXXmlCrypt.DecryptXmlFile(filePath, sal, /*"abc"*/""))
                {
                    // Print the decrypted XML to console
                    Console.WriteLine("Decrypt XML with {0} algorithm Succeed!", salType);
                    PrintXml(filePath, PrintTypes.PrintDecrypt);
                }
                else
                {
                    Console.WriteLine("Decrypt with {0} algorithm Failed!", salType);
                }
            }
            else
            {
                Console.WriteLine("Encrypt with {0} algorithm Failed!", salType);
            }
        }
        private static void TestAsymmetricAlgorithm(String filePath)
        {
            String keyContainerName = "rsakey container";
            RSA rsaKey = GTXXmlCrypt.CreateRSAAlgorithm(keyContainerName);
            try
            {
                // Read the node which we want to encrypt/decrypt
                Console.WriteLine("Input the XML element node:");
                String elementName = Console.ReadLine();
                Console.WriteLine("Encrypt node element or its content, 0: Element, 1: Only content (Default is Element)");
                String content = Console.ReadLine();
                bool bContent = content.Equals("1") ? true : false;
                if (GTXXmlCrypt.EncryptXmlFile(filePath, elementName, bContent, rsaKey, ""/*"rsakey"*/))
                {
                    // Print the encrypted XML to console
                    Console.WriteLine("Encrypt XML with RSA algorithm Succeed!");
                    PrintXml(filePath, PrintTypes.PrintEncrypt);
                    if (GTXXmlCrypt.DecryptXmlFile(filePath, rsaKey, ""/*"rsakey"*/))
                    {
                        PrintXml(filePath, PrintTypes.PrintDecrypt);
                        Console.WriteLine("Decrypt XML with RSA algorithm Succeed!");
                    }
                    else
                    {
                        Console.WriteLine("Decrypt XML with RSA algorithm Failed!");
                    }
                }
                else
                {
                    Console.WriteLine("Encrypt xml with RSA algorithm Failed!");
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                rsaKey.Clear();
            }
        }
        static void PrintXml(String filePath, PrintTypes printType)
        {
            String format = String.Empty;
            switch (printType)
            {
                case PrintTypes.PrintOriginal:
                    format = "■ Original file:/n{0}";
                    break;
                case PrintTypes.PrintEncrypt:
                    format = "■ Encryptd file:/n{0}";
                    break;
                case PrintTypes.PrintDecrypt:
                    format = "■ Decrypted file:/n{0}";
                    break;
            }
            XmlDocument doc = new XmlDocument();
            //doc.PreserveWhitespace = true;
            doc.Load(filePath);
            XmlWriterSettings xmlSetting = new XmlWriterSettings();
            xmlSetting.Indent = true;
            xmlSetting.IndentChars = "/t";
            xmlSetting.Encoding = Encoding.UTF8;

            MemoryStream stream = new MemoryStream();
            XmlWriter writer = XmlWriter.Create(stream, xmlSetting);

            doc.Save(writer);
            doc.Save(filePath);
            // Reload the file and update the doc.InnerXml property.
            doc.PreserveWhitespace = true;
            doc.Load(filePath);

            Console.WriteLine(format, doc.InnerXml);
        }
    }
}
