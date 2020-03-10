using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Principal;
using System.Xml;
namespace ConsoleApp1
{
    public class GTXXmlCrypt
    {
        public enum SymmetricAlgTypes
        {
            DES = 1,
            AES128, // Rijndael 128
            AES192, // Rijndael 192
            AES256, // Rijndael 256
            TripleDES,
        }

        public static SymmetricAlgorithm CreateSymmetricAlgorithm(SymmetricAlgTypes salType)
        {
            SymmetricAlgorithm symAlg = null;
            switch (salType)
            {
                case SymmetricAlgTypes.DES:
                    symAlg = SymmetricAlgorithm.Create("DES");
                    break;
                case SymmetricAlgTypes.AES128:
                    symAlg = SymmetricAlgorithm.Create("Rijndael");
                    symAlg.KeySize = 128;
                    break;
                case SymmetricAlgTypes.AES192:
                    symAlg = SymmetricAlgorithm.Create("Rijndael");
                    symAlg.KeySize = 192;
                    break;
                case SymmetricAlgTypes.AES256:
                    symAlg = SymmetricAlgorithm.Create("Rijndael");
                    symAlg.KeySize = 256;
                    break;
                case SymmetricAlgTypes.TripleDES:
                    symAlg = SymmetricAlgorithm.Create("TripleDES");
                    break;
                default:
                    break;
            }
            return symAlg;
        }

        public static RSA CreateRSAAlgorithm(String containerName)
        {
            RSACryptoServiceProvider rsaKey = null;
            try
            {
                // Create a new CspParameters object to specify a key container.
                CspParameters cspParams = new CspParameters();
                cspParams.KeyContainerName = containerName;
                cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
                // Add the key's access privilege
                CryptoKeySecurity keySecurity = new CryptoKeySecurity();
                SecurityIdentifier si = new SecurityIdentifier(WellKnownSidType.LocalSid/*WorldSid*/, null);
                keySecurity.AddAccessRule(new CryptoKeyAccessRule(si, CryptoKeyRights.FullControl, AccessControlType.Allow));
                cspParams.CryptoKeySecurity = keySecurity;
                // Create a new RSA key and save it in the container. This key will encrypt
                // a symmetric key, which will then be encrypted in the XML document.
                rsaKey = new RSACryptoServiceProvider(cspParams);
            }
            catch (System.Exception ex)
            {
            }
            return rsaKey;
        }

        public static bool EncryptXmlFile(
            String filePath,
            String elementName,
            bool bContent,
            object key,
            String keyName)
        {
            if (File.Exists(filePath) && Path.GetExtension(filePath).ToLower().Equals(".xml") &&
                null != elementName && !elementName.Equals(String.Empty) &&
                null != key)
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(filePath);
                if (EncryptXmlDoc(xmlDoc, elementName, bContent, key, keyName))
                {
                    xmlDoc.Save(filePath);
                    return true;
                }
                return false;
            }
            return false;
        }

        public static bool EncryptXmlDoc(
            XmlDocument xmlDoc,
            String elementName,
            bool bContent,
            object key,
            String keyName)
        {
            SymmetricAlgorithm salgKey = null;
            RSA rsaKey = null;
            SymmetricAlgorithm sessionKey = null;

            if (key is SymmetricAlgorithm)
            {
                salgKey = key as SymmetricAlgorithm;
            }
            else if (key is RSA)
            {
                rsaKey = key as RSA;
                sessionKey = CreateSymmetricAlgorithm(SymmetricAlgTypes.DES/*AES256*/);
            }
            else
            {
                return false;
            }
            try
            {
                XmlNodeList nodeList = xmlDoc.GetElementsByTagName(elementName);
                int nCount = nodeList.Count;
                if (0 == nCount)
                {
                    return false;
                }
                for (int ix = 0; ix < nCount; ++ix)
                {
                    XmlElement elementToEncrypt = bContent ? (nodeList[ix] as XmlElement) : (nodeList[0] as XmlElement);
                    if (null != salgKey)
                    {
                        if (!EncryptXmlNode(elementToEncrypt, bContent, salgKey, keyName))
                        {
                            return false;
                        }
                    }
                    else if (null != rsaKey)
                    {
                        if (!EncryptXmlNode(elementToEncrypt, bContent, rsaKey, keyName, sessionKey))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }
            catch (System.Exception ex)
            {
            }
            finally
            {
                // Clear session key.
                if (null != sessionKey)
                {
                    sessionKey.Clear();
                }
            }
            return false;
        }

      
        public static bool EncryptXmlNode(
            XmlElement elementToEncrypt,
            bool bContent,
            SymmetricAlgorithm salgKey,
            String keyName)
        {
            if (null == elementToEncrypt || null == salgKey)
            {
                return false;
            }
            try
            {
                
                EncryptedXml eXml = new EncryptedXml();
                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, salgKey, bContent);
               
                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;
             
                edElement.EncryptionMethod = CreateEncryptionMethod(salgKey, false, false);
             
                if (null != keyName && !keyName.Equals(String.Empty))
                {
                 
                    edElement.KeyInfo = new KeyInfo();
                 
                    KeyInfoName kin = new KeyInfoName();
    
                    kin.Value = keyName;
              
                    edElement.KeyInfo.AddClause(kin);
                }
          
                edElement.CipherData.CipherValue = encryptedElement;
     
                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, bContent);
                return true;
            }
            catch (System.Exception ex)
            {
            }
            return false;
        }

        
        public static bool EncryptXmlNode(
            XmlElement elementToEncrypt,
            bool bContent,
            RSA rsaKey,
            String keyName,
            SymmetricAlgorithm sessionKey)
        {
            if (null == elementToEncrypt || null == rsaKey)
            {
                return false;
            }
            try
            {
              
                EncryptedXml eXml = new EncryptedXml();
                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, bContent);
               
                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;
              
                edElement.EncryptionMethod = CreateEncryptionMethod(sessionKey, false, false);

                EncryptedKey ek = new EncryptedKey();
                byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, rsaKey, false);
                ek.CipherData = new CipherData(encryptedKey);
                ek.EncryptionMethod = CreateEncryptionMethod(rsaKey, false, false);
               
                if (null != keyName && !keyName.Equals(String.Empty))
                {
  
                    edElement.KeyInfo = new KeyInfo();
                
                    KeyInfoName kin = new KeyInfoName();
           
                    kin.Value = keyName;
                   
                    ek.KeyInfo.AddClause(kin);
                }
  
                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));
               
                edElement.CipherData.CipherValue = encryptedElement;

                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, bContent);
                return true;
            }
            catch (System.Exception ex)
            {
            }
            return false;
        }

        public static bool DecryptXmlFile(String filePath, object key, String keyName)
        {
            if (File.Exists(filePath) && Path.GetExtension(filePath).ToLower().Equals(".xml") &&
                null != key)
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(filePath);
                if (DecryptXmlDoc(xmlDoc, key, keyName))
                {
                    xmlDoc.Save(filePath);
                    return true;
                }
                return false;
            }
            return false;
        }

        
        public static bool DecryptXmlDoc(XmlDocument xmlDoc, object key, String keyName)
        {
            try
            {
                if (null != keyName && !keyName.Equals(String.Empty))
                {
                    
                    EncryptedXml exml = new EncryptedXml(xmlDoc);
                 
                    exml.AddKeyNameMapping(keyName, key);
                    
                    exml.DecryptDocument();
                    return true;
                }
                else
                {
                    SymmetricAlgorithm salgKey = null;
                    RSA rsaKey = null;
                    if (key is SymmetricAlgorithm)
                    {
                        salgKey = key as SymmetricAlgorithm;
                    }
                    else if (key is RSA)
                    {
                        rsaKey = key as RSA;
                        salgKey = DecryptKey(xmlDoc, key);
                    }
                    else
                    {
                        return false;
                    }
                    XmlNodeList nodeList = xmlDoc.GetElementsByTagName("EncryptedData");
                    int nCount = nodeList.Count;
                    for (int ix = 0; ix < nCount; ++ix)
                    {
                        XmlElement encryptedElement = nodeList[0] as XmlElement;
                        if (null != salgKey)
                        {
                            if (!DecryptXmlNode(encryptedElement, salgKey))
                            {
                                return false;
                            }
                        }
                    }
                    return true;
                }
            }
            catch (System.Exception ex)
            {
            }
            return false;
        }

        
        public static bool DecryptXmlNode(XmlElement encryptedElement, SymmetricAlgorithm salgKey)
        {
            try
            {
                
                EncryptedData edElement = new EncryptedData();
                edElement.LoadXml(encryptedElement);
                
                EncryptedXml eXml = new EncryptedXml();
                byte[] rgbOutput = eXml.DecryptData(edElement, salgKey);
                
                eXml.ReplaceData(encryptedElement, rgbOutput);
                return true;
            }
            catch (System.Exception ex)
            {

            }
            return false;
        }

        
        private static EncryptionMethod CreateEncryptionMethod(object keyAlg, bool isKeyWrapAlgUri, bool isOaep)
        {
            EncryptionMethod encMethod = new EncryptionMethod();
            String URI = String.Empty;
            if (keyAlg is DES)
            {
                encMethod.KeyAlgorithm = EncryptedXml.XmlEncDESUrl;
                //encMethod.KeySize = 0; [exception, why?]
            }
            else if (keyAlg is Rijndael)
            {
                switch ((keyAlg as Rijndael).KeySize)
                {
                    case 128:
                        encMethod.KeyAlgorithm = isKeyWrapAlgUri ?
                            EncryptedXml.XmlEncAES128KeyWrapUrl : EncryptedXml.XmlEncAES128Url;
                        encMethod.KeySize = 128;
                        break;
                    case 192:
                        encMethod.KeyAlgorithm = isKeyWrapAlgUri ?
                            EncryptedXml.XmlEncAES192KeyWrapUrl : EncryptedXml.XmlEncAES192Url;
                        encMethod.KeySize = 192;
                        break;
                    case 256:
                        encMethod.KeyAlgorithm = isKeyWrapAlgUri ?
                            EncryptedXml.XmlEncAES256KeyWrapUrl : EncryptedXml.XmlEncAES256Url;
                        encMethod.KeySize = 256;
                        break;
                    default:
                        break;
                }
            }
            else if (keyAlg is TripleDES)
            {
                encMethod.KeyAlgorithm = isKeyWrapAlgUri ?
                    EncryptedXml.XmlEncTripleDESKeyWrapUrl : EncryptedXml.XmlEncTripleDESUrl;
                //encMethod.KeySize = 0; [exception, why?]
            }
            else if (keyAlg is RSA)
            {
                encMethod.KeyAlgorithm = isOaep ?
                    EncryptedXml.XmlEncRSAOAEPUrl : EncryptedXml.XmlEncRSA15Url;
            }
            else
            {
                // Do nothing
            }
            return encMethod;
        }

        
        private static SymmetricAlgorithm DecryptKey(XmlDocument xmlDoc, object decryptKey)
        {
            XmlNodeList encKeyNodeList = xmlDoc.GetElementsByTagName("EncryptedKey");
            XmlNodeList encDataNodeList = xmlDoc.GetElementsByTagName("EncryptedData");
            if (encDataNodeList.Count > 0 && encKeyNodeList.Count > 0)
            {
                XmlElement encryptedKey = encKeyNodeList[0] as XmlElement;
                EncryptedKey ek = new EncryptedKey();
                ek.LoadXml(encryptedKey);
                byte[] decryptedData = null;
                //if (decryptKey is SymmetricAlgorithm)
                if (decryptKey is Rijndael || decryptKey is TripleDES)
                {
                    decryptedData = EncryptedXml.DecryptKey(ek.CipherData.CipherValue, (SymmetricAlgorithm)decryptKey);
                }
                else if (decryptKey is RSA)
                {

                    bool fOAEP = (ek.EncryptionMethod != null && ek.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                    decryptedData = EncryptedXml.DecryptKey(ek.CipherData.CipherValue, (RSA)decryptKey, fOAEP);
                }
                else
                {
                    
                    return null;
                }
                XmlElement encryptDataXml = encDataNodeList[0] as XmlElement;
                EncryptedData encryptData = new EncryptedData();
                encryptData.LoadXml(encryptDataXml);
                return GenerateSyAlgKey(decryptedData, encryptData.EncryptionMethod);
            }
            return null;
        }

        
        private static SymmetricAlgorithm GenerateSyAlgKey(byte[] decryptedKeyData, EncryptionMethod encMethod)
        {
            if (null == encMethod || null == decryptedKeyData || 0 == decryptedKeyData.Length)
            {
                return null;
            }
            String keyAlg = encMethod.KeyAlgorithm;
            int keySize = encMethod.KeySize;
            SymmetricAlgorithm symAlg = null;
            if (keyAlg.Equals(EncryptedXml.XmlEncDESUrl))
            {
                symAlg = SymmetricAlgorithm.Create("DES");
                symAlg.Key = decryptedKeyData;
            }
            else if (keyAlg.Equals(EncryptedXml.XmlEncAES128Url) || keyAlg.Equals(EncryptedXml.XmlEncAES128KeyWrapUrl))
            {
                symAlg = SymmetricAlgorithm.Create("Rijndael");
                symAlg.KeySize = 128;
                symAlg.Key = decryptedKeyData;
            }
            else if (keyAlg.Equals(EncryptedXml.XmlEncAES192Url) || keyAlg.Equals(EncryptedXml.XmlEncAES192KeyWrapUrl))
            {
                symAlg = SymmetricAlgorithm.Create("Rijndael");
                symAlg.KeySize = 192;
                symAlg.Key = decryptedKeyData;
            }
            else if (keyAlg.Equals(EncryptedXml.XmlEncAES256Url) || keyAlg.Equals(EncryptedXml.XmlEncAES256KeyWrapUrl))
            {
                symAlg = SymmetricAlgorithm.Create("Rijndael");
                symAlg.KeySize = 256;
                symAlg.Key = decryptedKeyData;
            }
            else if (keyAlg.Equals(EncryptedXml.XmlEncTripleDESUrl) || keyAlg.Equals(EncryptedXml.XmlEncTripleDESKeyWrapUrl))
            {
                symAlg = SymmetricAlgorithm.Create("TripleDES");
                symAlg.Key = decryptedKeyData;
            }
            else
            {
            }
            return symAlg;
        }
    }
}

