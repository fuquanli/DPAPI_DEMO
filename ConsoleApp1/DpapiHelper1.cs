using System;
using System.Configuration;
using System.Security;
using System.Text;

namespace ConsoleApp1
{
    public static class DpapiHelper
    {
        #region DPAPI加密
        #region 加密整个节点--针对config文件
        /// <summary>
        /// 加密整个节点
        /// 加密后只能在当前电脑上解密,copy到其他电脑不能解密
        /// </summary>
        /// <param name="sectionKey"></param>
        public static void EncryptConfigSection(string sectionKey)
        {
            Configuration config = ConfigurationManager.OpenExeConfiguration("DataModel.dll.config");
            ConfigurationSection section = config.GetSection(sectionKey);
            if (section != null && !section.SectionInformation.IsProtected && !section.ElementInformation.IsLocked)
            {
                section.SectionInformation.ProtectSection("DataProtectionConfigurationProvider");
            }
        }

        public static void DecryptConfigSection(string sectionKey)
        {
            Configuration config = ConfigurationManager.OpenExeConfiguration("DataModel.dll.config");
            ConfigurationSection section = config.GetSection(sectionKey);
            if (section != null)
            {
                section.SectionInformation.UnprotectSection();
                section.SectionInformation.ForceDeclaration(true);
                section.SectionInformation.ForceSave = true;
                config.Save(ConfigurationSaveMode.Full);
            }
        }
        #endregion

        #region 加密某字符串
        static byte[] entropy = Encoding.Unicode.GetBytes("12345678876543211234567887654abc");

        public static string EncryptString(System.Security.SecureString input)
        {
            byte[] encryptedData = System.Security.Cryptography.ProtectedData.Protect(
                System.Text.Encoding.UTF8.GetBytes(ToInsecureString(input)),
                entropy,
                System.Security.Cryptography.DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(encryptedData);
        }

        public static SecureString DecryptString(string encryptedData)
        {
            try
            {
                byte[] decryptedData = System.Security.Cryptography.ProtectedData.Unprotect(
                    Convert.FromBase64String(encryptedData),
                    entropy,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return ToSecureString(System.Text.Encoding.UTF8.GetString(decryptedData));
            }
            catch
            {
                return new SecureString();
            }
        }

        public static SecureString ToSecureString(string input)
        {
            SecureString secure = new SecureString();
            foreach (char c in input)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }

        public static string ToInsecureString(SecureString input)
        {
            string returnValue = string.Empty;
            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(input);
            try
            {
                returnValue = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(ptr);
            }
            return returnValue;
        }
        #endregion
        #endregion
    }
}
