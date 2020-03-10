using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace ConsoleApp1
{
    [Serializable]
    class User
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string LoginIM { get; set; }
        public string LoginByEmail { get; set; }
        public string UserAlias { get; set; }
        public string PKcity { get; set; }
        public string PKCompany { get; set; }
        public string PKUser { get; set; }
        public string Role { get; set; }

        public override string ToString()
        {
            return $@"Email:{Email}, Password:{Password}, LoginIM:{LoginIM}, LoginByEmail:{LoginByEmail}, UserAlias:{UserAlias}
                , PKcity:{PKcity}, PKCompany:{PKCompany}, PKUser:{PKUser}, Role:{Role}";
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            //TestConfig();

            //TestXML();

            //TestEncryptDat();
            //TestDecryptDat();


            //TestAESEncryptDat();
            //TestAESDecryptDat();

            TestEncryptXML();

            Console.ReadKey();
        }

        static void TestEncryptXML()
        {
            RSA rsaKey = GTXXmlCrypt.CreateRSAAlgorithm("rsakey container");

            GTXXmlCrypt.EncryptXmlFile("TestUserSetting.xml", "User", false, rsaKey, "");

            //GTXXmlCrypt.DecryptXmlFile("TestUserSetting.xml", rsaKey, "");
        }

        static void TestConfig()
        {
            DpapiHelper.EncryptConfigSection("appSettings");
            //DPAPIHelper.DecryptConfigSection("appSettings");

            //Configuration config = ConfigurationManager.OpenExeConfiguration("Fooww.Soft.DataModel.dll.config");
            //var connectionStrings = config.AppSettings.Settings["connectionStrings"];

        }

        /// <summary>
        /// 针对XML的value加密
        /// </summary>
        static void TestXML()
        {
            //加密密码
            XElement xElement = XElement.Load("UserSetting.xml");
            var userTag = xElement.Elements().FirstOrDefault(item => item.Name == "User");
            var passwordTag = userTag.Elements().FirstOrDefault(item => item.Name == "Password");
            //var securePassword = EncryptString(ToSecureString(passwordTag.Value));
            //passwordTag.Value = securePassword;
            //xElement.Save("UserSetting.xml");

            //取出原密码
            var password = DpapiHelper.ToInsecureString(DpapiHelper.DecryptString(passwordTag.Value));
            Console.WriteLine($"原密码：{password}");
        }

        /// <summary>
        /// 加密Json字符串后序列化成dat文件
        /// </summary>
        static void TestEncryptDat()
        {
            //加密
            User user = new User
            {
                Email = "lifuquan-fooww@fooww.com",
                Password = "123456",
                LoginIM = "0",
                LoginByEmail = "1",
                PKcity = "197e6c8f-6d32-4a27-867a-0ac6e77ee729",
                PKCompany = "3478b0f5-ca53-4c07-a3b7-4977222c1619",
                PKUser = "c1cfc8bc-61f2-4596-9f6f-d48c126113cc",
                Role = "系统管理员"
            };
            
            using (FileStream fileStream = new FileStream("user.dat", FileMode.Create))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                var value = JsonConvert.SerializeObject(user);

                Stopwatch watch = new Stopwatch();
                watch.Start();
                var secureValue = DpapiHelper.EncryptString(DpapiHelper.ToSecureString(value));
                watch.Stop();
                Console.WriteLine($"加密花费时间:{watch.ElapsedMilliseconds}毫秒");

                binaryFormatter.Serialize(fileStream, secureValue);
            }
            
        }

        static void TestDecryptDat()
        {
            using (FileStream fileStream = new FileStream("user.dat", FileMode.Open))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                var secureValue = binaryFormatter.Deserialize(fileStream);

                Stopwatch watch = new Stopwatch();
                watch.Start();
                var value = DpapiHelper.ToInsecureString(DpapiHelper.DecryptString(secureValue.ToString()));
                watch.Stop();
                Console.WriteLine($"解密花费时间:{watch.ElapsedMilliseconds}毫秒");

                var userValue = JsonConvert.DeserializeObject<User>(value);
            }
        }

        static void TestAESEncryptDat()
        {
            User user = new User
            {
                Email = "lifuquan-fooww@fooww.com",
                Password = "123456",
                LoginIM = "0",
                LoginByEmail = "1",
                PKcity = "197e6c8f-6d32-4a27-867a-0ac6e77ee729",
                PKCompany = "3478b0f5-ca53-4c07-a3b7-4977222c1619",
                PKUser = "c1cfc8bc-61f2-4596-9f6f-d48c126113cc",
                Role = "系统管理员"
            };

            using (FileStream fileStream = new FileStream("user.dat", FileMode.Create))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();

                var jsonValue = JsonConvert.SerializeObject(user);
                Stopwatch watch = new Stopwatch();
                watch.Start();
                string result = AesHelper.AesEncrypt(jsonValue);
                watch.Stop();
                Console.WriteLine($"加密花费时间:{watch.ElapsedMilliseconds}毫秒");
                Console.WriteLine($"加密结果:{result}");

                binaryFormatter.Serialize(fileStream, result);
            }
        }

        static void TestAESDecryptDat()
        {
            using (FileStream fileStream = new FileStream("user.dat", FileMode.Open))
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                var secureValue = binaryFormatter.Deserialize(fileStream);

                Stopwatch watch = new Stopwatch();
                watch.Start();
                var value = AesHelper.AesDecrypt(secureValue.ToString());
                Console.WriteLine($"解密结果:{value}");
                watch.Stop();
                Console.WriteLine($"解密花费时间:{watch.ElapsedMilliseconds}毫秒");
            }
        }
    }
}
