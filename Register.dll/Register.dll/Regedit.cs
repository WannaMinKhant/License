using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.NetworkInformation;
using System.Management;
using System.Security;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Windows.Forms;

namespace Register.dll
{
    public class Regedit
    {
        //constructor
        public Regedit()
        {
           
        }

        private bool activated = false;

        private string serial;
        private RegistryKey regkey;
        private string user;

        public string User
        {
            get { return user; }
            set { user = value; }
        }
        public string Serial
        {
            get { return serial; }
            set { serial = value; }
        }


        static string privateKey = "Vict0ri@Win3Fruity2o18V0lt3xK00l";

        static string secondKey = "MinKh@ntNy@rKy@w";

        private string verifyKey = "Fruity53n535";

        private string RealKey,checkKey;

        private string cpuId, mac, challangeKey;

        private string CPUID()
        {
            string cpu = string.Empty;
            ManagementClass mgc = new ManagementClass("Win32_Processor");
            ManagementObjectCollection mgco = mgc.GetInstances();
            foreach(ManagementObject cpuid in mgco)
            {
                if(cpu == string.Empty)
                {
                    cpu = cpuid.Properties["ProcessorId"].Value.ToString();
                }
            }
            return cpu;
        }

        private string MacAddress()
        {
            string mac = string.Empty;
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach(NetworkInterface macId in nics)
            {
                
                if(mac == string.Empty)
                {
                    IPInterfaceProperties properties = macId.GetIPProperties();
                    mac = macId.GetPhysicalAddress().ToString();
                }
                
            }
            return mac;
        }

        public string GetComponent(string hWclass, string syntax)
        {
            string com = string.Empty;
            ManagementObjectSearcher mos = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM " + hWclass);

            foreach(ManagementObject mo in mos.Get())
            {
                com = mo[syntax].ToString();
            }

            return com;
        }

        private static string Encrypt(string str)
        {
            byte[] planeTextByte = System.Text.UTF8Encoding.UTF8.GetBytes(str);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = System.Text.UTF8Encoding.UTF8.GetBytes(privateKey);
            aes.IV = System.Text.UTF8Encoding.UTF8.GetBytes(secondKey);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] encrypt = crypto.TransformFinalBlock(planeTextByte, 0, planeTextByte.Length);
            crypto.Dispose();
            return Convert.ToBase64String(encrypt);

        }

        private static string Decrypt(string encrypted)
        {
            byte[] encryptbyte = Convert.FromBase64String(encrypted);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = System.Text.UTF8Encoding.UTF8.GetBytes(privateKey);
            aes.IV = System.Text.UTF8Encoding.UTF8.GetBytes(secondKey);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateDecryptor(aes.Key, aes.IV);
            byte[] secret = crypto.TransformFinalBlock(encryptbyte, 0, encryptbyte.Length);
            crypto.Dispose();
            return System.Text.UTF8Encoding.UTF8.GetString(secret);
        }

        public string CreateKey()
        {
            cpuId = CPUID();
            mac = MacAddress();
            string preId = cpuId.Substring(0, 6);
            string user = this.user;
            string complieKey = preId + verifyKey + mac + user;
            challangeKey = Encrypt(complieKey);
            return challangeKey;
        }

        public bool Activate()
        {
            bool check = false;
            string compileKey = Decrypt(this.serial);
            string VerifyKey = compileKey.Substring(0,16);
            string Mac = compileKey.Substring(compileKey.Length - 12,12 );

            RealKey = Encrypt(user + secondKey + this.mac);

            if(secondKey == VerifyKey && RealKey == this.serial)
            {
                          
                regkey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("SOFTWARE\\SystemFS");
                regkey.SetValue(this.user, RealKey);
                regkey.Close();
                check = true;
            }

            return check;
        }

        public bool CheckLicense()
        {
            checkKey = Encrypt(secondKey + this.mac);

            regkey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\SystemFS", true);
            if(regkey != null)
            {
               
                if (regkey.GetValue(this.user).ToString() == checkKey)
                {
                    activated = true;
                }
                else
                {
                    activated = false;
                }

            }
            else
            {
              activated = false;
            }
            return activated;
        }
    }
}
