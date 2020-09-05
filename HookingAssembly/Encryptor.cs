using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace HookingAssembly
{
    public class Encryptor
    {
        // Token: 0x06000E12 RID: 3602 RVA: 0x00005CD3 File Offset: 0x000040D3
        public static byte[] Decrypt(byte[] encryptedData, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        // Token: 0x06000E13 RID: 3603 RVA: 0x00033DD8 File Offset: 0x000321D8
        public static string DecryptString(string secretKey, string encryptedText)
        {
            string result;
            try
            {
                byte[] encryptedData = Convert.FromBase64String(encryptedText.Replace(" ", "+").Replace("-", "+").Replace('_', '/'));
                result = Encoding.UTF8.GetString(Encryptor.Decrypt(encryptedData, Encryptor.GetRijndaelManaged(secretKey)));
            }
            catch (Exception)
            {
                result = "";
            }
            return result;
        }

        // Token: 0x06000E14 RID: 3604 RVA: 0x00005CEF File Offset: 0x000040EF
        public static byte[] Encrypt(byte[] plainBytes, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateEncryptor().TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }

        // Token: 0x06000E15 RID: 3605 RVA: 0x00005D0B File Offset: 0x0000410B
        public static string EncryptString(string secretKey, string plainText)
        {
            return Convert.ToBase64String(Encryptor.Encrypt(Encoding.UTF8.GetBytes(plainText), Encryptor.GetRijndaelManaged(secretKey)));
        }

        // Token: 0x06000E16 RID: 3606 RVA: 0x00033E70 File Offset: 0x00032270
        public static string GetMd5Hash(string input)
        {
            byte[] array = MD5.Create().ComputeHash(Encoding.ASCII.GetBytes(input));
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < array.Length; i++)
            {
                string text = array[i].ToString("X").ToLower();
                stringBuilder.Append(((text.Length == 1) ? "0" : "") + text);
            }
            return stringBuilder.ToString();
        }

        // Token: 0x06000E17 RID: 3607 RVA: 0x00033F00 File Offset: 0x00032300
        public static RijndaelManaged GetRijndaelManaged(string secretKey)
        {
            byte[] array = new byte[16];
            byte[] bytes = Encoding.UTF8.GetBytes(secretKey);
            Array.Copy(bytes, array, Math.Min(array.Length, bytes.Length));
            return new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                KeySize = 128,
                BlockSize = 128,
                Key = array,
                IV = array
            };
        }
    }
}
