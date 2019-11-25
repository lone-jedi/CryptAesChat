using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace Crypt
{
    public partial class Form1 : Form
    {
        private readonly byte[] mainToken = new byte[] { 4, 3, 8, 4, 3, 2, 5, 8, 6, 6, 7, 8, 6, 2, 0, 2, 8, 7, 8, 2, 7, 8, 0, 2, 8, 1, 8, 8, 8, 7, 3, 3};

        public Form1()
        {
            InitializeComponent();
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            label1.Text = "";

            string text = "";
            

            try
            {
                string original = textBox1.Text;

                using (Aes myAes = Aes.Create())
                {
                    myAes.Key = mainToken;
                    // Зашифрованную строку переводим в массив байтов
                    byte[] encrypted = EncryptStringToBytesAes(original, myAes.Key, myAes.IV);
                    text += "Crypted:  ";
                    foreach (byte bt in encrypted)
                        text +=  bt.ToString();

                    text += "\n";

                   // Расшифровываем байты и записываем в строку.
                   string roundtrip = DecryptStringFromBytesAes(encrypted, myAes.Key, myAes.IV);

                    //Выводим на экран результат
                    text += "Original:  " + original + "\n";
                    text += "Round Trip: " + roundtrip + "\n";

                }
            }
            catch (Exception ex)
            {
                // Если что-то не так выбрасываем исключение
                text = "Error: " + ex.Message + "\n";
            }

            label1.Text = text;
        }

        static byte[] EncryptStringToBytesAes(string plainText, byte[] Key, byte[] IV)
        {
            // Проверка аргументов
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Создаем объект класса AES
            // с определенным ключом and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создаем объект, который определяет основные операции преобразований.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток для шифрования.
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Записываем в поток все данные.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            //Возвращаем зашифрованные байты из потока памяти.
            return encrypted;
        }

        static string DecryptStringFromBytesAes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Проверяем аргументы
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Строка, для хранения расшифрованного текста
            string plaintext;

            // Создаем объект класса AES,
            // Ключ и IV
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Создаем объект, который определяет основные операции преобразований.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Создаем поток для расшифрования.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Читаем расшифрованное сообщение и записываем в строку
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }
    }
}
