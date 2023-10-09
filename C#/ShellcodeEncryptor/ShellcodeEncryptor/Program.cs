using System;
using System.IO;
using System.Security.Cryptography;

namespace ShellcodeEncryptor
{
    class Program
    {
        static byte[] EncryptStringToBytes(string str, byte[] keys)
        {
            byte[] encrypted;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = keys;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(aes.IV, 0, aes.IV.Length);
                    ICryptoTransform encoder = aes.CreateEncryptor();
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encoder, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(str);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            return encrypted;
        }

        static void Main(string[] args)
        {
            string filepath = args[0];
            string bufString = File.ReadAllText(filepath);

            bufString = bufString.Replace("\r", string.Empty).Replace("\n", string.Empty).Replace("\t", string.Empty).Replace(" ", string.Empty).Replace(";", string.Empty).Replace(",", string.Empty).Replace("0x", "x").Replace("{", string.Empty).Replace("}", string.Empty);
            string[] bufArr = bufString.Split('x');
            byte[] buf = new byte[bufArr.Length - 1];

            for (int i = 0; i < bufArr.Length - 1; i++)
            {
                string a = bufArr[i + 1];
                buf[i] = Convert.ToByte(a, 16);
            }
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;
            byte[] key = aes.Key;
            byte[] encrypted = EncryptStringToBytes(BitConverter.ToString(buf), key);

            if (buf.Length < 1024)
            {
                Console.Write("byte[] key = new byte[{0}] {{", key.Length);
                for (int i = 0; i < key.Length; i++)
                {
                    if (i % 12 == 0)
                    {
                        Console.Write("\n\t");
                    }
                    Console.Write("0x{0},", BitConverter.ToString(key, i, 1).ToLower());
                }
                Console.Write("\b\0\n};\n\n");
                Console.Write("byte[] buf = new byte[{0}] {{", encrypted.Length);
                for (int i = 0; i < encrypted.Length; i++)
                {
                    if (i % 12 == 0)
                    {
                        Console.Write("\n\t");
                    }
                    Console.Write("0x{0},", BitConverter.ToString(encrypted, i, 1).ToLower());
                }
                Console.Write("\b\0\n};\n\n");
            }
            else
            {
                string[] _outfile = filepath.Split('\\');
                _outfile[_outfile.Length - 1] = "output.txt";
                string outfile = string.Join("\\", _outfile);
                Console.Write("Payload too big! Dumping encrypted shellcode and key to file: {0}\n", outfile);
                using (StreamWriter writer = new StreamWriter(outfile))
                {
                    writer.Write("byte[] key = new byte[{0}] {{", key.Length);
                    for (int i = 0; i < key.Length; i++)
                    {
                        if (i % 12 == 0)
                        {
                            writer.Write("\n\t");
                        }
                        writer.Write("0x{0},", BitConverter.ToString(key, i, 1).ToLower());
                    }
                    writer.Write("\n};\n\n");
                    writer.Write("byte[] buf = new byte[{0}] {{", encrypted.Length);
                    for (int i = 0; i < encrypted.Length; i++)
                    {
                        if (i % 12 == 0)
                        {
                            writer.Write("\n\t");
                        }
                        writer.Write("0x{0},", BitConverter.ToString(encrypted, i, 1).ToLower());
                    }
                    writer.Write("\n};");
                }
            }
        }
    }
}
