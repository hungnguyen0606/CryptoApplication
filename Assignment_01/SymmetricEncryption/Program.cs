using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SymmetricEncryption
{
        
    class Program
    {
       
        static void Main(string[] args)
        {
            string src, des;
            Console.Write("Source file: ");
            src = Console.ReadLine();
            Console.Write("Destination file: ");
            des = Console.ReadLine();

            Console.Write("Choose 0/1 to encrypt/decrypt: ");
            int isEc = Convert.ToInt32(Console.ReadLine());

            MyEncryption myEn = new MyEncryption();
            if (isEc == 0)
            {
                Console.WriteLine("Choose encryption's type.\n\t0. AES\n\t1. 3Des\nChoose type (0/1): ");
                int et = Convert.ToInt32(Console.ReadLine());
                Console.WriteLine("Choose Padding mode.\n\t0. PKCS7\n\t1. ISO10126\nChoose type (0/1): ");
                int padMode = Convert.ToInt32(Console.ReadLine());
                Console.WriteLine("Choose Mode of Operation.\n\t0. CBC\n\t1. CFB\nChoose type (0/1): ");
                int ciMode = Convert.ToInt32(Console.ReadLine());
                Console.Write("Enter your password: ");
                string pass = Console.ReadLine();
                bool isEncrypt = myEn.Encrypt(src, des, pass, et, padMode, ciMode);
                if (isEncrypt)
                    Console.WriteLine("Encrypt successfully.");
                else
                    Console.WriteLine("Fail to Encrypt");
            }
            else
            {
                Console.Write("Enter your password: ");
                string pass = Console.ReadLine();

                bool isDec = myEn.Decrypt(src, des, pass);
                if (isDec)
                    Console.WriteLine("Decrypt successfully.");
                else
                    Console.WriteLine("Fail to decrypt");

            }

        }
    }
}
