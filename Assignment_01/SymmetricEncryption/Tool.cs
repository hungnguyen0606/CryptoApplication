using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace SymmetricEncryption
{
    class Tool
    {
        //maximum size of string up to 128 bytes (length of MD5)
        public string Expand(string str, int size = -1)
        {
            StringBuilder ret = new StringBuilder();
            
            using (SHA512 sha = SHA512.Create())
            {
                byte[] data = sha.ComputeHash(Encoding.UTF8.GetBytes(str));
                
                string temp = Encoding.UTF8.GetString(data);
                if (size == -1)
                    size = temp.Length;
                if (size > temp.Length)
                    size = temp.Length;

                return temp.Substring(0, size); 
            }
        }
        public string genRandomString(int len)
        {
            StringBuilder ret = new StringBuilder();
            byte[] temp = new byte[len];
            Random r = new Random();
            for (int i = 0; i < len; ++i)
                temp[i] = (byte)r.Next(256);
            return ret.ToString();
        }
    }
}
