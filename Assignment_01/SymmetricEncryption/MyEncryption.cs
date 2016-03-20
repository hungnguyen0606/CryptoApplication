using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;


namespace SymmetricEncryption
{

    class MyEncryption
    {
        public bool Encrypt(string src, string des, string pass, int et, int padMode, int ciMode)
        {
            SymmetricAlgorithm EncryptionType;

            if (et == 0)
            {
                EncryptionType = new RijndaelManaged();
                //EncryptionType.BlockSize = EncryptionType.LegalBlockSizes[0];
            }
            else
            {
                EncryptionType = new TripleDESCryptoServiceProvider();    
            }

            //generate random Initial Vector
            EncryptionType.GenerateIV();
            //check the key's size
            var key = Encoding.ASCII.GetBytes(pass);
            if (!EncryptionType.ValidKeySize(key.Length))
                return false;
            EncryptionType.Key = key;
            EncryptionType.KeySize = key.Length;
            //
            //set padding mode
            EncryptionType.Padding = padMode == 0 ? PaddingMode.PKCS7 : PaddingMode.ISO10126;
            //set mode of operation
            EncryptionType.Mode = ciMode == 0 ? CipherMode.CBC : CipherMode.CFB;
            //
            ICryptoTransform transform = EncryptionType.CreateEncryptor();
            
            //prepare header
            byte[] LenKey = new byte[4];
            byte[] LenIV = new byte[4];
            byte[] mPadMode = new byte[4];
            byte[] mEncryptionType = new byte[4];
            byte[] mModeOperation = new byte[4];

            LenKey = BitConverter.GetBytes(EncryptionType.KeySize / 8);
            LenIV = BitConverter.GetBytes(EncryptionType.IV.Length);
            mPadMode = BitConverter.GetBytes(padMode);
            mEncryptionType = BitConverter.GetBytes(et);
            mModeOperation = BitConverter.GetBytes(ciMode);


            //write encrypted data to file
            using (FileStream outFs = new FileStream(des, FileMode.Create))
            {
                outFs.Write(mEncryptionType, 0, 4);
                outFs.Write(mModeOperation, 0, 4);
                outFs.Write(mPadMode, 0, 4);
                outFs.Write(LenKey, 0, 4);
                outFs.Write(LenIV, 0, 4);
                outFs.Write(EncryptionType.IV, 0, EncryptionType.IV.Length);

                using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {
                    int blockSizeBytes = EncryptionType.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];
                    int bytesRead = 0;
                    int count = 0;
                    int offset = 0;
                    using (FileStream inFs = new FileStream(src, FileMode.Open))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamEncrypted.Write(data, 0, count);
                            bytesRead += blockSizeBytes;
                        }
                        while (count > 0);
                        inFs.Close();
                    }
                    outStreamEncrypted.FlushFinalBlock();
                    outStreamEncrypted.Close();
                }
                outFs.Close();
            }


            return true;
        }
        public bool Decrypt(string src, string des, string pass)
        {
            using (FileStream inFs = new FileStream(src, FileMode.Open))
            {
                //read header and create decryption
                
                byte[] mEncryptionType = new byte[4];
                byte[] mModeOperation = new byte[4];
                byte[] mPadMode = new byte[4];
                byte[] LenKey = new byte[4];
                byte[] LenIV = new byte[4];
                //
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(mEncryptionType, 0, 4);
                inFs.Read(mModeOperation, 0, 4);
                inFs.Read(mPadMode, 0, 4);
                inFs.Read(LenKey, 0, 4);
                inFs.Read(LenIV, 0, 4);

                SymmetricAlgorithm myEncryption;
                if (BitConverter.ToInt32(mEncryptionType, 0) == 0)
                    myEncryption = new RijndaelManaged();
                else
                    myEncryption = new TripleDESCryptoServiceProvider();
                //
                myEncryption.KeySize = BitConverter.ToInt32(LenKey, 0);
                byte[] iv = new byte[BitConverter.ToInt32(LenIV, 0)];
                inFs.Read(iv, 0, iv.Length);

                myEncryption.IV = iv;
                myEncryption.Mode = (BitConverter.ToInt32(mModeOperation, 0) == 0) ? CipherMode.CBC : CipherMode.CFB;
                myEncryption.Padding = (BitConverter.ToInt32(mPadMode, 0) == 0) ? PaddingMode.PKCS7 : PaddingMode.ISO10126;

                ICryptoTransform transform = myEncryption.CreateDecryptor();
                
                //
                using (FileStream outFs = new FileStream(des, FileMode.Create))
                {

                    int count = 0;
                    int offset = 0;
                   
                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = my.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];


                    // By decrypting a chunk a time,
                    // you can save memory and
                    // accommodate large files.

                    // Start at the beginning
                    // of the cipher text.
                    inFs.Seek(startC, SeekOrigin.Begin);
                    using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamDecrypted.Write(data, 0, count);

                        }
                        while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                        outStreamDecrypted.Close();
                    }
                    outFs.Close();
                }
                inFs.Close();
            }
            return true;
        }
    }
}
