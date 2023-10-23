using System.Security.Cryptography;

namespace Cryptography;
public static class Encrypter
{
    public static void EncryptFile(string inFile, RSA rsaPublicKey) {
        using (Aes aes = Aes.Create()) {
            // Create instance of Aes for symetric encryption of the data.
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            using (ICryptoTransform transform = aes.CreateEncryptor()) {
                RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(rsaPublicKey);
                byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aes.Key, aes.GetType());

                // Create byte arrays to contain the length values of the key and IV.
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                int lKey = keyEncrypted.Length;
                LenK = BitConverter.GetBytes(lKey);
                int lIV = aes.IV.Length;
                LenIV = BitConverter.GetBytes(lIV);


                // Change the file's extension to ".enc"
                string outFile = inFile.Substring(0, inFile.LastIndexOf(".")) + ".enc";

                using (FileStream outFs = new FileStream(outFile, FileMode.Create)) {

                    // Write the following to the FileStream for the encrypted file (outFs):
                    // - length of the key
                    // - length of the IV
                    // - ecrypted key
                    // - the IV
                    // - the encrypted cipher content
                    outFs.Write(LenK, 0, 4);
                    outFs.Write(LenIV, 0, 4);
                    outFs.Write(keyEncrypted, 0, lKey);
                    outFs.Write(aes.IV, 0, lIV);

                    // Now write the cipher text using a CryptoStream for encrypting.
                    using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write)) {

                        // By encrypting a chunk at a time, you can save memory and accommodate large files.
                        int count = 0;

                        // blockSizeBytes can be any arbitrary size.
                        int blockSizeBytes = aes.BlockSize / 8;
                        byte[] data = new byte[blockSizeBytes];
                        int bytesRead = 0;

                        using (FileStream inFs = new FileStream(inFile, FileMode.Open)) {
                            do {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                outStreamEncrypted.Write(data, 0, count);
                                bytesRead += count;
                            }
                            while (count > 0);
                            inFs.Close();
                        }
                        outStreamEncrypted.FlushFinalBlock();
                        outStreamEncrypted.Close();
                    }
                    outFs.Close();
                }
            }
        }
    }

}
