using System.Security.Cryptography;
using System.Text;

namespace Cryptography;
public static class Decrypter
{
    // Decrypt a file using a private key.
    public static byte[] DecryptFile(string inFile, RSA rsaPrivateKey) {

        byte[] decryptedData;
        // Create instance of Aes for symetric decryption of the data.
        using (Aes aes = Aes.Create()) {
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;

            // Create byte arrays to get the length of the encrypted key and IV.
            // These values were stored as 4 bytes each at the beginning of the encrypted package.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

            // Construct the file name for the decrypted file.
            string outFile = inFile.Substring(0, inFile.LastIndexOf(".")) + ".txt";

            // Use FileStream objects to read the encrypted file (inFs) and save the decrypted file (outFs).
            using (FileStream inFs = new FileStream(inFile, FileMode.Open)) {

                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(LenK, 0, 3);
                inFs.Seek(4, SeekOrigin.Begin);
                inFs.Read(LenIV, 0, 3);

                // Convert the lengths to integer values.
                int lenK = BitConverter.ToInt32(LenK, 0);
                int lenIV = BitConverter.ToInt32(LenIV, 0);

                // Determine the start position of the cipher text (startC) and its length(lenC).
                int startC = lenK + lenIV + 8;
                int lenC = (int)inFs.Length - startC;

                // Create the byte arrays for the encrypted Aes key, the IV, and the cipher text.
                byte[] KeyEncrypted = new byte[lenK];
                byte[] IV = new byte[lenIV];

                // Extract the key and IV starting from index 8 after the length values.
                inFs.Seek(8, SeekOrigin.Begin);
                inFs.Read(KeyEncrypted, 0, lenK);
                inFs.Seek(8 + lenK, SeekOrigin.Begin);
                inFs.Read(IV, 0, lenIV);
                // Use RSA to decrypt the Aes key.
                byte[] KeyDecrypted = rsaPrivateKey.Decrypt(KeyEncrypted, RSAEncryptionPadding.Pkcs1);

                // Decrypt the key.
                using (ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV)) {

                    // Decrypt the cipher text from from the FileSteam of the encrypted
                    // file (inFs) into the FileStream for the decrypted file (outFs).
                    using (MemoryStream outFs = new MemoryStream()) {

                        int count = 0;

                        int blockSizeBytes = aes.BlockSize / 8;
                        byte[] data = new byte[blockSizeBytes];

                        // By decrypting a chunk a time, you can save memory and accommodate large files.

                        // Start at the beginning of the cipher text.
                        inFs.Seek(startC, SeekOrigin.Begin);
                        using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write)) {
                            do {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                outStreamDecrypted.Write(data, 0, count);
                            }
                            while (count > 0);
 
                            outStreamDecrypted.FlushFinalBlock();
                            outStreamDecrypted.Close();
                            decryptedData = outFs.ToArray();
                        }
                    }
                    inFs.Close();
                }
            }
            return decryptedData;
        }
    }
}

