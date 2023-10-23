using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using X509CertEncrypt;

//var certs = new X509Store(StoreName.My, StoreLocation.LocalMachine);


//var myCertificate = certs.Certificates.Find(
//       X509FindType.FindBySubjectName,
//          "www.fabrikam.com",
//             false).First();

//await Encrypt("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCertificate\\appsettings.json", "Patti Fuller");
//
//await Decrypt("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCertificate\\appsettings.encrypted.enc", "Patti Fuller");


MicrosoftExample.Main();

static async Task Encrypt(string filePath, string certName) {

    //We're using AES encryption to create my key.
    Aes aesKey = Aes.Create();
    aesKey.GenerateKey();
    byte[] ivKey = new byte[aesKey.IV.Length];
    Array.Copy(aesKey.Key, ivKey, aesKey.IV.Length);
    aesKey.IV = ivKey;
    var encryptor = aesKey.CreateEncryptor();
    var encryptedKey = EncryptKey(ivKey, certName);
    Console.WriteLine(Encoding.UTF8.GetString(encryptedKey));
    //Copy the file to memory so we can overwrite the source with it's encrypted version.
    var file = await File.ReadAllBytesAsync(filePath);

    var encryptedFilePath = "C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCertificate\\appsettings.encrypted.enc";
    //We're using truncate mode, so the file opens up and is empty.
    using (var outputStream = new FileStream(encryptedFilePath, FileMode.OpenOrCreate)) {
        //Add the encrypted key to the start of file.
        await outputStream.WriteAsync(encryptedKey, 0, encryptedKey.Length);
        using (var encryptStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
        using (var inputStream = new MemoryStream(file)) {
            await inputStream.CopyToAsync(encryptStream);
        }
    }
}

static async Task Decrypt(string filePath, string certName) {
    //Read the file in memory so we can overwrite the source with it's original file.
    //We also need it in memory so we can extract the key.
    var file = (await File.ReadAllBytesAsync(filePath)).ToList();
    var encryptedKey = new Collection<byte>();
    //Checking the length so we know how much bytes we need to take from the file.
    //Different certificates can create different size of keys.

    var encryptLength = 256;
    //Extract the key.
    for (var i = 0; i < encryptLength; i++) {

        encryptedKey.Add(file[i]);
    }
    file.RemoveRange(0, encryptLength);

    var decryptedKey = DecryptKey(encryptedKey.ToArray(), certName);
    Console.WriteLine(Encoding.UTF8.GetString(decryptedKey));
    using (var managed = new AesManaged()) {
        //I'm using AES encryption, but this time we do not generate the key but pass our decrypted key.
        Aes aesKey = Aes.Create();
        aesKey.Key = decryptedKey;
        byte[] ivKey = new byte[aesKey.IV.Length];
        Array.Copy(aesKey.Key, ivKey, aesKey.IV.Length);
        aesKey.IV = ivKey;
        var decryptor = aesKey.CreateDecryptor();

        var decryptedFilePath = "C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCertificate\\appsettings.decrypted.json";
        //We're using truncate mode, so the file opens up and is empty.
        using (var fileStream = new FileStream(decryptedFilePath, FileMode.OpenOrCreate))
        using (var decryptStream = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Write))
        using (var encryptedFileStream = new MemoryStream(file.ToArray()))
            await encryptedFileStream.CopyToAsync(decryptStream);
    }
}


static byte[] DecryptKey(byte[] keyBytes, string certName) {
    var certs = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    certs.Open(OpenFlags.ReadOnly);
    var cert = certs.Certificates.Find(X509FindType.FindBySubjectName, certName, false).First();

    var privateKey = cert.GetRSAPrivateKey();
    //Decrypt the key with the same padding used to encrypt it.
    return privateKey.Decrypt(keyBytes, RSAEncryptionPadding.OaepSHA512);
}
static byte[] EncryptKey(byte[] key, string certName) {
    var certs = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    certs.Open(OpenFlags.ReadOnly);
    var cert = certs.Certificates.Find(X509FindType.FindBySubjectName, certName, false).First();

    var publicKey = cert.GetRSAPublicKey();
    //Encrypt the key with certificate
    return publicKey.Encrypt(key, RSAEncryptionPadding.OaepSHA512);
}
