using Cryptography;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TestCrypto;

public class UnitTest1
{
    [Fact]
    public void Test1() {

        X509Certificate2 cert = Certificate.GetCertificateFromStore("CN=Patti Fuller");

        var filePath = "C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCrypto\\appsettings.json";
        //var toEncrypt = File.ReadAllText(filePath);
        //string toEncrypt = @"{""Password"": ""qwerty12""}";
        //StreamWriter sw = File.CreateText(filePath);
        //sw.WriteLine(toEncrypt);
        //sw.Close();

        //Encrypter.EncryptFile(filePath, (RSA)cert.PublicKey.Key!);

        File.Delete(filePath);

        var encryptedFilePath = filePath.Substring(0, filePath.LastIndexOf(".")) + ".enc";
        var data = Decrypter.DecryptFile(encryptedFilePath, cert.GetRSAPrivateKey()!);
        var dataAsString = Encoding.UTF8.GetString(data);

        //StreamWriter json = File.CreateText(filePath);
        //json.WriteLine(dataAsString);
        //json.Close();


        Assert.NotEmpty(dataAsString.Replace("\n", "").Replace("\r", ""));
    }
}