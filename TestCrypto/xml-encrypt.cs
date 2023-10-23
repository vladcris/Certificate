using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace TestCrypto;
public class xml_encrypt
{
    [Fact]
    public void Test1() {
        // Create an XmlDocument object.
        XmlDocument xmlDoc = new XmlDocument();

        // Load an XML file into the XmlDocument object.
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCrypto\\test.xml");

        // Open the X.509 "Current User" store in read only mode.
        X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        // Place all certificates in an X509Certificate2Collection object.
        X509Certificate2Collection certCollection = store.Certificates;

        X509Certificate2 cert = null;

        // Loop through each certificate and find the certificate
        // with the appropriate name.
        foreach (X509Certificate2 c in certCollection) {
            if (c.SerialNumber == "65AF6AAF232BD7B64A170B0A7ABCF1CF") {
                cert = c;

                break;
            }
        }

        if (cert == null) {
            throw new CryptographicException("The X.509 certificate could not be found.");
        }

        // Close the store.
        store.Close();

        // Encrypt the "creditcard" element.
        Encrypt(xmlDoc, "creditcard", cert);

        // Save the XML document.
        xmlDoc.Save("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCrypto\\test-encrypted.xml");

        // Display the encrypted XML to the console.
        Console.WriteLine("Encrypted XML:");
        Console.WriteLine();
        Console.WriteLine(xmlDoc.OuterXml);
    }

    [Fact]
    public void Test2() {
        // Create an XmlDocument object.
        XmlDocument xmlDoc = new XmlDocument();

        // Load an XML file into the XmlDocument object.
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.Load("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCrypto\\test-encrypted.xml");

        // Decrypt the document.
        Decrypt(xmlDoc);

        // Save the XML document.
        xmlDoc.Save("C:\\Users\\const\\source\\repos\\Uncertain\\Certificate\\TestCrypto\\test-decrypted.xml");

        // Display the decrypted XML to the console.
        Console.WriteLine("Decrypted XML:");
        Console.WriteLine();
        Console.WriteLine(xmlDoc.OuterXml);
    }

    public static void Decrypt(XmlDocument Doc) {
        // Check the arguments.
        if (Doc == null)
            throw new ArgumentNullException("Doc");

        // Create a new EncryptedXml object.
        EncryptedXml exml = new EncryptedXml(Doc);

        // Decrypt the XML document.
        exml.DecryptDocument();
    }

    public static void Encrypt(XmlDocument Doc, string ElementToEncrypt, X509Certificate2 Cert) {
        // Check the arguments.
        if (Doc == null)
            throw new ArgumentNullException("Doc");
        if (ElementToEncrypt == null)
            throw new ArgumentNullException("ElementToEncrypt");
        if (Cert == null)
            throw new ArgumentNullException("Cert");

        ////////////////////////////////////////////////
        // Find the specified element in the XmlDocument
        // object and create a new XmlElement object.
        ////////////////////////////////////////////////

        XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementToEncrypt)[0] as XmlElement;
        // Throw an XmlException if the element was not found.
        if (elementToEncrypt == null) {
            throw new XmlException("The specified element was not found");
        }

        //////////////////////////////////////////////////
        // Create a new instance of the EncryptedXml class
        // and use it to encrypt the XmlElement with the
        // X.509 Certificate.
        //////////////////////////////////////////////////

        EncryptedXml eXml = new EncryptedXml();

        // Encrypt the element.
        EncryptedData edElement = eXml.Encrypt(elementToEncrypt, Cert);

        ////////////////////////////////////////////////////
        // Replace the element from the original XmlDocument
        // object with the EncryptedData element.
        ////////////////////////////////////////////////////
        EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
    }
}
