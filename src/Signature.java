import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.sql.Timestamp;
import java.util.List;

import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class Signature extends AbstractSignature {
	
	public static String makeid() {
		  String text = "";
		  String possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

		  for (int i = 0; i < 5; i++)
		    text += possible.charAt((int)Math.floor(Math.random() * possible.length()));

		  return text;
		}
	
	static public void sign(List<String> documentNames) throws IOException {
		int count = 1;
		int rc = -1;		
		XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		//dSigner.setLanguage("sk");

		
		for (int i = 0; i < documentNames.size(); i++) {
			System.out.println(documentNames.get(i));
			XmlPlugin xmlPlugin = new XmlPlugin();
			DataObject xmlObject = xmlPlugin.createObject2(
					documentNames.get(i).replaceAll("[.]", ""), 
					MainGUI.nazov, 
					readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/" + documentNames.get(i)),
					readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsd"), 
					//readResource("c:/skola9/SIPVS/Git/sipvs/" + documentNames.get(i)),
					//readResource("c:/skola9/SIPVS/Git/sipvs/file.xsd"), 
					"",
					"http://www.w3.org/2001/XMLSchema",
					readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsl"),
					//readResource("c:/skola9/SIPVS/Git/sipvs/file.xsl"),
					"http://www.w3.org/1999/XSL/Transform",
					"HTML");

			if (xmlObject == null) {
				System.out.println("XMLPlugin.createObject() errorMessage=" + xmlPlugin.getErrorMessage());
				JOptionPane.showMessageDialog(null, xmlPlugin.getErrorMessage());
				return;
			}
			rc = dSigner.addObject(xmlObject);
		}
		
		if (rc != 0) {
			System.out.println("XadesSig.addObject() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			JOptionPane.showMessageDialog(null, dSigner.getErrorMessage());
			return;
		}

		rc = dSigner.sign20("SignId" + count, "http://www.w3.org/2001/04/xmlenc#sha256", "urn:oid:1.3.158.36061701.1.2.1", "dataEnvelopeId",
				"dataEnvelopeURI", "dataEnvelopeDescr");
		if (rc != 0) {
			System.out.println("XadesSig.sign20() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			JOptionPane.showMessageDialog(null, dSigner.getErrorMessage());
			return;
		}
		
		DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = null;
		InputSource source = new InputSource(new StringReader(dSigner.getSignedXmlWithEnvelope()));
		Document document = null;
		try {
			docBuilder = docFactory.newDocumentBuilder();
			document = docBuilder.parse(source);
		} catch (SAXException | ParserConfigurationException e) {
			e.printStackTrace();
		}

		//get TimeStampValue by Web Service
		String timeStampValue = getTimeStamp(document.getElementsByTagName("ds:SignatureValue").item(0).getTextContent());
		
		Element unsignedProperties = document.createElement("xades:UnsignedProperties");
		
		Element unsignedSignatureProperties = document.createElement("xades:UnsignedSignatureProperties");
		
		Element signatureTimestamp = document.createElement("xades:SignatureTimeStamp");
		signatureTimestamp.setAttribute("Id", "TSID" + count++);
		
		Element encapsulatedTimeStamp = document.createElement("xades:EncapsulatedTimeStamp");

		unsignedProperties.appendChild(unsignedSignatureProperties);
		unsignedSignatureProperties.appendChild(signatureTimestamp);
		signatureTimestamp.appendChild(encapsulatedTimeStamp);
		encapsulatedTimeStamp.appendChild(document.createTextNode(timeStampValue));
		document.getElementsByTagName("xades:QualifyingProperties").item(0).appendChild(unsignedProperties);
		
		try {
			//Generate XML file
			Source xmlSource = new DOMSource(document);
			Result result = new StreamResult(new FileOutputStream("signedWithStamp.xml"));
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty("indent", "yes");
			transformer.transform(xmlSource, result);
		} catch (TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	static public String getTimeStamp(String xmlData) {
		TimeStamp TimeClient = new TimeStamp();
		String timeStampString = TimeClient.getTS(xmlData);
		return timeStampString;
	}
	
}
