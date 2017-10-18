import java.io.IOException;
import java.io.PrintWriter;

import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;


public class Signature extends AbstractSignature {
	
	static public void sign() throws IOException {
		int rc;

	 XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		//dSigner.setLanguage("sk");

		XmlPlugin xmlPlugin = new XmlPlugin();
		DataObject xmlObject = xmlPlugin.createObject2(
				"XML1", 
				"XML", 
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xml"),
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xsd"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xml"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsd"), 
				"",
				"http://www.w3.org/2001/XMLSchema",
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xsl"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsl"),
				"http://www.w3.org/1999/XSL/Transform",
				"HTML");

		if (xmlObject == null) {
			System.out.println("XMLPlugin.createObject() errorMessage=" + xmlPlugin.getErrorMessage());
			return;
		}

		rc = dSigner.addObject(xmlObject);
		if (rc != 0) {
			System.out.println("XadesSig.addObject() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}

		rc = dSigner.sign20("signatureId20", "http://www.w3.org/2001/04/xmlenc#sha256", "urn:oid:1.3.158.36061701.1.2.1", "dataEnvelopeId",
				"dataEnvelopeURI", "dataEnvelopeDescr");
		if (rc != 0) {
			System.out.println("XadesSig.sign20() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			return;
		}		

		System.out.println(dSigner.getSignedXmlWithEnvelope());
		PrintWriter out = new PrintWriter("signedXml.xml");
		out.println(dSigner.getSignedXmlWithEnvelope());
		out.close();
		
	}
	
}
