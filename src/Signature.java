import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.UUID;

import javax.swing.JOptionPane;

import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;


public class Signature extends AbstractSignature {
	
	private static String makeid() {
		  String text = "";
		  String possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

		  for (int i = 0; i < 5; i++)
		    text += possible.charAt((int)Math.floor(Math.random() * possible.length()));

		  return text;
		}
	
	static public void sign() throws IOException {
		int rc;

	 XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		//dSigner.setLanguage("sk");

		XmlPlugin xmlPlugin = new XmlPlugin();
		DataObject xmlObject = xmlPlugin.createObject2(
				"b", 
				MainGUI.nazov, 
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
			JOptionPane.showMessageDialog(null, xmlPlugin.getErrorMessage());
			return;
		}
		
		DataObject xmlObject2 = xmlPlugin.createObject2(
				"a", 
				MainGUI.nazov, 
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xml"),
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xsd"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file2.xml"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsd"), 
				"",
				"http://www.w3.org/2001/XMLSchema",
				//readResource("C:/skola9/SIPVS/Git/sipvs/file.xsl"),
				readResource("C:/Users/mato1/OneDrive/SIPVS/zadanie/file.xsl"),
				"http://www.w3.org/1999/XSL/Transform",
				"HTML");

		if (xmlObject2 == null) {
			System.out.println("XMLPlugin.createObject() errorMessage=" + xmlPlugin.getErrorMessage());
			JOptionPane.showMessageDialog(null, xmlPlugin.getErrorMessage());
			return;
		}
		
		UUID randomID = UUID.randomUUID();
		rc = dSigner.addObject(xmlObject);
		rc = dSigner.addObject(xmlObject2);
		
		if (rc != 0) {
			System.out.println("XadesSig.addObject() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			JOptionPane.showMessageDialog(null, dSigner.getErrorMessage());
			return;
		}

		rc = dSigner.sign20(makeid(), "http://www.w3.org/2001/04/xmlenc#sha256", "urn:oid:1.3.158.36061701.1.2.1", "dataEnvelopeId",
				"dataEnvelopeURI", "dataEnvelopeDescr");
		if (rc != 0) {
			System.out.println("XadesSig.sign20() errorCode=" + rc + ", errorMessage=" + dSigner.getErrorMessage());
			JOptionPane.showMessageDialog(null, dSigner.getErrorMessage());
			return;
		}		

		System.out.println(dSigner.getSignedXmlWithEnvelope());
		PrintWriter out = new PrintWriter("signedXml.xml");
		out.println(dSigner.getSignedXmlWithEnvelope());
		out.close();		
	}
	
}
