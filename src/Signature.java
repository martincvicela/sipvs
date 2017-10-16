import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;

public class Signature {

	static public InputStream getResourceAsStream(String name) {
		String path = new File("resources", name).getPath();
		InputStream is = AbstractTest.class.getResourceAsStream(path);
		if (is == null) {
			throw new RuntimeException("Nepodarilo sa otvorit zdroj: " + path);
		}
		return is;
	}

	static public String readResource(String name) throws IOException {
		InputStream is = getResourceAsStream(name);
		byte[] data = new byte[is.available()];
		is.read(data);
		is.close();
		return new String(data, "UTF-8");
	}

	static public String readResourceAsBase64(String name) throws IOException {
		InputStream is = getResourceAsStream(name);
		byte[] data = new byte[is.available()];
		is.read(data);
		is.close();
		String msg = Base64.encode(data);
		return msg;

	}

	static public void writeFileFromBase64(String filename, String base64) throws IOException {
		String path = new File(System.getProperty("user.home"), filename).getAbsolutePath();
		FileOutputStream is = new FileOutputStream(path);
		try {
			is.write(Base64.decode(base64));
		} catch (Base64DecodingException e) {
			throw new RuntimeException(e);
		} finally {
			is.close();
		}
	}
	
	static public void sign() {
		int rc;

		final XadesSig dSigner = new XadesSig();
		dSigner.installLookAndFeel();
		dSigner.installSwingLocalization();
		dSigner.reset();
		//dSigner.setLanguage("sk");

		XmlPlugin xmlPlugin = new XmlPlugin();
		DataObject xmlObject = xmlPlugin.createObject("XML1", "XML", readResource("xml/UI_26_vin_neobmedz/form.108.xml"),
				readResource("xml/UI_26_vin_neobmedz/form.108.xsd"),
				"http://www.egov.sk/mvsr/NEV/datatypes/Zapis/Ext/PodanieZiadostiOPrihlasenieImporteromSoZepUI.1.0.xsd", "http://www.example.com/xml/sb",
				readResource("xml/UI_26_vin_neobmedz/form.108.sb.xslt"), "http://www.example.com/xml/sb");

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
	}
	
}
