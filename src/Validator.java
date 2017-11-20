import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class Validator {
	private  Document parsedDoc;
	private XPath xpath;
	
	private Rule[] rules = new Rule[] {
			
			/*
			 * Overenie d·tovej ob·lky:
			 * ï	koreÚov˝ element musÌ obsahovaù atrib˙ty xmlns:xzep a xmlns:ds 
			 * 		podæa profilu XADES_ZEP.
			 */
	        new Rule() 
	        { 
	        	public String verifie() throws XPathExpressionException 
	        	{
	        		Element e = (Element) xpath.evaluate("/*", parsedDoc, XPathConstants.NODE);
	        		if (e.getAttribute("xmlns:xzep").compareTo("http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0") == 0
	        				&& e.getAttribute("xmlns:ds").compareTo("http://www.w3.org/2000/09/xmldsig#") == 0)
	        		{
	        			return "";
	        		}
	        		return "koreÚov˝ element musÌ obsahovaù atrib˙ty xmlns:xzep a xmlns:ds podæa profilu XADES_ZEP";
	        	} 
	        },
	        /*
	         * Overenie XML Signature:
			 *	ï	kontrola obsahu ds:SignatureMethod a ds:CanonicalizationMethod 
			 *		ñ musia obsahovaù URI niektorÈho z podporovan˝ch algoritmov pre danÈ elementy 
			 *		podæa profilu XAdES_ZEP
	         */
	        new Rule()
	        { 
	        	public String verifie() throws XPathExpressionException 
	        	{ 
	        		String returnValue = ""; 
	        		Set<String> signatureMethods = getSignature();
	        		Set<String> canonicalizationMethods = getCanonicalization();
	        		Node e = parsedDoc.getElementsByTagName("ds:SignatureMethod").item(0);
	        		Node f = parsedDoc.getElementsByTagName("ds:CanonicalizationMethod").item(0);
	        		if (!signatureMethods.contains(e.getAttributes().getNamedItem("Algorithm").getNodeValue()))        				
	        		{
	        			returnValue += "kontrola obsahu ds:SignatureMethod musÌ obsahovaù URI niektorÈho z podporovan˝ch algoritmov pre danÈ elementy\n";
	        		}
	        		if (!canonicalizationMethods.contains(f.getAttributes().getNamedItem("Algorithm").getNodeValue()))
	        		{
	        			returnValue += "kontrola obsahu ds:CanonicalizationMethod musÌ obsahovaù URI niektorÈho z podporovan˝ch algoritmov pre danÈ elementy\n";
	        		}
	        		return returnValue;
	        	} 
	        },
	        /*
	         * Overenie XML Signature:
			 *	ï	kontrola obsahu ds:Transforms a ds:DigestMethod vo vöetk˝ch referenci·ch v ds:SignedInfo 
			 *		ñ musia obsahovaù URI niektorÈho z podporovan˝ch algoritmov podæa profilu XAdES_ZEP
			 * overenie ds:Manifest elementov:
			 *	ï	ds:Transforms musÌ byù z mnoûiny podporovan˝ch algoritmov pre dan˝ element podæa profilu XAdES_ZEP,
			 *	ï	ds:DigestMethod ñ musÌ obsahovaù URI niektorÈho z podporovan˝ch algoritmov podæa profilu XAdES_ZEP,
	         */
	        new Rule() 
	        { 
	        	public String verifie() 
	        	{ 
	        		String returnValue = "";
	        		Set<String> digestMethod = getDigest();	
	        		Set<String> transform = getTransform();
	        		
	        		NodeList e = parsedDoc.getElementsByTagName("ds:Transform");
	        		NodeList f = parsedDoc.getElementsByTagName("ds:DigestMethod");
	        		for (int i = 0; i < e.getLength(); i++) {
	        			if (!transform.contains(e.item(i).getAttributes().getNamedItem("Algorithm").getNodeValue())) 
	        			{
	        				if (e.item(i).getParentNode().getParentNode().getParentNode().getNodeName().compareTo("ds:Manifest") == 0) 
	        				{
	        					returnValue += "overenie ds:Manifest elementov: ds:Transforms musÌ byù z mnoûiny podporovan˝ch algoritmov pre dan˝ element podæa profilu XAdES_ZEP\n";
	        				}
	        				else if (e.item(i).getParentNode().getParentNode().getParentNode().getNodeName().compareTo("ds:SignedInfo") == 0) 
	        				{
	        					returnValue += "kontrola obsahu ds:Transforms vo vöetk˝ch referenci·ch v ds:SignedInfo musia obsahovaù URI niektorÈho z podporovan˝ch\n";
	        				}
	        			}
	        		}
	        		for (int i = 0; i < f.getLength(); i++) {
	        			if (!digestMethod.contains(f.item(i).getAttributes().getNamedItem("Algorithm").getNodeValue())) 
	        			{
	        				if (f.item(i).getParentNode().getParentNode().getNodeName().compareTo("ds:Manifest") == 0) {
	        					returnValue += "overenie ds:Manifest elementov: ds:DigestMethod ñ musÌ obsahovaù URI niektorÈho z podporovan˝ch algoritmov podæa profilu XAdES_ZEP\n";
	        				}
	        				else if (f.item(i).getParentNode().getParentNode().getNodeName().compareTo("ds:SignedInfo") == 0)
	        				{
	        					returnValue += "kontrola obsahu ds:DigestMethod vo vöetk˝ch referenci·ch v ds:SignedInfo musia obsahovaù URI niektorÈho z podporovan˝ch\n";
	        				}
	        			}
	        		}
	        		return returnValue;
	        	} 
	        },
	        new Rule()
	        {
	        	/*Core validation (podæa öpecifik·cie XML Signature) ñ overenie hodnoty podpisu ds:SignatureValue a referenciÌ v ds:SignedInfo:
	        		-	dereferencovanie URI, kanonikaliz·cia referencovan˝ch ds:Manifest elementov a overenie hodnÙt odtlaËkov ds:DigestValue,
	        		-	kanonikaliz·cia ds:SignedInfo a overenie hodnoty ds:SignatureValue pomocou pripojenÈho podpisovÈho certifik·tu v ds:KeyInfo,*/
	        	public String verifie() 
	        	{
	        		//under construction
	        		return "";
	        	}
	        	
	        },
	        new Rule()
	        {
	        	/*ds:Signature:
				ï	musÌ maù Id atrib˙t,
				ï	musÌ maù öpecifikovan˝ namespace xmlns:ds,
				*/
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		Node e = parsedDoc.getElementsByTagName("ds:Signature").item(0).getAttributes().getNamedItem("Id");
	        		Node f = parsedDoc.getElementsByTagName("ds:Signature").item(0).getAttributes().getNamedItem("xmlns:ds");
	        		if (e == null) {
	        			returnValue += "ds:Signature musÌ maù Id atrib˙t\n";
	        		}
	        		if (f == null || f.getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#") != 0) {
	        			returnValue += "ds:Signature musÌ maù öpecifikovan˝ namespace xmlns:ds\n";
	        		}	        				        		
	        		return returnValue;
	        	}
	        	
	        },
	        new Rule()
	        {
	        	// ds:SignatureValue ñ musÌ maù Id atrib˙t
	        	
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		Node e = parsedDoc.getElementsByTagName("ds:SignatureValue").item(0).getAttributes().getNamedItem("Id");
	        		if (e == null) {
	        			returnValue += "ds:SignatureValue ñ musÌ maù Id atrib˙t\n";
	        		}        				        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	        	/* overenie existencie referenciÌ v ds:SignedInfo a hodnÙt atrib˙tov Id a Type voËi profilu XAdES_ZEP pre:
				*	ï	ds:KeyInfo element,
				*	ï	ds:SignatureProperties element,
				*	ï	xades:SignedProperties element,
				*	ï	vöetky ostatnÈ referencie v r·mci ds:SignedInfo musia byù referenciami na ds:Manifest elementy
				* ds:KeyInfo:
				*	ï	musÌ maù Id atrib˙t,
				* ds:SignatureProperties:
				*	ï	musÌ maù Id atrib˙t,
				* xades:SignedProperties:
				*	ï	musÌ maù Id atrib˙t,
				* ds:Manifest:
				*	ï	kaûd˝ ds:Manifest element musÌ maù Id atrib˙t
	        	*/
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		NodeList e = parsedDoc.getElementsByTagName("ds:SignedInfo").item(0).getChildNodes();
	        		NodeList f = parsedDoc.getElementsByTagName("ds:Manifest");
	        		Set<String> manifestsIds = new HashSet<String>();
	        		for (int i = 0; i < f.getLength(); i++) { 		
	        			String manifestsId = f.item(i).getAttributes().getNamedItem("Id").getNodeValue();
	        			if (manifestsId != null) 
	        			{
	        				manifestsIds.add(manifestsId); 
	        			}
	        			else 
	        			{
	        				returnValue += "kaûd˝ ds:Manifest element musÌ maù Id atrib˙t\n";
	        			}
	        		}
	        		boolean KeyInfo = false;
	        		boolean SignatureProperties  = false;
	        		boolean SignedProperties  = false;
	        		
        			for (int i = 0; i < e.getLength(); i++) {
	        			if (e.item(i).getNodeName().compareTo("ds:Reference") == 0) {
		        			if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#Object") == 0) 
		        			{
		        				String keyInfoId = parsedDoc.getElementsByTagName("ds:KeyInfo").item(0).getAttributes().getNamedItem("Id").getNodeValue();
		        				if (keyInfoId == null) 
		        				{
		        					returnValue += "ds:KeyInfo musÌ maù Id atrib˙t\n";
		        				}
		        				String referenceURI = e.item(i).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
		        				if (referenceURI != null && keyInfoId.compareTo(referenceURI) == 0) 
		        				{
		        					KeyInfo = true;
		        				}
		        			}
		        			else if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#SignatureProperties") == 0) 
		        			{
		        				String signaturePropertiesId = parsedDoc.getElementsByTagName("ds:SignatureProperties").item(0).getAttributes().getNamedItem("Id").getNodeValue();
		        				if (signaturePropertiesId == null) 
		        				{
		        					returnValue += "ds:SignatureProperties musÌ maù Id atrib˙t\n";
		        				}
		        				String referenceURI = e.item(i).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
		        				if (referenceURI != null && signaturePropertiesId.compareTo(referenceURI) == 0) 
		        				{
		        					SignatureProperties = true;
		        				}    				
		        			}
		        			else if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://uri.etsi.org/01903#SignedProperties") == 0) 
		        			{
		        				String signedPropertiesId = parsedDoc.getElementsByTagName("xades:SignedProperties").item(0).getAttributes().getNamedItem("Id").getNodeValue();
		        				if (signedPropertiesId == null) 
		        				{
		        					returnValue += "xades:SignedProperties musÌ maù Id atrib˙t\n";
		        				}
		        				String referenceURI = e.item(i).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
		        				if (referenceURI != null && signedPropertiesId.compareTo(referenceURI) == 0) 
		        				{
		        					SignedProperties = true;
		        				}    				        				
		        			}
		        			else if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#Manifest") == 0) 
		        			{
		        				String referenceURI = e.item(i).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
		        				if (referenceURI == null) 
		        				{
		        					returnValue += "neplatn· referencia na ds:Manifest element\n";
		        				}
		        				else if (!manifestsIds.contains(referenceURI)) 
		        				{
		        					returnValue += "neplatn· referencia na ds:Manifest element\n";
		        				}    		 
		        			}
		        			else 
		        			{
		        				returnValue += "vöetky ostatnÈ referencie v r·mci ds:SignedInfo musia byù referenciami na ds:Manifest elementy\n";
		        			}
	        			}
	        		}
	        		if (!KeyInfo) 
	        		{
	        			returnValue += "neplatn· referencia na ds:KeyInfo element\n";
	        		}
	        		if (!SignatureProperties) 
	        		{
	        			returnValue += "neplatn· referencia na ds:SignatureProperties element\n";
	        		}
	        		if (!SignedProperties) 
	        		{
	        			returnValue += "neplatn· referencia na xades:SignedProperties element\n";
	        		}        			        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
        	/*	overenie obsahu ds:KeyInfo:
    		 *	ï	musÌ obsahovaù ds:X509Data, ktor˝ obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName,
    		 *	ï	hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName s˙hlasia s prÌsluön˝mi hodnatami v certifik·te, ktor˝ sa nach·dza v ds:X509Certificate,
    		 */
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		Node X509Certificate = null, X509IssuerSerial = null, X509SubjectName = null;
	        		Node e = parsedDoc.getElementsByTagName("ds:X509Data").item(0);
	        		if (e != null && e.getParentNode().getNodeName().compareTo("ds:KeyInfo") == 0) {
	        			NodeList f = e.getChildNodes();
	        			for (int i = 0; i < f.getLength(); i++) {
	        				if (f.item(i).getNodeName().compareTo("ds:X509Certificate") == 0) 
	        				{
	        					X509Certificate = f.item(i);
	        				}
	        				else if (f.item(i).getNodeName().compareTo("ds:X509IssuerSerial") == 0) 
	        				{
	        					X509IssuerSerial = f.item(i);
	        				}
	        				else if (f.item(i).getNodeName().compareTo("ds:X509SubjectName") == 0) 
	        				{
	        					X509SubjectName = f.item(i);
	        				}
	        			}
	        			if (X509Certificate == null || X509IssuerSerial == null || X509SubjectName == null) {
	        				returnValue += "ds:KeyInfo musÌ obsahovaù ds:X509Data, ktor˝ obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName\n";
	        			}
	        			else {
	        				try {
	        					String X509IssuerName = X509IssuerSerial.getFirstChild().getTextContent();
	        					String X509SerialNumber = X509IssuerSerial.getLastChild().getTextContent();
								X509CertificateObject certificate = loadCertificate(X509Certificate);
								String cIssuerName = certificate.getIssuerX500Principal().toString().replace("ST", "S");
								String cSerialNumber = certificate.getSerialNumber().toString();
								String cSubjectName = certificate.getSubjectX500Principal().toString();
								if (X509IssuerName == null 
										|| X509SerialNumber == null 
										|| X509IssuerName.compareTo(cIssuerName) != 0 
										|| X509SerialNumber.compareTo(cSerialNumber) != 0
										|| X509SubjectName.getTextContent().compareTo(cSubjectName) != 0) 
								{
									returnValue += "hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName s˙hlasia s prÌsluön˝mi hodnatami v certifik·te, ktor˝ sa nach·dza v ds:X509Certificate\n";
								}
							} catch (IOException e1) {
								e1.printStackTrace();
							} catch (GeneralSecurityException e1) {
								e1.printStackTrace();
							}	
	        			}
	        		}
	        		else 
	        		{
	        			returnValue += "ds:KeyInfo musÌ obsahovaù ds:X509Data\n";
	        		}
	        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	       /*	overenie obsahu ds:SignatureProperties:
			*	ï	musÌ obsahovaù dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos,
			*	ï	obidva ds:SignatureProperty musia maù atrib˙t Target nastaven˝ na ds:Signature,
	        */
	        	public String verifie() 
	        	{
	        		String returnValue = "";	
	        		NodeList e = parsedDoc.getElementsByTagName("ds:SignatureProperty");
	        		if (e != null 
	        				&& e.getLength() == 2 
	        				&& e.item(0).getParentNode().getNodeName().compareTo("ds:SignatureProperties") == 0 
	        				&& e.item(1).getParentNode().getNodeName().compareTo("ds:SignatureProperties") == 0) 
	        		{
	        			Node property1 = e.item(0);
	        			Node property2 = e.item(1);
	        			if (property1.getFirstChild().getNodeName().compareTo("xzep:SignatureVersion") == 0
	        					&& property2.getFirstChild().getNodeName().compareTo("xzep:ProductInfos") == 0
	        					|| property1.getFirstChild().getNodeName().compareTo("xzep:ProductInfos") == 0
	        					&& property2.getFirstChild().getNodeName().compareTo("xzep:SignatureVersion") == 0)
	        			{
	        				String signatureId = parsedDoc.getElementsByTagName("ds:Signature").item(0).getAttributes().getNamedItem("Id").getNodeValue();
	        				String property1Target = property1.getAttributes().getNamedItem("Target").getNodeValue().substring(1);
	        				String property2Target = property1.getAttributes().getNamedItem("Target").getNodeValue().substring(1);
	        				if (!(signatureId != null && property1Target != null && property2Target != null
	        						&& signatureId.compareTo(property1Target) == 0
	        						&& signatureId.compareTo(property2Target) == 0)) 
	        				{
	        					System.out.println(signatureId);
	        					System.out.println(property1Target);
	        					System.out.println(property2Target);
	        					returnValue += "obidva ds:SignatureProperty musia maù atrib˙t Target nastaven˝ na ds:Signature";
	        				}
	        			}
	        			else 
	        			{
	        				returnValue += "ds:SignatureProperties musÌ obsahovaù dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos\n";
	        			}
	        		}
	        		else 
	        		{
	        			returnValue += "ds:SignatureProperties musÌ obsahovaù dva elementy ds:SignatureProperty\n";
	        		}
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	       /* overenie ds:Manifest elementov:
			*	ï	overenie hodnoty Type atrib˙tu voËi profilu XAdES_ZEP,
			*	ï	kaûd˝ ds:Manifest element musÌ obsahovaù pr·ve jednu referenciu na ds:Object,
	        */
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		NodeList manifests = parsedDoc.getElementsByTagName("ds:Manifest");
	        		
	        		if (manifests != null) {
		        		for(int i = 0; i < manifests.getLength(); i++) {
		        			NodeList childrens = manifests.item(i).getChildNodes();
		        			int references = 0;
		        			for (int j = 0; j < childrens.getLength(); j++) {
		        				if (childrens.item(j).getNodeName().compareTo("ds:Reference") == 0) 
		        				{
		        					references++;
		        					if (childrens.item(j).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#Object") != 0) 
		        					{
		        						returnValue += "overenie hodnoty Type atrib˙tu voËi profilu XAdES_ZEP\n";
		        					}
		        				}
		        			}
		        			if (references != 1) {
		        				returnValue += "kaûd˝ ds:Manifest element musÌ obsahovaù pr·ve jednu referenciu na ds:Object\n";
		        			}
		        		}	
	        		}
	        		else 
	        		{
	        			returnValue += "overenie ds:Manifest elementov - element neexistuje\n";
	        		}
	        		
	        		return returnValue;
	        	}        	
	        },
	    };

	public interface Rule{
	    public String verifie() throws XPathExpressionException; 
	}
	
	//maybe this is not good idea, someday I will check for it
	Validator(File xmlFile) throws ParserConfigurationException, SAXException, IOException
	{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		parsedDoc = builder.parse(xmlFile);
		xpath = XPathFactory.newInstance().newXPath();
	}
	
	//inspired by https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.jce.provider.X509CertificateObject
	
	private X509CertificateObject loadCertificate(Node X509Certificate) throws IOException, GeneralSecurityException {
		InputStream in = new ByteArrayInputStream(Base64.decode(X509Certificate.getTextContent()));
	    ASN1InputStream derin = new ASN1InputStream(in);
	    ASN1Primitive certInfo = derin.readObject();
	    derin.close();
	    ASN1Sequence seq = ASN1Sequence.getInstance(certInfo);
	    return new X509CertificateObject(Certificate.getInstance(seq));
	}
	
	private Set<String> getDigest () { 
		Set<String> digestMethod = new HashSet<String>();	
		digestMethod.add("http://www.w3.org/2000/09/xmldsig#sha1");
		digestMethod.add("http://www.w3.org/2001/04/xmldsig-more#sha224");
		digestMethod.add("http://www.w3.org/2001/04/xmlenc#sha256");
		digestMethod.add("http://www.w3.org/2001/04/xmldsig-more#sha384");
		digestMethod.add("http://www.w3.org/2001/04/xmlenc#sha512");
		
		return digestMethod;
	}
	
	private Set<String> getTransform() {
		Set<String> transform = new HashSet<String>();
		transform.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		
		return transform;
	}
	
	private Set<String> getSignature() {
		Set<String> signatureMethods = new HashSet<String>();
		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#dsa-sha1"); 
		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		
		return signatureMethods;
	}
	
	private Set<String> getCanonicalization() {
		Set<String> canonicalizationMethods = new HashSet<String>();
		canonicalizationMethods.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		
		return canonicalizationMethods;
	}
	
		
	List<String> validate()
	{
		List<String> retList = new LinkedList<String>();;
		for(int i = 0; i< rules.length; i++)
		{
			try {
				String tmp = rules[i].verifie();
				if(!("".equals(tmp)))
				{
					retList.add(tmp);
				}
			} catch (XPathExpressionException e) {
				e.printStackTrace();
			}
		}
		return retList;
	}
}
