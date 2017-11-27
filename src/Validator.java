import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.signature.XMLSignature;

import sun.security.provider.certpath.OCSP;

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
	       /* overenie  elementov:
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
	        new Rule()
	        {
	       /* Core validation (podæa öpecifik·cie XML Signature) ñ overenie hodnoty podpisu ds:SignatureValue a referenciÌ v ds:SignedInfo:
			* dereferencovanie URI, kanonikaliz·cia referencovan˝ch ds:Manifest elementov a overenie hodnÙt odtlaËkov ds:DigestValue,
			* kanonikaliz·cia ds:SignedInfo a overenie hodnoty ds:SignatureValue pomocou pripojenÈho podpisovÈho certifik·tu v ds:KeyInfo,
	        */
	        	public String verifie() 
	        	{
	        		/*String returnValue = "";
	        		CertificateFactory cf;
	        		
					try {
						cf = CertificateFactory.getInstance("X.509");

		        	    FileInputStream in;
		        	    in = new FileInputStream("eeccrca.crl");
		        	    X509CRL crl = (X509CRL) cf.generateCRL(in);
		        	    Set s = crl.getRevokedCertificates();
		        	    
					} catch (CertificateException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}						
					catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CRLException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
	        	    
	        	    
	        		return "lol";*/
	        		// Validate the XMLSignature.
	        		/*try {
		        		// Find Signature element.

		        		// Find Signature element.
		        		NodeList nl =
		        		    parsedDoc.getElementsByTagNameNS("*", "Signature");
		        		if (nl.getLength() == 0) {
		        		    throw new Exception("Cannot find Signature element");
		        		}

		        		// Create a DOMValidateContext and specify a KeySelector
		        		// and document context.
		        		DOMValidateContext valContext = new DOMValidateContext
		        	            (new KeyValueKeySelector(), nl.item(0));

		        		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		        		// Unmarshal the XMLSignature.
		        		javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		        		
		        		
						boolean coreValidity = signature.validate(valContext);

						// Check core validation status.
						if (coreValidity == false) {
						    System.err.println("Signature failed core validation");
						    boolean sv = signature.getSignatureValue().validate(valContext);
						    System.out.println("signature validation status: " + sv);
						    if (sv == false) {
						        // Check the validation status of each Reference.
						        Iterator i = signature.getSignedInfo().getReferences().iterator();
						        for (int j=0; i.hasNext(); j++) {
						            boolean refValid = ((Reference) i.next()).validate(valContext);
						            System.out.println("ref["+j+"] validity status: " + refValid);
						        }
						    }
						} else {
						    System.out.println("Signature passed core validation");
						}
					} catch (XMLSignatureException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (MarshalException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					*/
	        		return "";
	        	}	 
	        },
	        new Rule()
	        {
	       /* Overenie Ëasovej peËiatky:
			* overenie platnosti podpisovÈho certifik·tu Ëasovej peËiatky voËi Ëasu UtcNow a voËi platnÈmu poslednÈmu CRL.
	        */
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();

	                X509CRL crl = getCrl();
	        		
	        		X509CertificateHolder signer = null;
	        		
	        		TimeStampToken token = getToken();
	        		
	        		Store<X509CertificateHolder> certHolders = token.getCertificates();
	        		ArrayList<X509CertificateHolder> certList = new ArrayList<>(certHolders.getMatches(null));

	        		BigInteger serialNumToken = token.getSID().getSerialNumber();
	        		X500Name issuerToken = token.getSID().getIssuer();

	        		for (X509CertificateHolder certHolder : certList) {
	        			if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)){
	        				signer = certHolder;
	        				break;
	        			}
	        		}

	        		if (signer == null){
	        			returnValue.append("Ch˝ba certifik·t Ëasovej peËiatky.");
	        		}

	        		if (!signer.isValidOn(new Date())){
	        			returnValue.append("Podpisov˝ certifik·t Ëasovej peËiatky nie je platn˝ voËi UtcNow Ëasu.");
	        		}

	        		if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
	        			returnValue.append("Podpisov˝ certifik·t Ëasovej peËiatky nie je platn˝ voËi platnÈmu poslednÈmu CRL.");
	        		}

	        		return returnValue.toString();
	        	}
	        },
	        new Rule()
	        {
	       /* Overenie Ëasovej peËiatky:
			* overenie MessageImprint z Ëasovej peËiatky voËi podpisu ds:SignatureValue
	        */
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		
	        		TimeStampToken token = getToken();
	        		
	        		byte[] messageImprint = token.getTimeStampInfo().getMessageImprintDigest();
	        		String hashAlg = token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

	        		byte[] signature = Base64.getDecoder().decode(parsedDoc.getElementsByTagName("xades:EncapsulatedTimeStamp").item(0).getTextContent().getBytes());
	        		
	        		MessageDigest messageDigest = null;
        			try {
						messageDigest = MessageDigest.getInstance(hashAlg, "BC");
						if (!MessageDigest.isEqual(messageImprint, messageDigest.digest(signature))){
		        			returnValue.append("MessageImprint z Ëasovej peËiatky a podpis ds:SignatureValue sa nezhoduj˙.");
		        		}
					} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
						returnValue.append("Zl˝ algoritmus v MD.");
					}
	        		
	        		return returnValue.toString();
	        	}
	        },
	        new Rule()
	        {
	       /* Overenie platnosti podpisovÈho certifik·tu:
			* overenie platnosti podpisovÈho certifik·tu dokumentu voËi Ëasu T z Ëasovej peËiatky a voËi platnÈmu poslednÈmu CRL.
	        */
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		
	        		X509CertificateObject cert = null;
	        		ASN1InputStream asn1is = null;
	        		X509CRL crl = getCrl();
	        		TimeStampToken token = getToken();
	        		
        			asn1is = new ASN1InputStream(new ByteArrayInputStream(Base64.getDecoder().decode(parsedDoc.getElementsByTagName("ds:X509Certificate").item(0).getTextContent())));
        			ASN1Sequence sq = null;
					try {
						sq = (ASN1Sequence) asn1is.readObject();
						cert = new X509CertificateObject(Certificate.getInstance(sq));
					} catch (IOException | CertificateParsingException e) {
						e.printStackTrace();
					} finally {
						try {
							asn1is.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}

					try {
						cert.checkValidity(token.getTimeStampInfo().getGenTime());
					} catch (CertificateExpiredException | CertificateNotYetValidException e) {
						returnValue.append("Certifik·t nie je platn˝ voËi Ëasu T z Ëasovej peËiatky.");
					}

	        		X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
	        		if (entry != null && entry.getRevocationDate().before(token.getTimeStampInfo().getGenTime())) {
	        			returnValue.append("Certifik·t nie je platn˝ voËi poslednÈmu CRL.");
	        		}

	        		return returnValue.toString();
	        	}
	        }
	    };
	
	public interface Rule{
	    public String verifie() throws XPathExpressionException; 
	}
	
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue)xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        //@@@FIXME: this should also work for key types other than DSA/RSA
        static boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
                return true;
            } else if (algName.equalsIgnoreCase("RSA") &&
                       algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
                return true;
            } else {
                return false;
            }
        }
    }
    
    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;
        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() { return pk; }
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
		InputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(X509Certificate.getTextContent()));
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
	
	private TimeStampToken getToken() {
		TimeStampToken token = null;
		try {
			token = new TimeStampToken(new CMSSignedData(Base64.getDecoder().decode
					(parsedDoc.getElementsByTagName("xades:EncapsulatedTimeStamp").item(0).getTextContent())));
		} catch (DOMException | TSPException | IOException | CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return token;
	}
	
	private X509CRL getCrl() {
		URL url = null;
        InputStream iStream = null;
        X509CRL crl = null;
		try {
        	url = new URL("http://test.ditec.sk/DTCCACrl/DTCCACrl.crl");	//cviËenie 2 - crl.txt, od nich m·me ten certifik·t
        	iStream = url.openStream();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            crl = (X509CRL) factory.generateCRL(iStream);
        } catch (CertificateException | IOException | CRLException e) {
			e.printStackTrace();
		} finally {
        	try {
				iStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
		return crl;
	}
	
		
	List<String> validate()
	{
		List<String> retList = new LinkedList<String>();
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
