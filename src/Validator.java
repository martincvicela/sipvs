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
import java.security.Security;
import java.security.SignatureException;
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
import java.util.Map;
import java.util.Set;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

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
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.signature.XMLSignature;

import sun.security.provider.certpath.OCSP;

public class Validator {
	private  Document parsedDoc;
	private XPath xpath;
	
	//everything
	//https://www.ditec.sk/ep/signature_formats/xades_zep/v1.1/GOV_ZEP.75.3.170522.Profil_XAdES_ZEP_v1.1_-_format_ZEP_na_baze_XAdES.PDF
	
	private Rule[] rules = new Rule[] {
			
			/*
			 * Overenie d�tovej ob�lky:
			 * �	kore�ov� element mus� obsahova� atrib�ty xmlns:xzep a xmlns:ds 
			 * 		pod�a profilu XADES_ZEP.
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
	        		return "kore�ov� element mus� obsahova� atrib�ty xmlns:xzep a xmlns:ds pod�a profilu XADES_ZEP";
	        	} 
	        },
	        /*
	         * Overenie XML Signature:
			 *	�	kontrola obsahu ds:SignatureMethod a ds:CanonicalizationMethod 
			 *		� musia obsahova� URI niektor�ho z podporovan�ch algoritmov pre dan� elementy 
			 *		pod�a profilu XAdES_ZEP
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
	        			returnValue += "kontrola obsahu ds:SignatureMethod mus� obsahova� URI niektor�ho z podporovan�ch algoritmov pre dan� elementy\n";
	        		}
	        		if (!canonicalizationMethods.contains(f.getAttributes().getNamedItem("Algorithm").getNodeValue()))
	        		{
	        			returnValue += "kontrola obsahu ds:CanonicalizationMethod mus� obsahova� URI niektor�ho z podporovan�ch algoritmov pre dan� elementy\n";
	        		}
	        		return returnValue;
	        	} 
	        },
	        /*
	         * Overenie XML Signature:
			 *	�	kontrola obsahu ds:Transforms a ds:DigestMethod vo v�etk�ch referenci�ch v ds:SignedInfo 
			 *		� musia obsahova� URI niektor�ho z podporovan�ch algoritmov pod�a profilu XAdES_ZEP
			 * overenie ds:Manifest elementov:
			 *	�	ds:Transforms mus� by� z mno�iny podporovan�ch algoritmov pre dan� element pod�a profilu XAdES_ZEP,
			 *	�	ds:DigestMethod � mus� obsahova� URI niektor�ho z podporovan�ch algoritmov pod�a profilu XAdES_ZEP,
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
	        					returnValue += "overenie ds:Manifest elementov: ds:Transforms mus� by� z mno�iny podporovan�ch algoritmov pre dan� element pod�a profilu XAdES_ZEP\n";
	        				}
	        				else if (e.item(i).getParentNode().getParentNode().getParentNode().getNodeName().compareTo("ds:SignedInfo") == 0) 
	        				{
	        					returnValue += "kontrola obsahu ds:Transforms vo v�etk�ch referenci�ch v ds:SignedInfo musia obsahova� URI niektor�ho z podporovan�ch\n";
	        				}
	        			}
	        		}
	        		for (int i = 0; i < f.getLength(); i++) {
	        			if (!digestMethod.contains(f.item(i).getAttributes().getNamedItem("Algorithm").getNodeValue())) 
	        			{
	        				if (f.item(i).getParentNode().getParentNode().getNodeName().compareTo("ds:Manifest") == 0) {
	        					returnValue += "overenie ds:Manifest elementov: ds:DigestMethod � mus� obsahova� URI niektor�ho z podporovan�ch algoritmov pod�a profilu XAdES_ZEP\n";
	        				}
	        				else if (f.item(i).getParentNode().getParentNode().getNodeName().compareTo("ds:SignedInfo") == 0)
	        				{
	        					returnValue += "kontrola obsahu ds:DigestMethod vo v�etk�ch referenci�ch v ds:SignedInfo musia obsahova� URI niektor�ho z podporovan�ch\n";
	        				}
	        			}
	        		}
	        		return returnValue;
	        	} 
	        },
	        new Rule()
	        {
	        	/*Core validation (pod�a �pecifik�cie XML Signature) � overenie hodnoty podpisu ds:SignatureValue a referenci� v ds:SignedInfo:
	        		-	dereferencovanie URI, kanonikaliz�cia referencovan�ch ds:Manifest elementov a overenie hodn�t odtla�kov ds:DigestValue*/
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		
	        		Element signatureElement = (Element) parsedDoc.getElementsByTagName("ds:Signature").item(0);
	        		Element signatureInfoElement = (Element) signatureElement.getElementsByTagName("ds:SignedInfo").item(0);
	        		NodeList referenceElements =  signatureInfoElement.getElementsByTagName("ds:Reference");
	        		
	        		int i = 0;
	        		while (i<referenceElements.getLength()){
	        			Element refElement = (Element) referenceElements.item(i);
	        			
	        			XPath xpath = XPathFactory.newInstance().newXPath();
	        			NodeList nodeList = null;
						try {
							nodeList = (NodeList) xpath.compile("//*[@Id='" + refElement.getAttribute("URI").substring(1) + "']")
									.evaluate(parsedDoc, XPathConstants.NODESET);
						} catch (XPathExpressionException e1) {
							e1.printStackTrace();
						}
	        			
	        			if (nodeList.getLength() == 0) {
	        				returnValue.append("Ne�spe�n� dereferencovanie URI: " + refElement.getAttribute("URI").substring(1)+ "\n");
	        			}
	        			
	        			Element manEl = null;
	        			
	        			//dereferencovanie URI pre manifest
	        			NodeList allManifests =  parsedDoc.getElementsByTagName("ds:Manifest");
	        			for (int k=0;k<allManifests.getLength();k++) {
	        				Element manifest = (Element) allManifests.item(k);
	        				if (manifest.hasAttribute("Id") && refElement.getAttribute("URI").substring(1).equals(manifest.getAttribute("Id"))) {
	        					manEl = manifest;
	        				}
	        			}
	        				
	        			if (manEl == null) {
	        			} else {
	        			
		        			Element digestMethodElement = (Element) refElement.getElementsByTagName("ds:DigestMethod").item(0);
		        			
		        			//4.5 identifik�tory MD
		        			Map<String, String> possibleDM = new HashMap<String, String>();
		        			possibleDM.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
		        			possibleDM.put("http://www.w3.org/2001/04/xmldsigmore#sha224", "SHA-224");
		        			possibleDM.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
		        			possibleDM.put("http://www.w3.org/2001/04/xmldsigmore#sha384", "SHA-384");
		        			possibleDM.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
		        			
		        			if (!possibleDM.containsKey(digestMethodElement.getAttribute("Algorithm"))) {
		        				returnValue.append("Core valid�cia: Element ds:DigestMethod v reference elemente obsahuje nepodporovan� algoritmus.\n");
		        			}
		        			
		        			DOMImplementationLS lsImpl = (DOMImplementationLS)manEl.getOwnerDocument().getImplementation().getFeature("LS", "3.0");
		        			LSSerializer serializer = lsImpl.createLSSerializer();
		        			serializer.getDomConfig().setParameter("xml-declaration", false);
		        			byte[] manElBytes = serializer.writeToString(manEl).getBytes();
		        			
		        			NodeList transformsList = manEl.getElementsByTagName("ds:Transforms");
		        			
		        			int j = 0;
		        			while (j<transformsList.getLength()) {
		        				
		        				Element listItem = (Element) transformsList.item(j);
		        				Element transElem = (Element) listItem.getElementsByTagName("ds:Transform").item(0);
		        				
		        				org.apache.xml.security.Init.init();
		        				
		        				if (transElem.getAttribute("Algorithm").equals(getTransformString())) {
		        					Canonicalizer c;
		        					try {
		        						c = Canonicalizer.getInstance(transElem.getAttribute("Algorithm"));
		        						manElBytes = c.canonicalize(manElBytes);
		        					} catch (Exception e) {
		        						returnValue.append("Core valid�cia: Nepodarilo sa kanonikalizova� manifest element.\n");
		        					}
		        				} else {
		        					returnValue.append("Core valid�cia: Nepodporovan� transforma�n� met�da.\n");
		        				}
		        				j++;
		        			}
		        			
		        			MessageDigest messageDigest = null;
		        			
		        			try {
		        				messageDigest = MessageDigest.getInstance(possibleDM.get(digestMethodElement.getAttribute("Algorithm")));
		        				
		        			} catch (NoSuchAlgorithmException e) {
		        				returnValue.append("Core valid�cia: Nepodporovan� DM algoritmus.\n");
		        			}
		        			
		        			//podpis, expected vs actual
		        			if (refElement.getElementsByTagName("ds:DigestValue").item(0).getTextContent()
		        					.equals(new String(Base64.getEncoder().encode(messageDigest.digest(manElBytes)))) == false) {
		        				returnValue.append("Core valid�cia: Porovn�van� odtla�ky sa nerovnaj�.\n");
		        			}
	        			}
	        			i++;
	        		}

	        		return returnValue.toString();
	        	}
	        	
	        },
	        new Rule()
	        {
	        	/*Core validation (pod�a �pecifik�cie XML Signature) � overenie hodnoty podpisu ds:SignatureValue a referenci� v ds:SignedInfo:
	        		-	kanonikaliz�cia ds:SignedInfo a overenie hodnoty ds:SignatureValue pomocou pripojen�ho podpisov�ho certifik�tu v ds:KeyInfo,*/
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		Element sigElem = (Element) parsedDoc.getElementsByTagName("ds:Signature").item(0);
	        		Element sigValElem = (Element) sigElem.getElementsByTagName("ds:SignatureValue").item(0);
	        		
	        		Element sigInfElem = (Element) sigElem.getElementsByTagName("ds:SignedInfo").item(0);
	        		Element canonnMethodElem = (Element) sigInfElem.getElementsByTagName("ds:CanonicalizationMethod").item(0);
	        		Element sigMethodElem = (Element) sigInfElem.getElementsByTagName("ds:SignatureMethod").item(0);
	        		
	        		DOMImplementationLS lsImpl = (DOMImplementationLS)sigInfElem.getOwnerDocument().getImplementation().getFeature("LS", "3.0");
        			LSSerializer serializer = lsImpl.createLSSerializer();
        			serializer.getDomConfig().setParameter("xml-declaration", false);
        			byte[] sigInfElBytes = serializer.writeToString(sigInfElem).getBytes();
	        		
        			org.apache.xml.security.Init.init();
        			
        			Canonicalizer c;
	        		try {
	        			c = Canonicalizer.getInstance(canonnMethodElem.getAttribute("Algorithm"));
	        			sigInfElBytes = c.canonicalize(sigInfElBytes);
	        			
	        		} catch (Exception e) {
	        			System.out.println(e);
						returnValue.append("Core valid�cia: Nepodarilo sa kanonikalizova� SignatureInfo element.\n");
					}
	        		
	        		//ziskaj certifik�t
	        		X509CertificateObject cert = null;
	        		ASN1InputStream asn1is = null;
        			ASN1Sequence sq = null;
					try {
						asn1is = new ASN1InputStream(new ByteArrayInputStream(Base64.getDecoder().decode(parsedDoc.getElementsByTagName("ds:X509Certificate").item(0).getTextContent())));
						sq = (ASN1Sequence) asn1is.readObject();
						cert = new X509CertificateObject(Certificate.getInstance(sq));
					} catch (IOException | CertificateParsingException e) {
						returnValue.append("Core valid�cia: Nepodarilo sa n�js� certifik�t v elemente KeyInfo.\n");
					} finally {
						try {
							asn1is.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}

	        		//4.5 identifik�tory signature method
        			Map<String, String> possibleSM = new HashMap<String, String>();
        			possibleSM.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
        			possibleSM.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA/ISO9796-2");
        			possibleSM.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
        			possibleSM.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
        			possibleSM.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
	        		
        			java.security.Signature signer = null;
	        		try {
	        			Security.addProvider(new BouncyCastleProvider());
	        			signer = java.security.Signature.getInstance(possibleSM.get(sigMethodElem.getAttribute("Algorithm")));
	        			signer.initVerify(cert.getPublicKey());
	        			signer.update(sigInfElBytes);
	        			
	        		} catch (Exception e) {
	        			returnValue.append("Core valid�cia: ds:SignatureMethod obsahuje neplatn� algoritmus, preto sa nepodarilo inicializova� tvorbu overovacieho podpisu .\n");
	        		}
	        		
	        		if (signer != null) {
		        		boolean verificatedGood = false;
		        		
		        		try {
		        			verificatedGood = signer.verify(Base64.getDecoder().decode(sigValElem.getTextContent().getBytes()));
		        		} catch (SignatureException e) {
		        			returnValue.append("Core valid�cia: Nepodarilo sa verifikova� podpis.\n");
		        		}
		        		
		        		if (verificatedGood == false) {
		        			returnValue.append("Core valid�cia: Podp�san� SignedInfo a SignatureValue sa nezhoduj�.\n");
		        		}
	        		}
	        		return returnValue.toString();
	        	}
	        	
	        },
	        new Rule()
	        {
	        	/*ds:Signature:
				�	mus� ma� Id atrib�t,
				�	mus� ma� �pecifikovan� namespace xmlns:ds,
				*/
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		Node e = parsedDoc.getElementsByTagName("ds:Signature").item(0).getAttributes().getNamedItem("Id");
	        		Node f = parsedDoc.getElementsByTagName("ds:Signature").item(0).getAttributes().getNamedItem("xmlns:ds");
	        		if (e == null) {
	        			returnValue += "ds:Signature mus� ma� Id atrib�t\n";
	        		}
	        		if (f == null || f.getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#") != 0) {
	        			returnValue += "ds:Signature mus� ma� �pecifikovan� namespace xmlns:ds\n";
	        		}	        				        		
	        		return returnValue;
	        	}
	        	
	        },
	        new Rule()
	        {
	        	// ds:SignatureValue � mus� ma� Id atrib�t
	        	
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		Node e = parsedDoc.getElementsByTagName("ds:SignatureValue").item(0).getAttributes().getNamedItem("Id");
	        		if (e == null) {
	        			returnValue += "ds:SignatureValue � mus� ma� Id atrib�t\n";
	        		}        				        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	        	/* overenie existencie referenci� v ds:SignedInfo a hodn�t atrib�tov Id a Type vo�i profilu XAdES_ZEP pre:
				*	�	ds:KeyInfo element,
				*	�	ds:SignatureProperties element,
				*	�	xades:SignedProperties element,
				*	�	v�etky ostatn� referencie v r�mci ds:SignedInfo musia by� referenciami na ds:Manifest elementy
				* ds:KeyInfo:
				*	�	mus� ma� Id atrib�t,
				* ds:SignatureProperties:
				*	�	mus� ma� Id atrib�t,
				* xades:SignedProperties:
				*	�	mus� ma� Id atrib�t,
				* ds:Manifest:
				*	�	ka�d� ds:Manifest element mus� ma� Id atrib�t
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
	        				returnValue += "ka�d� ds:Manifest element mus� ma� Id atrib�t\n";
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
		        					returnValue += "ds:KeyInfo mus� ma� Id atrib�t\n";
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
		        					returnValue += "ds:SignatureProperties mus� ma� Id atrib�t\n";
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
		        					returnValue += "xades:SignedProperties mus� ma� Id atrib�t\n";
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
		        					returnValue += "neplatn� referencia na ds:Manifest element\n";
		        				}
		        				else if (!manifestsIds.contains(referenceURI)) 
		        				{
		        					returnValue += "neplatn� referencia na ds:Manifest element\n";
		        				}    		 
		        			}
		        			else 
		        			{
		        				returnValue += "v�etky ostatn� referencie v r�mci ds:SignedInfo musia by� referenciami na ds:Manifest elementy\n";
		        			}
	        			}
	        		}
	        		if (!KeyInfo) 
	        		{
	        			returnValue += "neplatn� referencia na ds:KeyInfo element\n";
	        		}
	        		if (!SignatureProperties) 
	        		{
	        			returnValue += "neplatn� referencia na ds:SignatureProperties element\n";
	        		}
	        		if (!SignedProperties) 
	        		{
	        			returnValue += "neplatn� referencia na xades:SignedProperties element\n";
	        		}        			        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
        	/*	overenie obsahu ds:KeyInfo:
    		 *	�	mus� obsahova� ds:X509Data, ktor� obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName,
    		 *	�	hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName s�hlasia s pr�slu�n�mi hodnatami v certifik�te, ktor� sa nach�dza v ds:X509Certificate,
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
	        				returnValue += "ds:KeyInfo mus� obsahova� ds:X509Data, ktor� obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName\n";
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
									returnValue += "hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName s�hlasia s pr�slu�n�mi hodnatami v certifik�te, ktor� sa nach�dza v ds:X509Certificate\n";
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
	        			returnValue += "ds:KeyInfo mus� obsahova� ds:X509Data\n";
	        		}
	        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	       /*	overenie obsahu ds:SignatureProperties:
			*	�	mus� obsahova� dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos,
			*	�	obidva ds:SignatureProperty musia ma� atrib�t Target nastaven� na ds:Signature,
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
	        				try {
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
		        					returnValue += "obidva ds:SignatureProperty musia ma� atrib�t Target nastaven� na ds:Signature";
		        				}
	        				} catch (Exception e1) {
	        					returnValue += "Signature element neobsahuje atrib�t Id";
	        				}
	        			}
	        			else 
	        			{
	        				returnValue += "ds:SignatureProperties mus� obsahova� dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos\n";
	        			}
	        		}
	        		else 
	        		{
	        			returnValue += "ds:SignatureProperties mus� obsahova� dva elementy ds:SignatureProperty\n";
	        		}
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	       /* overenie  elementov:
			*	�	overenie hodnoty Type atrib�tu vo�i profilu XAdES_ZEP,
			*	�	ka�d� ds:Manifest element mus� obsahova� pr�ve jednu referenciu na ds:Object,
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
		        						returnValue += "overenie hodnoty Type atrib�tu vo�i profilu XAdES_ZEP\n";
		        					}
		        				}
		        			}
		        			if (references != 1) {
		        				returnValue += "ka�d� ds:Manifest element mus� obsahova� pr�ve jednu referenciu na ds:Object\n";
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
	        	/*
	        	 * overenie referenci� v elementoch ds:Manifest:
				 * dereferencovanie URI, aplikovanie pr�slu�nej ds:Transforms transform�cie (pri base64 decode),
				 * overenie hodnoty ds:DigestValue,
	        	 */
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		
	        		ArrayList<Element> references = new ArrayList<Element>();
	        		
	        		NodeList manifests = parsedDoc.getElementsByTagName("ds:Manifest");
	        		       		
	        		//najdi v�etky referencie v manifestoch
	        		for(int i = 0; i < manifests.getLength(); i++) {
	        			NodeList childrens = manifests.item(i).getChildNodes();
	        			for (int j = 0; j < childrens.getLength(); j++) {
	        				if (childrens.item(j).getNodeName().compareTo("ds:Reference") == 0) 
	        				{
	        					references.add((Element)childrens.item(j));
	        				}
	        			}
	        		}	
	        		
	        		for (int i=0;i<references.size();i++) {
	        			Element refElement = references.get(i);
	        			
	        			Element objEl = null;
	        			
	        			//dereferencovanie URI pre manifest
	        			NodeList allObjects =  parsedDoc.getElementsByTagName("ds:Object");
	        			for (int k=0;k<allObjects.getLength();k++) {
	        				Element object = (Element) allObjects.item(k);
	        				if (object.hasAttribute("Id") && refElement.getAttribute("URI").substring(1).equals(object.getAttribute("Id"))) {
	        					objEl = object;
	        				}
	        			}
	        			
	        			//iba ak na�iel objekt s dan�m ID
	        			if (objEl == null) {
	        				returnValue.append("Pri dereferencovan� referencii v manifest elementoch sa nena�iel objekt s Id: " + refElement.getAttribute("URI").substring(1) + "\n");
	        			} else {
	        			
		        			Element digestMethodElement = (Element) refElement.getElementsByTagName("ds:DigestMethod").item(0);     			
		        			
		        			NodeList transformsList = refElement.getElementsByTagName("ds:Transforms");
		        			
		        			//overujem DigestValue pre v�etky transformy
		        			int j = 0;
		        			while (j<transformsList.getLength()) {

		        				Element listItem = (Element) transformsList.item(j);
		        				Element transElem = (Element) listItem.getElementsByTagName("ds:Transform").item(0);
		        				
		        				DOMImplementationLS lsImpl = (DOMImplementationLS)objEl.getOwnerDocument().getImplementation().getFeature("LS", "3.0");
		        				LSSerializer serializer = lsImpl.createLSSerializer();
		        				serializer.getDomConfig().setParameter("xml-declaration", false);
		        				byte[] objnElBytes = serializer.writeToString(objEl).getBytes();
		        				
		        				org.apache.xml.security.Init.init();
		        				
		        				if (transElem.getAttribute("Algorithm").equals(getTransformString())) {
		        					Canonicalizer c;
		        					try {
		        						c = Canonicalizer.getInstance(transElem.getAttribute("Algorithm"));
		        						objnElBytes = c.canonicalize(objnElBytes);
		        					} catch (Exception e) {
		        						System.out.println(e);
		        						returnValue.append("Nepodarilo sa kanonikalizova� ds:Object element.\n");
		        						returnValue.append(e + "\n");
		        					}
		        				}
		        				
		        				//pri base64 dekodujeme
		        				if (transElem.getAttribute("Algorithm").equals("http://www.w3.org/2000/09/xmldsig#base64")) {
		        					objnElBytes = Base64.getDecoder().decode(objnElBytes);
		        				}
		        				
		        				//4.5 identifik�tory MD
			        			Map<String, String> possibleDM = new HashMap<String, String>();
			        			possibleDM.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
			        			possibleDM.put("http://www.w3.org/2001/04/xmldsigmore#sha224", "SHA-224");
			        			possibleDM.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
			        			possibleDM.put("http://www.w3.org/2001/04/xmldsigmore#sha384", "SHA-384");
			        			possibleDM.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");  
			        			
			        			MessageDigest messageDigest = null;
			        			
			        			try {
			        				messageDigest = MessageDigest.getInstance(possibleDM.get(digestMethodElement.getAttribute("Algorithm")));
			        				
			        			} catch (NoSuchAlgorithmException e) {
			        				returnValue.append("Subvalid�cia: Nepodporovan� DM algoritmus.\n");
			        			}
			        			
			        			if (messageDigest != null) {
				        			//podpis, expected vs actual
				        			if (refElement.getElementsByTagName("ds:DigestValue").item(0).getTextContent()
				        					.equals(new String(Base64.getEncoder().encode(messageDigest.digest(objnElBytes)).toString())) == false) {
				        				
				        				returnValue.append("Subvalid�cia: DigestValue v elemente Reference sa nezhoduje s hodnotou vypo��tanou z Object elementu.\n");
				        			}
			        			}
		        				j++;
		        			}
		        			
		        			
	        			}
	        		}
	        		
					return returnValue.toString();
	        		
	        	}	 
	        },
	        new Rule()
	        {
	       /* Overenie �asovej pe�iatky:
			* overenie platnosti podpisov�ho certifik�tu �asovej pe�iatky vo�i �asu UtcNow a vo�i platn�mu posledn�mu CRL.
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
	        			returnValue.append("Ch�ba certifik�t �asovej pe�iatky.\n");
	        		}

	        		if (!signer.isValidOn(new Date())){
	        			returnValue.append("Podpisov� certifik�t �asovej pe�iatky nie je platn� vo�i UtcNow �asu.\n");
	        		}

	        		if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
	        			returnValue.append("Podpisov� certifik�t �asovej pe�iatky nie je platn� vo�i platn�mu posledn�mu CRL.\n");
	        		}

	        		return returnValue.toString();
	        	}
	        },
	        new Rule()
	        {
	       /* Overenie �asovej pe�iatky:
			* overenie MessageImprint z �asovej pe�iatky vo�i podpisu ds:SignatureValue
	        */
	        	public String verifie() 
	        	{
	        		StringBuilder returnValue = new StringBuilder();
	        		
	        		TimeStampToken token = getToken();
	        		
	        		byte[] messageImprint = token.getTimeStampInfo().getMessageImprintDigest();
	        		String hashAlg = token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

	        		byte[] signature = Base64.getDecoder().decode(parsedDoc.getElementsByTagName("ds:SignatureValue").item(0).getTextContent().getBytes());
	        		
	        		MessageDigest messageDigest = null;
        			try {
						messageDigest = MessageDigest.getInstance(hashAlg);
						if (!MessageDigest.isEqual(messageImprint, messageDigest.digest(signature))){
		        			returnValue.append("MessageImprint z �asovej pe�iatky a podpis ds:SignatureValue sa nezhoduj�.\n");
		        		}
					} catch (NoSuchAlgorithmException e) {
						returnValue.append("Overenie �asovej pe�iatky: Nepodporovan� messageDigest algoritmus v tokene pri porovn�van� s MessageImprint.\n");
					}
	        		
	        		return returnValue.toString();
	        	}
	        },
	        new Rule()
	        {
	       /* Overenie platnosti podpisov�ho certifik�tu:
			* overenie platnosti podpisov�ho certifik�tu dokumentu vo�i �asu T z �asovej pe�iatky a vo�i platn�mu posledn�mu CRL.
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
						returnValue.append("Certifik�t nie je platn� vo�i �asu T z �asovej pe�iatky.\n");
					}

	        		X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
	        		if (entry != null && entry.getRevocationDate().before(token.getTimeStampInfo().getGenTime())) {
	        			returnValue.append("Certifik�t nie je platn� vo�i posledn�mu CRL.\n");
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
	
	private String getTransformString() {
		return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
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
		canonicalizationMethods.add(getTransformString());
		
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
        	url = new URL("http://test.ditec.sk/DTCCACrl/DTCCACrl.crl");	//cvi�enie 2 - crl.txt, od nich m�me ten certifik�t
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
