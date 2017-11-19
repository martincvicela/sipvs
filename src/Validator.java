import java.io.File;
import java.io.IOException;
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
	        		Set<String> signatureMethods = new HashSet<String>();
	        		Set<String> canonicalizationMethods = new HashSet<String>();
	        		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#dsa-sha1"); 
	        		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
	        		canonicalizationMethods.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
	        		
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
	         */
	        new Rule() 
	        { 
	        	public String verifie() 
	        	{ 
	        		String returnValue = "";
	        		Set<String> transform = new HashSet<String>();
	        		Set<String> digestMethod = new HashSet<String>();
	        		transform.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"); 
	        		digestMethod.add("http://www.w3.org/2000/09/xmldsig#sha1");
	        		digestMethod.add("http://www.w3.org/2001/04/xmldsig-more#sha224");
	        		digestMethod.add("http://www.w3.org/2001/04/xmlenc#sha256");
	        		digestMethod.add("http://www.w3.org/2001/04/xmldsig-more#sha384");
	        		digestMethod.add("http://www.w3.org/2001/04/xmlenc#sha512");
	        		
	        		NodeList e = parsedDoc.getElementsByTagName("ds:Transform");
	        		NodeList f = parsedDoc.getElementsByTagName("ds:DigestMethod");
	        		for (int i = 0; i < e.getLength(); i++) {
	        			if (!transform.contains(e.item(i).getAttributes().getNamedItem("Algorithm").getNodeValue())) 
	        			{
	        				returnValue += "kontrola obsahu ds:Transforms vo vöetk˝ch referenci·ch v ds:SignedInfo musia obsahovaù URI niektorÈho z podporovan˝ch\n";
	        			}
	        		}
	        		for (int i = 0; i < f.getLength(); i++) {
	        			if (!digestMethod.contains(f.item(i).getAttributes().getNamedItem("Algorithm").getNodeValue())) 
	        			{
	        				returnValue += "kontrola obsahu ds:DigestMethod vo vöetk˝ch referenci·ch v ds:SignedInfo musia obsahovaù URI niektorÈho z podporovan˝ch\n";
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
	        	*/
	        	//MATO -v rieseni
	        	public String verifie() 
	        	{
	        		String returnValue = "";
	        		NodeList e = parsedDoc.getElementsByTagName("ds:Reference");
	        		boolean KeyInfo = false;
	        		boolean SignatureProperties  = false;
	        		boolean SignedProperties  = false;
	        		for (int i = 0; i < e.getLength(); i++) {
	        			if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#Object") == 0) 
	        			{
	        				String keyInfoId = parsedDoc.getElementsByTagName("ds:KeyInfo").item(0).getAttributes().getNamedItem("Id").getNodeValue();
	        				String referenceURI = e.item(i).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
	        				if (keyInfoId.compareTo(referenceURI) == 0) 
	        				{
	        					KeyInfo = true;
	        				}
	        			}
	        			else if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://www.w3.org/2000/09/xmldsig#SignatureProperties") == 0) 
	        			{
	        				
	        				SignatureProperties = true;
	        			}
	        			else if (e.item(i).getAttributes().getNamedItem("Type").getNodeValue().compareTo("http://uri.etsi.org/01903#SignedProperties") == 0) 
	        			{
	        				SignedProperties = true;
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
    		 *	ï	musÌ maù Id atrib˙t,
    		 *	ï	musÌ obsahovaù ds:X509Data, ktor˝ obsahuje elementy: ds:X509Certificate, ds:X509IssuerSerial, ds:X509SubjectName,
    		 *	ï	hodnoty elementov ds:X509IssuerSerial a ds:X509SubjectName s˙hlasia s prÌsluön˝mi hodnatami v certifik·te, ktor˝ sa nach·dza v ds:X509Certificate,
    		 */
	        	//MATO -v rieseni
	        	public String verifie() 
	        	{
	        		String returnValue = "";	        		    				        		
	        		return returnValue;
	        	}        	
	        },
	        new Rule()
	        {
	       /*	overenie obsahu ds:SignatureProperties:
			*	ï	musÌ maù Id atrib˙t,
			*	ï	musÌ obsahovaù dva elementy ds:SignatureProperty pre xzep:SignatureVersion a xzep:ProductInfos,
			*	ï	obidva ds:SignatureProperty musia maù atrib˙t Target nastaven˝ na ds:Signature,
	        */
	        	//MATO -v rieseni
	        	public String verifie() 
	        	{
	        		String returnValue = "";	        		    				        		
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
