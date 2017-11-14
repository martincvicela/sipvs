import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

public class Validator {
	private  Document parsedDoc;
	private XPath xpath;
	
	
	/*I changed my mind :)
	public enum Rules implements Rule{
	    RULE1 {
	        public boolean verifie() {
	        	System.out.println("rule1");
	        	return true;
	        }
	    }, RULE2 {
	        public boolean verifie() {
	        	System.out.println("rule2");
	        	return true;
	        }
	    }, RULE3 {
	        public boolean verifie() {
	        	System.out.println("rule3");
	        	return true;
	        }
	    };

	}*/
	private Rule[] rules = new Rule[] {
			
			/*
			 * Overenie d·tovej ob·lky:
			 * ï	koreÚov˝ element musÌ obsahovaù atrib˙ty xmlns:xzep a xmlns:ds 
			 * 		podæa profilu XADES_ZEP.
			 */
	        new Rule() 
	        { 
	        	public boolean verifie() throws XPathExpressionException 
	        	{
	        		Element e = (Element) xpath.evaluate("/*", parsedDoc, XPathConstants.NODE);
	        		if (e.getAttribute("xmlns:xzep").compareTo("http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0") == 0
	        				&& e.getAttribute("xmlns:ds").compareTo("http://www.w3.org/2000/09/xmldsig#") == 0)
	        		{
	        			return true;
	        		}
	        		return false;
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
	        	public boolean verifie() throws XPathExpressionException 
	        	{ 
	        		Set<String> signatureMethods = new HashSet<String>();
	        		Set<String> canonicalizationMethods = new HashSet<String>();
	        		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#dsa-sha1"); 
	        		signatureMethods.add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
	        		signatureMethods.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
	        		canonicalizationMethods.add("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
	        		
	        		Element e = (Element) xpath.evaluate("//ds:Signature/ds:SignedInfo/ds:SignatureMethod", parsedDoc, XPathConstants.NODE);
	        		//if (e == null) return false;
	        		if (signatureMethods.contains(e.getAttribute("Algorithm"))
	        				&& canonicalizationMethods.contains("Algorithm"))
	        		{
	        			return true;
	        		}
	        		return false;
	        	} 
	        },
	        /*
	         * Overenie XML Signature:
			 *	ï	kontrola obsahu ds:Transforms a ds:DigestMethod vo vöetk˝ch referenci·ch v ds:SignedInfo 
			 *		ñ musia obsahovaù URI niektorÈho z podporovan˝ch algoritmov podæa profilu XAdES_ZEP
	         */
	        new Rule() 
	        { 
	        	public boolean verifie() 
	        	{ 
	        		return true;
	        	} 
	        },
	        new Rule() { public boolean verifie() { return true; } },
	    };

	public interface Rule{
	    public boolean verifie() throws XPathExpressionException; 
	}
	
	//maybe this is not good idea, someday I will check for it
	Validator(File xmlFile) throws ParserConfigurationException, SAXException, IOException
	{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		parsedDoc = builder.parse(xmlFile);
		xpath = XPathFactory.newInstance().newXPath();
	}
	
	
	
	int validate()
	{
		for(int i = 0; i< rules.length; i++)
		{
			try {
				if(!rules[i].verifie())
					return i+1;
			} catch (XPathExpressionException e) {
				e.printStackTrace();
			}
		}
		return 0;
	}
}
