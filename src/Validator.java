import java.io.File;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Validator {
	public  Document parsedDoc;
	
	
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
	        new Rule() { public boolean verifie() { return true;} },
	        new Rule() { public boolean verifie() { return true; } },
	        new Rule() { public boolean verifie() { return true; } },
	        new Rule() { public boolean verifie() { return true; } },
	    };

	public interface Rule{
	    public boolean verifie(); 
	}
	
	//maybe this is not good idea, someday I will check for it
	Validator(File xmlFile) throws ParserConfigurationException, SAXException, IOException
	{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		parsedDoc = builder.parse(xmlFile);
	}
	
	
	
	int validate()
	{
		for(int i = 0; i< rules.length; i++)
		{
			if(!rules[i].verifie())
				return i;
		}
		return 0;
	}
}
