import java.io.File;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;


public class Validate {
	
	public Validate() 
	{
	
	}
	
	public String validateXML(File xml, File xsd)
	{
	    try
	    {
	        SchemaFactory factory = 
	            SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
	        Schema schema = factory.newSchema(new StreamSource(xsd));
	        Validator validator = schema.newValidator();
	        validator.validate(new StreamSource(xml));
	        return "XML je validne";
	    }
	    catch(Exception ex)
	    {
	        return "Nevalidne XML: " + ex;
	    }
	}
}
