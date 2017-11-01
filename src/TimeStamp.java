import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import org.apache.cxf.helpers.IOUtils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class TimeStamp {
	
	public String getTS(String input) {
		     
        String base64data = Base64.getEncoder().encodeToString(input.getBytes());
        
        String rawOutput = null;
		try {
			rawOutput = IOUtils.readStringFromStream(getWholeTimeStamp(base64data));
			System.out.println("Service output: " + rawOutput);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = null;
		InputSource source = new InputSource(new StringReader(rawOutput));
		Document document = null;
		try {
			docBuilder = docFactory.newDocumentBuilder();
			document = docBuilder.parse(source);
		} catch (SAXException | ParserConfigurationException | IOException e) {
			e.printStackTrace();
		}
		
		Node timeStampResult = document.getElementsByTagName("GetTimestampResult").item(0);
		
		return timeStampResult.getTextContent();
	}

	private static InputStream getWholeTimeStamp(String base64data) {
		InputStream in = null;
		try {
			OutputStream out = null;
			URL myUrl = new URL("http://test.ditec.sk/timestampws/TS.asmx");
			HttpURLConnection connection = (HttpURLConnection) myUrl.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("POST");
			//connection.setRequestProperty("Content-type", "application/timestamp-query");
			connection.setRequestProperty("Content-type", "text/xml; charset=utf-8");
			connection.setRequestProperty("SOAPAction", "http://www.ditec.sk/GetTimestamp");
			
			out = connection.getOutputStream();
			Writer wout = new OutputStreamWriter(out);
			wout.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                    "  <soap:Body>\n" +
                    "    <GetTimestamp xmlns=\"http://www.ditec.sk/\">\n" +
                    "      <dataB64>" + base64data + "</dataB64>\n" +
                    "    </GetTimestamp>\n" +
                    "  </soap:Body>\n" +
                    "</soap:Envelope>");
			wout.flush();
			
			in = connection.getInputStream();
		} catch (Exception e) {
			System.out.println(e);
		}
		return in;
	}
	
}
