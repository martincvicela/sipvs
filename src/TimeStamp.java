import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
//import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampToken; //https://www.bouncycastle.org/latest_releases.html

//nepoužívajú tu TimeStampRequest ale miesto toho asi ditec.TS?
//import sk.ditec.TS;

import org.apache.cxf.*;
import java.net.URL;

import javax.xml.bind.Element;
import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.handler.MessageContext;

public class TimeStamp {
	
	public String getTS(String input) {
		
		//náhrada za import sk.ditec.TS;
		URL wsdlURL = null;
		try {
			wsdlURL = new URL("http://test.ditec.sk/timestampws/TS.asmx?wsdl");
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Service service = Service.create(wsdlURL, new QName("http://www.ditec.sk/", "TS"));
		Dispatch<Source> disp = service.createDispatch(new QName("http://www.ditec.sk/", "TSSoap"), Source.class, Service.Mode.MESSAGE);
		
		Map<String, Object> headers = new HashMap<String, Object>();
	    headers.put("Content-Type", Arrays.asList(new String[] {"application/timestamp-query"}));
		disp.getRequestContext().put(MessageContext.HTTP_REQUEST_METHOD, "POST");
		disp.getRequestContext().put(MessageContext.HTTP_REQUEST_HEADERS, headers);
		
		Source response = (Source)disp.invoke(new StreamSource(new StringReader(input)));
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		String timeStampB64 = response.toString();
		
		TimeStampResponse TSresponse = null;
		try {
			TSresponse = new TimeStampResponse(Base64.getDecoder().decode(timeStampB64.getBytes()));
		} catch (TSPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		TimeStampToken timestampToken = TSresponse.getTimeStampToken();
		   
		/*Element docElement = DOMUtils.sourceToElement(retObj);
		Element retElement = DOMUtils.getFirstChildElement(docElement);
		String retPayload = DOMWriter.printNode(retElement, false);*/
	    
		//Source request = new StreamSource(input);
		//String stringRequest = Base64.getEncoder().encodeToString(input.getBytes("utf-8"));
		//Source response = disp.invoke(request);
		//String response = disp.invoke(stringRequest);
		//System.out.println(response);
		//System.out.println(((Map<String, Object>) disp.getResponseContext().get(MessageContext.HTTP_RESPONSE_HEADERS)).get(null));
		
		try {
			System.out.println(new String(Base64.getEncoder().encode(timestampToken.getEncoded())));
			return new String(Base64.getEncoder().encode(timestampToken.getEncoded()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	/*public String getTS(String input) {
		
		//String stringRequest = Base64.getEncoder().encodeToString(input.getBytes("utf-8"));
		//String stringResponse = getTSAResponse(stringRequest);
		///////////
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
			messageDigest.update(input.getBytes("utf-8"));
			byte[] digest = messageDigest.digest();
			
			//byte[] responseByteData = Base64.decode(stringResponse.getBytes());
			//InputStream in = new ByteArrayInputStream(responseByteData);
			
			TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
			TimeStampRequest req = reqgen.generate(TSPAlgorithms.SHA1, digest);
			byte request[] = req.getEncoded();

			InputStream in = getStandardTSAREsponse(request);
			//InputStream in = getDitecTSAResponse(request);
			System.out.println(in);

			TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
			TimeStampResponse response = new TimeStampResponse(resp);
			response.validate(req);
			System.out.println(response.getTimeStampToken().getTimeStampInfo().getGenTime());
			
			
			
		} catch (NoSuchAlgorithmException | IOException | TSPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		return "";
	}*/

	/*private static InputStream getStandardTSAREsponse(byte request[]) {
		InputStream in = null;
		try {

			OutputStream out = null;
			URL url = new URL("http://test.ditec.sk/timestampws/TS.asmx");
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/timestamp-query");
			con.setRequestProperty("Content-length", String.valueOf(request.length));
			out = con.getOutputStream();
			out.write(request);
			out.flush();

			if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
				throw new IOException(
						"Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
			}
			
			in = con.getInputStream();
		} catch (Exception e) {
			System.out.println(e);
		}
		return in;
	}*/
	
}
