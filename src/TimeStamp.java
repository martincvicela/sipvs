import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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

//import org.apache.cxf;


public class TimeStamp {

	public String getTS(String input) {
		
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
	}
	
	//dalej tu riešia nejaké tokeny
	private static InputStream getStandardTSAREsponse(byte request[]) {
		InputStream in = null;
		try {

			OutputStream out = null;
			URL url = new URL("http://test.ditec.sk/timestampws/TS.aspx");
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
	}
	
}
