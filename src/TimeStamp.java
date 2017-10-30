import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
//import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampToken; //https://www.bouncycastle.org/latest_releases.html

//nepoužívajú tu TimeStampRequest ale miesto toho asi ditec.TS?
import sk.ditec.TS;

public class TimeStamp {

	public String getTS(String input) {
		
		TS client = new TS();
		String timeStampMessage = client.getTSSoap().getTimestamp(input);
		return timeStampMessage;
	}
	
	//dalej tu riešia nejaké tokeny
}
