import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Contact")
public class Contact {
	public Contact() {
		super();
	}
	public Contact(String telephoneNumber, String email) {
		super();
		this.telephoneNumber = telephoneNumber;
		this.email = email;
	}
	@XmlElement(name = "TelephoneNumber")
	public String telephoneNumber = "";
	@XmlElement(name = "Email")
	public String email = "";
}
