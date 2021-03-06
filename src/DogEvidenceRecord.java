
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "DogEvidenceRecord")
public class DogEvidenceRecord {

	public DogEvidenceRecord() {

	}

	public DogEvidenceRecord(DogEvidenceRecord argRecord) {
		this.name = argRecord.name;
		this.contact = argRecord.contact;
		this.dogs = argRecord.dogs;
		this.city = argRecord.city;
		DateFormat outputFormatter = new SimpleDateFormat("yyyy-MM-dd");
		this.requestDate= outputFormatter.format(argRecord.requestDateAll);
	}

	@XmlElement(name = "Name")
	public String name;
	@XmlElement(name = "Contact")
	Contact contact = new Contact();
	@XmlElement(name = "Dog")
	public ArrayList<Dog> dogs = new ArrayList<Dog>();
	@XmlElement(name = "City")
	String city;
	//date is transformet only into MM/dd/yyyy, but requestDateAll contains also time
	Date requestDateAll = new Date();
	DateFormat outputFormatter = new SimpleDateFormat("yyyy-MM-dd");
	@XmlElement(name = "RequestDate")
	String requestDate= outputFormatter.format(requestDateAll);
}
