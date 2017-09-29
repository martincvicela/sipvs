
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
		this.requestDateAll = argRecord.requestDateAll;
		this.city = argRecord.city;
		this.dogs = argRecord.dogs;
	}

	@XmlElement(name = "Name")
	public String name;
	@XmlElement(name = "Dog")
	public ArrayList<Dog> dogs = new ArrayList<Dog>();
	@XmlElement(name = "Contact")
	Contact contact = new Contact("sdfg", "asdf");
	//date is transformet only into MM/dd/yyyy, but requestDateAll contains also time
	Date requestDateAll = new Date();
	DateFormat outputFormatter = new SimpleDateFormat("MM/dd/yyyy");
	@XmlElement(name = "RequestDate")
	String requestDate= outputFormatter.format(requestDateAll);
	@XmlElement(name = "City")
	String city;
}
