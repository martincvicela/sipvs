import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Dog")
public class Dog{
	
	Date birthDateWithTime = new Date();
	DateFormat outputFormatter = new SimpleDateFormat("yyyy-MM-dd");
	@XmlElement(name = "BirthDate")
	String birthDate = outputFormatter.format(birthDateWithTime);
	@XmlElement(name = "Name")
	public String name = "Rex";
	@XmlAttribute(name = "Breed")
	public String breed = "German Shepherd";
	@XmlAttribute(name = "Gender")
	public String gender = "pes";	
	@XmlAttribute(name = "Colour")
	public String colour = "pink";
	@XmlElement(name = "EvidenceNumber")
	public Integer eNumber = 15467;
	
	public Dog(String colour, String name, String breed, Integer eNumber, Date bDate) {
		super();
		this.colour = colour;
		this.name = name;
		this.breed = breed;
		this.eNumber = eNumber;
		DateFormat outputFormatter = new SimpleDateFormat("yyyy-MM-dd");
		this.birthDate = outputFormatter.format(bDate);
	}
	public Dog() {
		super();
	}
}
