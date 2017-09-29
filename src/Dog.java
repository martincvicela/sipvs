import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Dog")
public class Dog{
	@XmlAttribute(name = "Colour")
	public String colour = "pink";
	@XmlElement(name = "Name")
	public String name = "Rex";
	@XmlAttribute(name = "Breed")
	public String breed = "German Shepherd";
	@XmlAttribute(name = "Gender")
	public String gender = "pes";	
	Date birthDateWithTime = new Date();
	DateFormat outputFormatter = new SimpleDateFormat("MM/dd/yyyy");
	@XmlElement(name = "BirthDate")
	String birthDate= outputFormatter.format(birthDateWithTime);
	
	public Dog(String colour, String name, String breed) {
		super();
		this.colour = colour;
		this.name = name;
		this.breed = breed;
	}
	public Dog() {
		super();
	}
}
