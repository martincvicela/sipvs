import java.io.File;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

public class ConvertDogRecordToXml {
	public ConvertDogRecordToXml(DogEvidenceRecord argEvidence) {
		DogEvidenceRecord evidenceRecord = new DogEvidenceRecord(argEvidence);

	  try {

		File file = new File("file.xml");
		JAXBContext jaxbContext = JAXBContext.newInstance(DogEvidenceRecord.class);
		Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

		// output pretty printed
		jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		jaxbMarshaller.setProperty("com.sun.xml.internal.bind.xmlHeaders",
		        "\n<?xml-stylesheet type='text/xsl' href=\"file.xsl\" ?>");
		
		jaxbMarshaller.marshal(evidenceRecord, file);
		jaxbMarshaller.marshal(evidenceRecord, System.out);

	      } catch (JAXBException e) {
		e.printStackTrace();
	      }

	}
}