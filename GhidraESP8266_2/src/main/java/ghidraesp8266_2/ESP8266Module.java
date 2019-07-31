package ghidraesp8266_2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class ESP8266Module  {
	
	private ESP8266Header header;
	private ESP8266Header userheader;
	private List<ESP8266Section> sections = new ArrayList<ESP8266Section>();
	
	public ESP8266Module(BinaryReader reader) throws IOException {
		header = new ESP8266Header(reader);
		for(int i=0; i < header.getSegmentCount(); ++i) {
			sections.add(new ESP8266Section(reader));
		}
		// Parse user ROM
		reader.setPointerIndex(0x1000);
		userheader = new ESP8266Header(reader);
		for(int i=0; i < userheader.getSegmentCount(); ++i) {
			sections.add(new ESP8266Section(reader));
		}
	}

	public ESP8266Section getSection(int id) {
		return sections.get(id);
	}
	
	public ESP8266Header getHeader() {
		return header;
	}
	
	public List<ESP8266Section> getSections() {
		return sections;
	}
}