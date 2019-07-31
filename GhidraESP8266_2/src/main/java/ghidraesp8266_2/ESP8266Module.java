package ghidraesp8266_2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class ESP8266Module  {
	
	private ESP8266Header header;
	private List<ESP8266Section> sections = new ArrayList<ESP8266Section>();
	
	public ESP8266Module(BinaryReader reader) throws IOException {
		header = new ESP8266Header(reader);
		while (reader.getPointerIndex() < reader.length()) {
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