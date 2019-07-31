package ghidraesp8266_2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class ESP8266Section implements StructConverter {
	private int offset;
	private int size;
	private byte[] content;
	
	public ESP8266Section(BinaryReader reader) throws IOException {
		offset = reader.readNextInt();
		size = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(DWORD, 1, "offset", "Starting offset of the section");
		structure.add(DWORD, 1, "size", "Size of the section");
		structure.add(BYTE, size, "content", "Contents of the section");
		return structure;
	}

	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	public byte[] getContent() {
		return content;
	}

	public String getName() {
		// Rules based on ranges
		if(offset == ESP8266Constants.SEGMENT_USER_CODE_BASE)
			return ".user_code";
		else if(offset == ESP8266Constants.SEGMENT_USER_DATA_BASE)
			return ".user_data";
		else if(offset <= ESP8266Constants.SEGMENT_DATA_END)
			return ".data";
		else if(offset > ESP8266Constants.SEGMENT_CODE_BASE)
			return ".code";
		else
			return ".unknown";
	}
}
