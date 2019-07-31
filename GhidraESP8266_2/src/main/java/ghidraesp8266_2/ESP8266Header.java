package ghidraesp8266_2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class ESP8266Header implements StructConverter {

	private byte magic;
	private byte segments;
	private byte flash_mode;
	private byte flash_size_free;
	private byte entrypoint;
	
	public ESP8266Header(BinaryReader reader) throws IOException {
		magic = reader.readNextByte();
		segments = reader.readNextByte();
		if (ESP8266Constants.ESP_MAGIC_BASE != getMagic()) {
			throw new IOException("not an ESP8266 file.");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(BYTE, 1, "magic", null);
		structure.add(BYTE, 1, "segments", null);
		structure.add(BYTE, 1, "flash_mode", null);
		structure.add(BYTE, 1, "flash_size_free", null);
		structure.add(BYTE, 1, "entrypoint", null);
		return structure;
	}
	
	public byte getMagic() {
		return magic;
	}
	
	public void setMagic(byte magic) {
		this.magic = magic;
	}

	public byte getSegmentCount( ) {
		return segments;
	}

	public void setSegmentCount(byte segments) {
		this.segments = segments;
	}

	public byte getFlashMode() {
		return flash_mode;
	}

	public void setFlashMode(byte flash_mode) {
		this.flash_mode = flash_mode;
	}

	public byte getFlashSizeFree() {
		return flash_size_free;
	}

	public void setFlashSizeFree(byte flash_size_free) {
		this.flash_size_free = flash_size_free;
	}

	public byte getEntrypoint() {
		return entrypoint;
	}

	public void setEntrypoint(byte entrypoint) {
		this.entrypoint = entrypoint;
	}

	
	

}