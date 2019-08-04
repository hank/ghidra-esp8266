package ghidraesp8266_2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class ESP8266Header implements StructConverter {

	private byte magic;
	private byte segments;
	private byte flash_mode;
	private byte flash_size_free;
	private long entrypoint;
	
	public ESP8266Header(BinaryReader reader) throws IOException {
		magic = reader.readNextByte();
		Msg.info(this, String.format("Magic = %02x", magic));
		if (ESP8266Constants.ESP_MAGIC_BASE != getMagic()) {
			throw new IOException("not an ESP8266 file.");
		}
		segments = reader.readNextByte();
		Msg.info(this, String.format("Segments = %d", segments));
		flash_mode = reader.readNextByte();
		Msg.info(this, String.format("Flash Mode = %d", flash_mode));
		flash_size_free = reader.readNextByte();
		Msg.info(this, String.format("Flash Size Free = %d", flash_size_free));
		entrypoint = reader.readNextInt();
		Msg.info(this, String.format("Entrypoint = %08x", entrypoint));
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(BYTE, 1, "magic", null);
		structure.add(BYTE, 1, "segments", "Number of segments");
		structure.add(BYTE, 1, "flash_mode", null);
		structure.add(BYTE, 1, "flash_size_free", null);
		structure.add(DWORD, 4, "entrypoint", "The entry function");
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

	public long getEntrypoint() {
		return entrypoint;
	}

	public void setEntrypoint(long entrypoint) {
		this.entrypoint = entrypoint;
	}
}