/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraesp8266_2;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraESP8266_2Loader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "ESP8266";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		ESP8266Header header = new ESP8266Header(reader);
		if (ESP8266Constants.ESP_MAGIC_BASE == header.getMagic()) {
			Msg.info(this, "ESP Magic Matched");
			loadSpecs.add(new LoadSpec(this, 0, 
					 new LanguageCompilerSpecPair("Xtensa:LE:32:default", "default"), true));
		}
		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}
	
	private void markupHeader(Program program, ESP8266Header header, TaskMonitor monitor, InputStream reader, MessageLog log) throws DuplicateNameException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Header";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, ".header", start, reader, 8, "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
			createData(program, program.getListing(), start, header.toDataType());
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void markAsCode(Program program, Address address) {
		AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
		if (codeProp == null) {
			try {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}
			catch (DuplicateNameException e) {
				codeProp = program.getAddressSetPropertyMap("CodeMap");
			}
		}

		if (codeProp != null) {
			codeProp.add(address, address);
		}
	}
	
	private void markupSections(Program program, ESP8266Module module, TaskMonitor monitor, InputStream reader, MessageLog log) throws DuplicateNameException, IOException, AddressOverflowException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Section";
		for (ESP8266Section section: module.getSections()) {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(section.getOffset());
			Msg.info(this, String.format("Section at offset %08x, size %d", start.getOffset(), section.getSize()));
			MemoryBlockUtils.createInitializedBlock(program, false,
				section.getName(), start, reader, section.getSize(), "", BLOCK_SOURCE_NAME, r, w, x, log, monitor);
			createData(program, program.getListing(), start, section.toDataType());			
			// Mark code sections
			if(section.getType() == ESP8266Constants.SECTION_TYPE_CODE)
			{
				Msg.info(this, "Section is code");
				markAsCode(program, start);
			}
			else
			{
				Msg.info(this, "Section is not code");
			}
		}
	}
	
	public Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "Data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "Data type markup conflict:" + e.getMessage());
		}
		return null;
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		monitor.setMessage( "ESP8266 Loader: Start loading" );
		
		try {
			InputStream inputStream;
			inputStream = provider.getInputStream(0);

			
			BinaryReader reader = new BinaryReader( provider, true );
			ESP8266Module module = new ESP8266Module( reader );
	
			markupHeader(program, module.getHeader(), monitor, inputStream, log);
			markupSections(program, module, monitor, inputStream, log);
			
			// Create entry point
			Address entryAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(module.getHeader().getEntrypoint(), true);
			program.getSymbolTable().addExternalEntryPoint(entryAddress);
		} catch (Exception e) {
			log.appendException( e );
		}
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
