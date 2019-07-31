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

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraESP8266_2Loader extends AbstractLibrarySupportLoader {
	private MemoryBlockUtil mbu; 

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
			Msg.info(this, "Magic Matched");
			List<QueryResult> queries =
				QueryOpinionService.query(getName(), ESP8266Constants.PRIMARY_KEY, null);
			for (QueryResult result : queries) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
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
	
	private void markupHeader(Program program, ESP8266Header header, TaskMonitor monitor, InputStream reader) throws DuplicateNameException, IOException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Header";
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
		try {
			mbu.createInitializedBlock(".header", start, reader, 5, "", BLOCK_SOURCE_NAME, r, w, x, monitor);
			createData(program, program.getListing(), start, header.toDataType());
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private void markupSections(Program program, ESP8266Module module, TaskMonitor monitor, InputStream reader) throws DuplicateNameException, IOException, AddressOverflowException {
		boolean r = true;
		boolean w = true;
		boolean x = true;
		String BLOCK_SOURCE_NAME = "ESP8266 Section";
		for (ESP8266Section section: module.getSections()) {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(section.getOffset());
			mbu.createInitializedBlock(section.getName(), start, reader, section.getSize(), "", BLOCK_SOURCE_NAME, r, w, x, monitor);
			createData(program, program.getListing(), start, section.toDataType());			
		}
	}
	
	public Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "ELF data type markup conflict:" + e.getMessage());
		}
		return null;
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
		Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
		throws CancelledException, IOException {

		monitor.setMessage( "ESP8266 Loader: Start loading" );
		
		try {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( 0x0 );
			long length = provider.length();
	
			InputStream inputStream;
			inputStream = provider.getInputStream(0);
			mbu = new MemoryBlockUtil(program, handler);

			
			BinaryReader reader = new BinaryReader( provider, true );
			ESP8266Module module = new ESP8266Module( reader );
	
//			createMethodLookupMemoryBlock( program, monitor );
//			createMethodByteCodeBlock( program, length, monitor);
			markupHeader(program, module.getHeader(), monitor, inputStream);
			markupSections(program, module, monitor, inputStream);
			monitor.setMessage( "ESP8266 Loader: Create byte code" );
			
			for (ESP8266Section section : module.getSections()) {
				monitor.setMessage("Loaded " + section.getName());
			}
		} catch (Exception e) {
			log.appendException( e );
		}
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
