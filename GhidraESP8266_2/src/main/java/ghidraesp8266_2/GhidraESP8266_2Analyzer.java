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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GhidraESP8266_2Analyzer extends AbstractAnalyzer {

	public GhidraESP8266_2Analyzer() {
		super("ESP8266", "Analyzes ESP8266 Firmware", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.
		//LanguageID lID = new LanguageID("Xtensa:LE:32:default");
		//return program.getLanguageID() == lID;
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}
	
	private Symbol createMethodSymbol(Program program, Address methodAddress, String methodName,
			Namespace classNameSpace, MessageLog log) {
		program.getSymbolTable().addExternalEntryPoint(methodAddress);
		try {
			return program.getSymbolTable().createLabel(methodAddress, methodName, classNameSpace,
				SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, true);
//		try {
//			ESP8266Module module = new ESP8266Module(reader);
//			for (ESP8266Section section: module.getSections()) {
//			}
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		return false;
	}
}
