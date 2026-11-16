//ApiScout plugin for Ghidra
//@author @mari-mari
//@category ApiScoutForGhidra
//@keybinding
//@menupath Tools.ApiScout
//@toolbar
// Put the script in the Ghidra plugins directory (ghidra_scripts).
// Requires working version of ApiScout (not bundled with this plugin, available here:
// https://github.com/danielplohmann/apiscout)
// When run for the first time, the script will ask for the path to the scout.py (ApiScout root directory)
// and remember it in the user preferences of Ghidra.
// Ctrl+A to choose all found APIs for annotation.
// Headless usage: -postScript GhidraScout.java <path to scout.py> [<path to API DB> ...], annotates all APIs found.

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.program.model.address.Address;
import generic.jar.ResourceFile;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class GhidraScout extends GhidraScript {
	TableChooserDialog tableDialog;
	String scoutPyPath = null;
	FileDataTypeManager windowsArchive = null;
	boolean windowsArchiveMissing = false;

	static final String PREFERENCE_SCOUT_PY_PATH = "apiscout.scout.py.path";
	static final String OTHER_API_DB = "Other file...";
	static final Pattern BITNESS_OF_DLL = Pattern.compile("\\((\\d+) bit\\)$");
	static final Pattern ORDINAL_ONLY_API = Pattern.compile("None<(\\d+)>");

	public void run() throws Exception {
		List<String> dataBasePaths = new ArrayList<String>();
		if (isRunningHeadless()) {
			String[] args = getScriptArgs();
			if (args.length == 0) {
				printerr("Usage: GhidraScout.java <path to scout.py> [<path to API DB> ...]");
				return;
			}
			this.scoutPyPath = args[0];
			dataBasePaths.addAll(Arrays.asList(args).subList(1, args.length));
		} else {
			// cancelling one of the dialogs ends the script
			this.scoutPyPath = this.initApiScoutPathProperty();
			dataBasePaths.addAll(askUserForDatabasesToUse());
		}
		printf("\nProcessing %s\nImage file: %s\n", currentProgram.getName(), currentProgram.getExecutablePath());

		// several API DBs can resolve the same location, which is listed once
		Map<String, ApiScoutResultEntry> uniqueApis = new LinkedHashMap<String, ApiScoutResultEntry>();
		for (MemoryRegion region : getMemoryRegions()) {
			monitor.checkCancelled();
			for (ApiScoutResultEntry entry : scoutRegion(region, dataBasePaths)) {
				uniqueApis.putIfAbsent(entry.address + " " + entry.dll + " " + entry.api, entry);
			}
		}
		List<ApiScoutResultEntry> foundApis = new ArrayList<ApiScoutResultEntry>(uniqueApis.values());
		printf("ApiScout found %d API references\n", foundApis.size());

		if (isRunningHeadless()) {
			int annotated = 0;
			for (ApiScoutResultEntry entry : foundApis) {
				if (annotate(entry)) {
					annotated++;
				}
			}
			closeWindowsArchive();
			printf("Annotated %d API references\n", annotated);
			return;
		}
		tableDialog = createTableChooserDialog("ApiScout: API references", createTableExecutor());
		configureTableColumns(tableDialog);
		for (ApiScoutResultEntry entry : foundApis) {
			tableDialog.add(new ApiRow(entry));
		}
		tableDialog.setClosedListener(this::closeWindowsArchive);
		tableDialog.setPreferredSize(900, 600);
		tableDialog.show();
		tableDialog.setMessage(foundApis.size() + " API references found, select the ones to annotate");
	}

	private String initApiScoutPathProperty() throws CancelledException {
		String scoutPyAbsolutePath = Preferences.getProperty(PREFERENCE_SCOUT_PY_PATH);
		if (scoutPyAbsolutePath != null && new File(scoutPyAbsolutePath).isFile()) {
			return scoutPyAbsolutePath;
		}
		scoutPyAbsolutePath = askFile("Path to ApiScout's scout.py script", "Select").getAbsolutePath();
		Preferences.setProperty(PREFERENCE_SCOUT_PY_PATH, scoutPyAbsolutePath);
		Preferences.store();
		return scoutPyAbsolutePath;
	}

	// The API DBs shipped next to scout.py are offered by name, any other file can be chosen as well.
	private List<String> askUserForDatabasesToUse() throws CancelledException {
		File dbFolder = new File(new File(this.scoutPyPath).getParentFile(), "dbs");
		List<String> choices = new ArrayList<String>();
		String[] dbFiles = dbFolder.list((folder, name) -> name.endsWith(".json"));
		if (dbFiles != null) {
			Arrays.sort(dbFiles);
			choices.addAll(Arrays.asList(dbFiles));
		}
		choices.add(OTHER_API_DB);
		List<String> chosen = askChoices("ApiScout",
				"API DBs of the system the memory dump was taken from:", choices);
		List<String> dataBasePaths = new ArrayList<String>();
		for (String choice : chosen) {
			if (OTHER_API_DB.equals(choice)) {
				dataBasePaths.add(askFile("ApiScout: API DB file", "OK").getAbsolutePath());
			} else {
				dataBasePaths.add(new File(dbFolder, choice).getAbsolutePath());
			}
		}
		if (dataBasePaths.isEmpty()) {
			throw new CancelledException();
		}
		return dataBasePaths;
	}

	// The memory of the program as Ghidra knows it, adjacent initialized blocks merged.
	// Scanning the memory instead of the imported file keeps the offsets right for every loader.
	private List<MemoryRegion> getMemoryRegions() {
		List<MemoryRegion> regions = new ArrayList<MemoryRegion>();
		MemoryRegion current = null;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!block.isInitialized() || !block.getStart().getAddressSpace().isLoadedMemorySpace()) {
				current = null;
				continue;
			}
			if (current != null && current.blocks.get(current.blocks.size() - 1).getEnd().isSuccessor(block.getStart())) {
				current.blocks.add(block);
			} else {
				current = new MemoryRegion(block);
				regions.add(current);
			}
		}
		return regions;
	}

	private List<ApiScoutResultEntry> scoutRegion(MemoryRegion region, List<String> dataBasePaths) throws Exception {
		List<ApiScoutResultEntry> results = new ArrayList<ApiScoutResultEntry>();
		File dumpFile = File.createTempFile("ghidrascout", ".bin");
		File jsonFile = File.createTempFile("ghidrascout", ".json");
		try {
			try (OutputStream output = new FileOutputStream(dumpFile)) {
				byte[] chunk = new byte[0x100000];
				for (MemoryBlock block : region.blocks) {
					for (long offset = 0; offset < block.getSize(); offset += chunk.length) {
						int length = (int) Math.min(chunk.length, block.getSize() - offset);
						block.getBytes(block.getStart().add(offset), chunk, 0, length);
						output.write(chunk, 0, length);
					}
				}
			}
			if (!executeScoutPy(dumpFile, jsonFile, region.start, dataBasePaths)) {
				return results;
			}
			try (Reader reader = Files.newBufferedReader(jsonFile.toPath(), StandardCharsets.UTF_8)) {
				List<ApiScoutResultEntry> entries = new Gson().fromJson(reader,
						new TypeToken<List<ApiScoutResultEntry>>() {
						}.getType());
				if (entries != null) {
					for (ApiScoutResultEntry entry : entries) {
						entry.address = region.start.add(entry.offset);
						results.add(entry);
					}
				}
			}
		} finally {
			dumpFile.delete();
			jsonFile.delete();
		}
		return results;
	}

	private boolean executeScoutPy(File dumpFile, File jsonFile, Address baseAddress, List<String> dataBasePaths)
			throws IOException, InterruptedException, CancelledException {
		boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
		String[] interpreters = isWindows ? new String[] { "py.exe", "python.exe" }
				: new String[] { "python3", "python" };
		for (String interpreter : interpreters) {
			List<String> command = new ArrayList<String>();
			command.add(interpreter);
			command.add(this.scoutPyPath);
			command.add("-s");
			command.add("-b");
			command.add("0x" + Long.toHexString(baseAddress.getOffset()));
			command.add("-o");
			command.add(jsonFile.getAbsolutePath());
			command.add(dumpFile.getAbsolutePath());
			command.addAll(dataBasePaths);
			File outputFile = File.createTempFile("ghidrascout", ".log");
			try {
				ProcessBuilder builder = new ProcessBuilder(command);
				builder.redirectErrorStream(true);
				builder.redirectOutput(outputFile);
				Process process;
				try {
					process = builder.start();
				} catch (IOException e) {
					// this interpreter is not installed, try the next one
					continue;
				}
				while (!process.waitFor(200, TimeUnit.MILLISECONDS)) {
					if (monitor.isCancelled()) {
						process.destroyForcibly();
						throw new CancelledException();
					}
				}
				if (process.exitValue() != 0) {
					printerr("ApiScout subprocess exited with error code " + process.exitValue() + "\n"
							+ new String(Files.readAllBytes(outputFile.toPath()), StandardCharsets.UTF_8));
					return false;
				}
				return true;
			} finally {
				outputFile.delete();
			}
		}
		printerr("No python interpreter found to run ApiScout.");
		return false;
	}

	// Annotates a reference the way Ghidra's own loaders describe an import:
	// a pointer with an external reference to the function of its library.
	private boolean annotate(ApiScoutResultEntry entry) {
		if (entry.api == null || entry.api.isEmpty()) {
			return false;
		}
		try {
			String name = SymbolUtilities.replaceInvalidChars(getLabelName(entry), true);
			createLabel(entry.address, name, true);
			if (getInstructionContaining(entry.address) != null) {
				// an API address within an instruction, which is left as it is
				return true;
			}
			boolean isPointerSized = getBitness(entry) == currentProgram.getDefaultPointerSize() * 8;
			DataType dataType = isPointerSized ? PointerDataType.dataType
					: getBitness(entry) == 64 ? QWordDataType.dataType : DWordDataType.dataType;
			Data existing = getDataAt(entry.address);
			if (existing == null || !existing.isPointer() || !isPointerSized) {
				try {
					DataUtilities.createData(currentProgram, entry.address, dataType, -1,
							ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				} catch (CodeUnitInsertionException e) {
					return true;
				}
			}
			if (!isPointerSized) {
				// e.g. a 32bit API address in a 64bit program, which is no pointer the program can follow
				return true;
			}
			String library = getLibraryName(entry);
			ExternalLocation location = currentProgram.getExternalManager().addExtFunction(library, name, null,
					SourceType.ANALYSIS);
			applyPrototype(location.getFunction(), entry.api);
			currentProgram.getReferenceManager().addExternalReference(entry.address, library, name, null,
					SourceType.ANALYSIS, 0, RefType.DATA);
			return true;
		} catch (Exception e) {
			printerr("Could not annotate " + entry.address + " with " + entry.api + ": " + e.getMessage());
			return false;
		}
	}

	// Prototypes are taken from the Windows data type archive shipped with Ghidra.
	private void applyPrototype(Function function, String api) {
		if (function == null || function.getSignatureSource() != SourceType.DEFAULT) {
			return;
		}
		DataTypeManager archive = getWindowsArchive();
		if (archive == null) {
			return;
		}
		List<DataType> candidates = new ArrayList<DataType>();
		archive.findDataTypes(api, candidates);
		for (DataType candidate : candidates) {
			if (candidate instanceof FunctionDefinition) {
				new ApplyFunctionSignatureCmd(function.getEntryPoint(), (FunctionDefinition) candidate,
						SourceType.ANALYSIS).applyTo(currentProgram);
				return;
			}
		}
	}

	private DataTypeManager getWindowsArchive() {
		if (this.windowsArchive == null && !this.windowsArchiveMissing) {
			int bits = currentProgram.getDefaultPointerSize() * 8;
			try {
				ResourceFile archiveFile = Application
						.findDataFileInAnyModule("typeinfo/win32/windows_vs12_" + bits + ".gdt");
				if (archiveFile != null) {
					this.windowsArchive = FileDataTypeManager.openFileArchive(archiveFile, false);
				}
			} catch (IOException e) {
				printerr("Could not open the Windows data type archive: " + e.getMessage());
			}
			this.windowsArchiveMissing = this.windowsArchive == null;
		}
		return this.windowsArchive;
	}

	private void closeWindowsArchive() {
		if (this.windowsArchive != null) {
			this.windowsArchive.close();
			this.windowsArchive = null;
		}
	}

	private int getBitness(ApiScoutResultEntry entry) {
		Matcher bitness = BITNESS_OF_DLL.matcher(entry.dll == null ? "" : entry.dll);
		return bitness.find() ? Integer.parseInt(bitness.group(1)) : currentProgram.getDefaultPointerSize() * 8;
	}

	private String getDllName(ApiScoutResultEntry entry) {
		return entry.dll == null ? "unknown" : entry.dll.replaceAll("\\(\\d+ bit\\)$", "");
	}

	private String getLibraryName(ApiScoutResultEntry entry) {
		return getDllName(entry).toUpperCase();
	}

	private String getLabelName(ApiScoutResultEntry entry) {
		Matcher ordinalOnly = ORDINAL_ONLY_API.matcher(entry.api);
		if (ordinalOnly.matches()) {
			// exported by ordinal only, so the API DB has no name for it
			return getDllName(entry) + "_ordinal_" + ordinalOnly.group(1);
		}
		return entry.api;
	}

	private void configureTableColumns(TableChooserDialog tableChooserDialog) {
		StringColumnDisplay apiColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "API";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ApiScoutResultEntry entry = ((ApiRow) rowObject).entry;
				return entry.api == null ? "" : getLabelName(entry);
			}
		};

		StringColumnDisplay dllColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Library";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return getDllName(((ApiRow) rowObject).entry);
			}
		};

		StringColumnDisplay addressColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "API Address";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return Long.toHexString(((ApiRow) rowObject).entry.apiAddress);
			}
		};
		tableChooserDialog.addCustomColumn(apiColumn);
		tableChooserDialog.addCustomColumn(dllColumn);
		tableChooserDialog.addCustomColumn(addressColumn);
	}

	private TableChooserExecutor createTableExecutor() {
		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Annotate";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				GhidraScout.this.annotate(((ApiRow) rowObject).entry);
				return false; // don't remove row from display table
			}
		};
		return executor;
	}

	class MemoryRegion {
		Address start;
		List<MemoryBlock> blocks = new ArrayList<MemoryBlock>();

		public MemoryRegion(MemoryBlock block) {
			this.start = block.getStart();
			this.blocks.add(block);
		}
	}

	class ApiScoutResultEntry {
		String api;
		String dll;
		long apiAddress;
		long offset;
		transient Address address;

		public String toString() {
			return String.join(" ", this.api, Long.toHexString(this.apiAddress), this.dll, Long.toHexString(this.offset));
		}
	}

	class ApiRow implements AddressableRowObject {
		ApiScoutResultEntry entry;

		public ApiRow(ApiScoutResultEntry entry) {
			this.entry = entry;
		}

		@Override
		public Address getAddress() {
			return this.entry.address;
		}
	}
}
