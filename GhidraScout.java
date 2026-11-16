//ApiScout plugin for Ghidra
//@author @mari-mari
//@category ApiScoutForGhidra
//@keybinding
//@menupath
//@toolbar
// Put the script in the Ghidra plugins directory (ghidra_scripts).
// Requires working version of ApiScout (not bundled with this plugin, available here:
// https://github.com/danielplohmann/apiscout)
// When run for the first time, the script will ask for the path to the scout.py (ApiScout root directory)
// and remember it in the user preferences of Ghidra.
// Ctrl+A to choose all found APIs for annotation.
// Headless usage: -postScript GhidraScout.java <path to scout.py> [<path to API DB> ...], annotates all APIs found.

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
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
			this.scoutPyPath = this.initApiScoutPathProperty();
			String dataBasePath = askUserForDatabaseToUse();
			if (!dataBasePath.isEmpty()) {
				dataBasePaths.add(dataBasePath);
			}
		}
		if (this.scoutPyPath == null) {
			printerr("Path to ApiScout's scout.py is not known, nothing to do.");
			return;
		}
		printf("\nProcessing %s\nImage file: %s\n", currentProgram.getName(), currentProgram.getExecutablePath());

		List<ApiScoutResultEntry> foundApis = new ArrayList<ApiScoutResultEntry>();
		for (MemoryRegion region : getMemoryRegions()) {
			foundApis.addAll(scoutRegion(region, dataBasePaths));
		}
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
		tableDialog = createTableChooserDialog("ApiScout results:", createTableExecutor());
		configureTableColumns(tableDialog);
		for (ApiScoutResultEntry entry : foundApis) {
			tableDialog.add(new ApiRow(entry));
		}
		tableDialog.setClosedListener(this::closeWindowsArchive);
		tableDialog.show();
		tableDialog.setMessage("Found apis");
	}

	private String initApiScoutPathProperty() {
		String scoutPyAbsolutePath = Preferences.getProperty(PREFERENCE_SCOUT_PY_PATH);
		if (scoutPyAbsolutePath != null && new File(scoutPyAbsolutePath).isFile()) {
			return scoutPyAbsolutePath;
		}
		try {
			scoutPyAbsolutePath = askFile("Path to ApiScout's scout.py script", "Select").getAbsolutePath();
		} catch (CancelledException e) {
			return null;
		}
		Preferences.setProperty(PREFERENCE_SCOUT_PY_PATH, scoutPyAbsolutePath);
		Preferences.store();
		return scoutPyAbsolutePath;
	}

	private String askUserForDatabaseToUse() {
		String dataBasePath = "";
		List<String> choices = new ArrayList<String>();
		choices.add("default");
		choices.add("other");
		try {
			String choice = askChoice("Choose Api scout DB file", "Default is PATH_TO_API_SCOUT/dbs/*.json", choices,
					"default");
			if ("other".equals(choice)) {
				dataBasePath = askFile("Api Scout DB path", "OK").getAbsolutePath();
				printf("ApiScout DB file(s): %s\n", dataBasePath);
			}
		} catch (CancelledException e) {
		}
		return dataBasePath;
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

	private boolean executeScoutPy(File dumpFile, File jsonFile, Address baseAddress, List<String> dataBasePaths) {
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
			ProcessBuilder builder = new ProcessBuilder(command);
			builder.redirectErrorStream(true);
			Process process;
			try {
				process = builder.start();
			} catch (IOException e) {
				// this interpreter is not installed, try the next one
				continue;
			}
			try {
				StringBuilder output = new StringBuilder();
				try (BufferedReader input = new BufferedReader(
						new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
					String line;
					while ((line = input.readLine()) != null) {
						output.append(line).append("\n");
					}
				}
				int exitCode = process.waitFor();
				if (exitCode != 0) {
					printerr("ApiScout subprocess exited with error code " + exitCode + "\n" + output);
					return false;
				}
				return true;
			} catch (IOException | InterruptedException e) {
				printerr("Running ApiScout failed: " + e);
				return false;
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
			try {
				DataUtilities.createData(currentProgram, entry.address, PointerDataType.dataType, -1,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			} catch (CodeUnitInsertionException e) {
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
				String val = ((ApiRow) rowObject).entry.api;
				return val == null ? "" : val;
			}
		};

		StringColumnDisplay dllColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "DLL";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				String val = ((ApiRow) rowObject).entry.dll;
				return val == null ? "" : val;
			}
		};

		StringColumnDisplay addressColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "API address";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return Long.toHexString(((ApiRow) rowObject).entry.apiAddress);
			}
		};
		tableChooserDialog.addCustomColumn(apiColumn);
		tableChooserDialog.addCustomColumn(addressColumn);
		tableChooserDialog.addCustomColumn(dllColumn);
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
