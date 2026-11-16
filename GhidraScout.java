//ApiScout plugin for Ghidra
//@author @mari-mari
//@category ApiScoutForGhidra
//@keybinding
//@menupath
//@toolbar
// Put the script in the Ghidra plugins directory (ghidra_scripts).
// Requires working version of ApiScout (not bundled with this plugin, available here:
// https://github.com/danielplohmann/apiscout)
// When run for the first time, the script will ask for the path to the scout.py (ApiScout root directory).
// Ctrl+A to choose all found APIs for annotation.
// Headless usage: -postScript GhidraScout.java <path to scout.py> [<path to API DB> ...], annotates all APIs found.

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class GhidraScout extends GhidraScript {
	TableChooserDialog tableDialog;
	String scoutPyPath = null;

	static String configFile = "ghidrascout.config";
	static String configPropertyName = "apiscout.scout.py.path";
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
			printf("Annotated %d API references\n", annotated);
			return;
		}
		tableDialog = createTableChooserDialog("ApiScout results:", createTableExecutor());
		configureTableColumns(tableDialog);
		for (ApiScoutResultEntry entry : foundApis) {
			tableDialog.add(new ApiRow(entry));
		}
		tableDialog.show();
		tableDialog.setMessage("Found apis");
	}

	private String initApiScoutPathProperty() {
		Properties prop = new Properties();
		String scoutPyAbsolutePath = null;
		File config = new File(getSourceFile().getParentFile().getAbsolutePath(), configFile);
		if (config.isFile()) {
			try (InputStream input = new FileInputStream(config)) {
				prop.load(input);
				scoutPyAbsolutePath = prop.getProperty(configPropertyName);
			} catch (IOException e) {
				printerr("Could not read " + config + ": " + e.getMessage());
			}
		}
		if (scoutPyAbsolutePath == null || !new File(scoutPyAbsolutePath).isFile()) {
			scoutPyAbsolutePath = createAndReadNewProperty(config);
		}
		return scoutPyAbsolutePath;
	}

	private String createAndReadNewProperty(File config) {
		String scoutPyAbsolutePath = null;
		try {
			scoutPyAbsolutePath = askFile("Path to ApiScout's scout.py script", "Select").getAbsolutePath();
		} catch (CancelledException e) {
			return null;
		}
		try (OutputStream output = new FileOutputStream(config)) {
			Properties props = new Properties();
			props.setProperty(configPropertyName, scoutPyAbsolutePath);
			props.store(output, null);
		} catch (IOException e) {
			printerr("Could not store " + config + ": " + e.getMessage());
		}
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
				for (MemoryBlock block : region.blocks) {
					byte[] content = new byte[(int) block.getSize()];
					block.getBytes(block.getStart(), content);
					output.write(content);
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

	private boolean annotate(ApiScoutResultEntry entry) {
		if (entry.api == null || entry.api.isEmpty()) {
			return false;
		}
		try {
			Data data = getDataAt(entry.address);
			if (data == null || !data.isDefined()) {
				try {
					createData(entry.address, PointerDataType.dataType);
				} catch (Exception e) {
					// something else is defined here already, the label is still of use
				}
			}
			createLabel(entry.address, SymbolUtilities.replaceInvalidChars(getLabelName(entry), true), true);
			return true;
		} catch (Exception e) {
			printerr("Could not annotate " + entry.address + " with " + entry.api + ": " + e.getMessage());
			return false;
		}
	}

	private String getLabelName(ApiScoutResultEntry entry) {
		Matcher ordinalOnly = ORDINAL_ONLY_API.matcher(entry.api);
		if (ordinalOnly.matches()) {
			// exported by ordinal only, so the API DB has no name for it
			String dllName = entry.dll == null ? "unknown" : entry.dll.replaceAll("\\(\\d+ bit\\)$", "");
			return dllName + "_ordinal_" + ordinalOnly.group(1);
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
