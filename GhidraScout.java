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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.address.*;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

public class GhidraScout extends GhidraScript {
	TableChooserDialog tableDialog;
	Address imageBase = null;
	String scoutPyPath = null;

	static String configFile = "ghidrascout.config";
	static String configPropertyName = "apiscout.scout.py.path";

	public void run() throws Exception {
		this.imageBase = currentProgram.getImageBase();
		this.scoutPyPath = this.initApiScoutPathProperty();
		String tempApiScoutOutputFilename = "scout.json";

		if (this.imageBase.equals(this.toAddr(0))) {
			this.imageBase = currentProgram.getMinAddress();
		}
		printf("\nProcessing %s\nImage file: %s\nBase addresss: %x\n", currentProgram.getName(),
				currentProgram.getExecutablePath(), this.imageBase.getOffset());

		executeScoutPy(tempApiScoutOutputFilename, askUserForDatabaseToUse());
		Map<Long, ApiScoutResultEntry> foundApis = readJsonFile(tempApiScoutOutputFilename);
		TableChooserExecutor executor = createTableExecutor();
		tableDialog = createTableChooserDialog("ApiScout results:", executor);
		configureTableColumns(tableDialog);
		addApiRows(tableDialog, foundApis);
		tableDialog.show();
		tableDialog.setMessage("Found apis");
		removeTempFile(tempApiScoutOutputFilename);
	}

	private String initApiScoutPathProperty() {
		Properties prop = new Properties();
		String scoutPyAbsPath = null;
		// String configAbsolutePath = getSourceFile().getParentFile() +
		// System.getProperty("file.separator") + configFile;
		String configAbsolutePath = String.join(System.getProperty("file.separator"),
				getSourceFile().getParentFile().toString(), configFile);
		try {
			prop.load(new BufferedReader(new FileReader(new File(configAbsolutePath))));
			scoutPyAbsPath = prop.getProperty(configPropertyName);
			if (prop.isEmpty() || scoutPyAbsPath == null) {
				scoutPyAbsPath = createAndReadNewProperty(configAbsolutePath);
			}
		} catch (FileNotFoundException e1) {

			scoutPyAbsPath = createAndReadNewProperty(configAbsolutePath);
		} catch (IOException e1) {
			Msg.error(GhidraScout.class, e1);
		}
		return scoutPyAbsPath;
	}

	private String createAndReadNewProperty(String configAbsolutePath) {
		String scoutPyAbsPath = null;
		try {
			scoutPyAbsPath = askFile("Path to ApiScout's scout.py script", "Select").getAbsolutePath();
		} catch (CancelledException e) {
			e.printStackTrace();
		}
		try (OutputStream output = new FileOutputStream(configAbsolutePath)) {
			Properties props = new Properties();
			props.setProperty(configPropertyName, scoutPyAbsPath);
			props.store(output, null);
		} catch (IOException io) {
			io.printStackTrace();
		}
		return scoutPyAbsPath;
	}

	private String askUserForDatabaseToUse() {
		String dataBasePath = "";
		String apiScoutDir = new File(this.scoutPyPath).getParent().toString();
		// String defaultDir = apiScoutDir + System.getProperty("file.separator") +
		// "databases";
		String defaultDir = String.join(System.getProperty("file.separator"), apiScoutDir, "databases");
		List<String> choices = new ArrayList<String>();
		choices.add("default");
		choices.add("other");
		String choice = null;
		try {
			choice = askChoice("Choose Api scout DB file", "Default is PATH_TO_API_SCOUT/dbs/*.db", choices,
					defaultDir);
		} catch (CancelledException e) {
			e.printStackTrace();
		}
		if (choice == "other") {
			try {
				dataBasePath += askFile("Api Scout DB path", "OK");
			} catch (CancelledException e) {
				e.printStackTrace();
			}
			printf("ApiScout DB file(s): %s\n", dataBasePath);
		}
		return dataBasePath;
	}

	private void executeScoutPy(String tempScoutOutputFile, String dataBasePath) {
		ProcessBuilder builder = new ProcessBuilder();
		String executablePath = currentProgram.getExecutablePath();
		String apiScoutOptions = "-s -o";
//		String shellCommandToRun = this.scoutPyPath + " " + apiScoutOptions + " " + tempScoutOutputFile + " "
//				+ executablePath + " " + dataBasePath;
		String shellCommandToRun = String.join(" ", this.scoutPyPath, apiScoutOptions, tempScoutOutputFile,
				executablePath, dataBasePath);
		boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
		if (isWindows) {
			builder.command("cmd.exe", "/c", "py.exe " + shellCommandToRun);
		} else {
			builder.command("sh", "-c", "python " + shellCommandToRun);
		}
		try {
			Process process = builder.start();
			BufferedReader input = new BufferedReader(new InputStreamReader(process.getInputStream()));
			while (input.readLine() != null) {
			} // for some reason, input should be consumed
			int exitCode = process.waitFor();
			printf("ApiScout subprocess exited with error code %d\n", exitCode);

		} catch (Exception e) {
			print(e.toString());
			e.printStackTrace();
		}

	}

	private void removeTempFile(String tempFileName) {
		File file = new File(tempFileName);
		file.delete();
	}

	private Map<Long, GhidraScout.ApiScoutResultEntry> readJsonFile(String filename) {
		Map<Long, ApiScoutResultEntry> results = new HashMap<Long, ApiScoutResultEntry>();
		try {
			Reader reader = Files.newBufferedReader(Paths.get(filename));
			List<ApiScoutResultEntry> map = new Gson().fromJson(reader, new TypeToken<List<ApiScoutResultEntry>>() {
			}.getType());
			map.forEach((value -> results.put(value.apiAddress, value)));
			return results;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;

	}

	private void configureTableColumns(TableChooserDialog tableChooserDialog) {
		StringColumnDisplay apiColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "API";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ApiRow entry = (ApiRow) rowObject;
				String val = entry.entry.api;
				if (val == null) {
					return "";
				}
				return val;
			}
		};

		StringColumnDisplay offsetColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Offset";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ApiRow entry = (ApiRow) rowObject;
				String val = Long.toHexString(entry.entry.offset + GhidraScout.this.imageBase.getOffset());
				if (val == null) {
					return "";
				}
				return val;
			}
		};

		StringColumnDisplay dllColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "DLL";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ApiRow entry = (ApiRow) rowObject;
				String val = entry.entry.dll;
				if (val == null) {

					return "";
				}
				return val;
			}
		};

		StringColumnDisplay addressColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "API address";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ApiRow entry = (ApiRow) rowObject;
				String val = Long.toHexString(entry.entry.apiAddress);
				if (val == null) {
					return "";
				}
				return val;
			}
		};
		tableChooserDialog.addCustomColumn(offsetColumn);
		tableChooserDialog.addCustomColumn(apiColumn);
		tableChooserDialog.addCustomColumn(addressColumn);
		tableChooserDialog.addCustomColumn(dllColumn);
	}

	private void addApiRows(TableChooserDialog tableChooserDialog, Map<Long, ApiScoutResultEntry> map) {
		Integer i = 0;
		for (ApiScoutResultEntry entry : map.values()) {
			tableChooserDialog.add(new ApiRow(i, entry));
			i++;
		}
	}

	private TableChooserExecutor createTableExecutor() {
		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Annotate";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				ApiRow apiRow = (ApiRow) rowObject;
				Address labelAddress = GhidraScout.this.imageBase.add(apiRow.entry.offset);
				try {
					GhidraScout.this.createLabel(labelAddress, apiRow.entry.api, false);
				} catch (Exception e) {
					e.printStackTrace();
				}
				return false; // don't remove row from display table
			}
		};
		return executor;
	}

	class ApiScoutResultEntry {
		String api;
		String dll;
		Long apiAddress;
		Integer offset;

		public ApiScoutResultEntry() {
		}

		public ApiScoutResultEntry(String api, String dll, Long apiAddress, Integer offset) {
			this.api = api;
			this.dll = dll;
			this.apiAddress = apiAddress;
			this.offset = offset;
		}

		public String toString() {
			return String.join(" ", this.api, this.apiAddress.toString(), this.dll, this.offset.toString());
			// return this.api + " " + this.apiAddress + " " + this.dll + " " + this.offset
			// + " ";
		}
	}

	class ApiRow implements AddressableRowObject {
		ApiScoutResultEntry entry;
		Integer id;

		public ApiRow() {
		}

		public ApiRow(Integer key, ApiScoutResultEntry entry) {
			this.entry = entry;
			this.id = key;
		}

		@Override
		public Address getAddress() {
			return GhidraScout.this.toAddr(this.id);
		}
	}
}
