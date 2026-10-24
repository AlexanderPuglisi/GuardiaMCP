# Guardia MCP step by step

**by Alexander Puglisi** · [Versione italiana](GUIDA.md)

This guide takes you from the download to your first protected server, with real screenshots of the
app. The pictures come from a fake PC built for the purpose (`scripts/make_tutorial.py`): names,
paths and secrets are made up.

No programming needed. You need Windows (tested on Windows 11) and five minutes.

---

## 1. Download and check

1. Open the [**Releases**](https://github.com/AlexanderPuglisi/guardia-mcp/releases/latest) page and
   download two files: `GuardiaMCP-0.2.3-windows-x64.zip` and `SHA256SUMS.txt`.
2. Check that the zip is the right one. Open **PowerShell** (Start menu → type `PowerShell` →
   Enter), paste these two lines and press Enter:

   ```powershell
   $sum = ((Get-Content "$env:USERPROFILE\Downloads\SHA256SUMS.txt" | Select-String 'windows-x64.zip').Line -split '\s+')[0]
   (Get-FileHash "$env:USERPROFILE\Downloads\GuardiaMCP-0.2.3-windows-x64.zip").Hash -eq $sum
   ```

   It must print **True**. If it prints `False`, do not open the zip: download it again.

## 2. Extract and open

1. Right-click the zip → **Extract All** → pick a folder you will not move, for example
   `C:\Users\YOUR-NAME`. A `GuardiaMCP` folder is created. Always extract first: the programs do not
   work when started from inside the zip.
2. Inside there are two programs:
   - **`GuardiaMCP.exe`**: the app with the window, the one you use (red shield icon, type
     *Application*). Next to it there is a small `GuardiaMCP.exe.config` file with the same name:
     leave it there, it is not the program;
   - **`guardia.exe`**: the command line; the Shield and the AI apps use it too, do not delete it.
3. Double-click **`GuardiaMCP.exe`**. The first time Windows may show a blue warning ("Windows
   protected your PC") because the program is not code-signed yet: choose **More info** → **Run
   anyway**.

> Using **Claude Desktop from the Microsoft Store**? Open Guardia from here at least once **before**
> protecting servers, so its data folder is created in the right place.

## 3. Overview: how your PC is doing

When it opens, Guardia runs the first scan by itself. The card at the top gives the verdict in one
sentence; below, the **Overview** counts problems by severity and shows the ones to look at first.
The scan never runs the servers and never changes their configuration: it only writes its own notes
(the baseline and the ledger) in Guardia's data folder.

![Overview](tutorial/en-01-overview.png)

What the verdict means:

- **All clear**: Guardia checked every server and skill it found and no rule found a risk. Scan
  again whenever you add or update a server.
- **No MCP servers or skills on this PC**: there is nothing to check, so there is nothing risky here
  and nothing to protect. When you install a server in Claude, Cursor, VS Code or another AI app,
  come back and press **Scan now**.
- **Nothing serious, things to improve** or **Serious problems to fix**: start from *Look at these
  first*.

## 4. Findings: what is there and how to fix it

**Findings** lists everything, most serious first. Use the filters at the top (Severe, Medium,
Minor) or the search box.

![Findings](tutorial/en-02-findings.png)

Click a finding to see the details:

- **Where**: the exact file. The small icon next to the path copies it, ready to paste into File
  Explorer; the line is underneath.
- **Found**: what Guardia saw (secrets are never shown in full).
- **Why**: the risk, in plain words.
- **How to fix**: what to do, step by step.

![Finding detail](tutorial/en-03-finding-detail.png)

After fixing, press **Scan now**: the finding goes away. One exception: the "changed since last
time" findings (rug pull, rules G03) stay until you confirm that the change is wanted with **Accept
changes**, under the list in **Findings** or in the server's detail. Accept only changes you
expect, for example after updating a server yourself.

## 5. Shield: protect a server while the AI works

The **Shield** sits between the AI app and an MCP server and checks every message.

1. **Close the AI app** (Claude, Cursor, VS Code…). Claude Desktop keeps running in the system tray
   after you close its window: right-click its icon next to the clock → **Quit**.
2. In **Shield**, press **Protect** next to the server and confirm. Guardia backs up the file and
   changes only that entry.
3. Reopen the AI app and use it as usual.

![Shield](tutorial/en-04-shield.png)

From then on:

- **new or changed** tools of that server stay hidden until you approve them, in the same section;
- poisoned tools, secrets and password requests are stopped even without rules of your own;
- every decision goes into the **Ledger**.

To undo: **Remove protection** next to the server.

No **Protect** button next to a server? That server cannot be connected automatically:

- remote servers (an internet address instead of a program): the Shield protects only local servers
  for now;
- Claude Desktop extensions, plugins and configurations managed by your company: their files are
  not meant to be edited;
- files with comments or in TOML format (Codex): Guardia shows the text to paste with **Copy the text
  to paste**, so you can make the change by hand.

## 6. Your own rules (optional)

Rules let you decide what to block, hide or be asked about.

1. In **Shield** → **Shield rules** press **Create the example rules**: the editor opens with
   Guardia's example, 5 useful rules each explained by a comment. Nothing is saved yet.
2. Change what you want and press **Save and approve**. If something is wrong, Guardia shows the
   line and saves nothing. To throw the example away, press **Close**.

![Rules editor](tutorial/en-05-rules-editor.png)

Already have rules? **Edit rules** opens them in the same editor. If you change the rules file by
hand outside the app, the Shield blocks protected servers until you approve it again with **Approve
the rules**: this is what stops someone else from changing your rules behind your back.

## 7. The confirmation window

When a rule says `ask`, this small always-on-top window appears. Read who asks for what and why,
then choose **Allow** or **Block**. No answer within 45 seconds means **block**. The AI cannot answer
for you.

![Confirmation window](tutorial/en-08-confirm.png)

## 8. Settings and history

In **Settings** you choose the language and what to scan, and add your project folders. Every change
is noted in the **History of changes** with the previous value: **Restore** puts it back.

![Settings](tutorial/en-06-settings.png)

## 9. Ledger: a history that cannot be rewritten

The **Ledger** holds every scan and every Shield decision in a signed chain: if someone deletes or
changes a line, Guardia notices.

![Ledger](tutorial/en-07-ledger.png)

## 10. Update to a new version

1. Close Guardia and the AI apps (Claude from the tray too).
2. Download and check the new zip as in step 1.
3. Extract it **to the same place** as before (for example `C:\Users\YOUR-NAME`). When Windows asks,
   choose **Replace the files in the destination**. Your data (rules, ledger, settings) is in another
   folder and stays as it is.
4. Open `GuardiaMCP.exe`. If you extracted the new version somewhere else, the **Shield** section
   shows **Relink to this Guardia** next to protected servers: press it, so they start from the new
   folder.

---

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| "Windows protected your PC" | The program is not code-signed | **More info** → **Run anyway** |
| "Smart App Control blocked an app" | Windows 11 with Smart App Control on blocks unsigned programs, with no "Run anyway" | Install from source (see the README), or switch Smart App Control off in *Windows Security* → *App & browser control* (Windows lets you switch it back on only by reinstalling, so choose calmly) |
| The antivirus deletes or blocks `guardia.exe` | Some antivirus products mistake programs built with PyInstaller for threats | Check the zip with step 1; if it prints **True**, report the false positive to your antivirus vendor, or install from source |
| An error about `python312.dll` | The program was started from inside the zip | Extract the zip first (step 2) |
| Double-clicking does nothing, or opens a text file | You opened `GuardiaMCP.exe.config` | Double-click **`GuardiaMCP.exe`**, the one with the red shield icon and type *Application* |
| `Failed to resolve Python.Runtime.Loader.Initialize` | Only with version **0.2.0**: Windows blocked the libraries of the downloaded zip | Use the latest version |
| Finding **G12-006** "Configuration file could not be analyzed" | Guardia could not read that file, so the servers in it were not checked and the analysis is marked incomplete. **Found** gives the line and what is wrong | Open the file and fix it. In Windows paths inside JSON files write `\\` (two backslashes) |
| A server shows **Relink to this Guardia**, or does not start after **Protect** | Guardia's folder was moved, renamed or deleted | Press **Relink to this Guardia**, then restart the AI app |
| A protected server's changes do not apply | The AI app was still running | Quit the AI app completely (Claude from the tray too) and open it again |

To uninstall, follow the **Uninstall** section of the [README](../README.md).
Questions or problems: open an *issue* on GitHub; for a vulnerability use **Security → Report a
vulnerability**.
