# Analyze LastPass Vault (CLI)

`analyze-lastpass-vault.ps1` is a CLI PowerShell script intended to analyze the content of a LastPass vault in XML format. `analyze-lastpass-vault.ps1` runs on Linux, macOS, or Windows.

It is derived from a GUI PowerShell script available at https://github.com/FuLoRi/Analyze-LastPassVaultGUI.

## Usage

Assuming that you have a LastPass account, you first must fetch the LastPass vault.

### Prerequisite

PowerShell needs to be installed. PowerShell runs on Windows, Linux, and macOS.
Follow the instructions for [PowerShell installation documentation](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.3) to install it on your system.

### Create the Vault File (XML)

1. Open your LastPass vault in a browser
1. Open the Developer Tools of your browser `Ctrl+Shift+I` on Google Chrome or via the menu
1. In the JavaScript Console, past the following code:

```javascript
fetch("https://lastpass.com/getaccts.php", {method: "POST"})
.then(response => response.text())
.then(text => console.log(text.replace(/>/g, ">\n")));
```

4. Click `Show More` and `Copy`
4. Paste the content of the clipboard in a file (example: `vault.xml`)

### Analyze the Vault

The most straightforward command to analyze a LastPass vault is the following:

```
$ analyze-lastpass-vault.ps1 -Vault vault.xml

Analyze LastPass Vault (CLI) version 0.2.0

URL                                  ID                  NameCM  UserNameCM  PasswordCM  ExtraCM  SNote LastTouch              LastModified
---                                  --                  ------  ----------  ----------  -------  ----- ---------              ------------
https://microsoft.com/login          8652323442445729740 CBC     CBC         CBC         CBC      0     7/5/2022 6:51:14 PM    1/14/2023 2:43:40 AM
https://google.com/login             8747761113231875288 CBC     CBC         CBC         CBC      0     7/5/2022 6:51:14 PM    1/14/2023 2:43:40 AM
https://yahoo.com/login              9083672910973725135 CBC     CBC         CBC         CBC      0     7/5/2022 6:51:14 PM    1/14/2023 2:43:40 AM
https://facebook.com                 5931619513392039774 CBC     CBC         CBC         CBC      0     7/5/2022 6:51:14 PM    1/14/2023 2:43:40 AM
...
```

To generate a file (CSV, JSON, or HTML), you can provide an output file at the command line:

```
$ analyze-lastpass-vault.ps1 -Vault vault.xml -OutFile vault.csv
...
```

To extract most of the fields from the vault file, add the option `-All`:

```
$ analyze-lastpass-vault.ps1 -Vault vault.xml -OutFile vault.json -All
...
```

For more details about the available options:

```
$ analyze-lastpass-vault.ps1 -?
...
```

## License

`analyze-lastpass-vault.ps1` is derived from https://github.com/FuLoRi/Analyze-LastPassVaultGUI released under a GPL-3.0 License.

To comply with the license of the original work, `analyze-lastpass-vault.ps1` is also released under a [GPL-3.0 license](LICENSE).