# nessusedit
A simple script for editing items in a Nessus report file. Comes with its own
class for handling all report file interaction.

Useful when you have a .nessus report file with lots of findings that you want
to filter out (false positives, irrelevant informational findings etc). It can be used
either via CLI, or as a Python module that you import, or as an interactive shell
for selectively removing findings.

## Dependencies
nessusedit depends on the following non-built in modules to work:
- `prettytable`
- `readchar`
- `lxml`

## Usage
To use nessusedit from the CLI, refer to the usage information included in the script:
```
usage: nessusedit.py [-h] [-b BOOLOP] [-f FILTER] [-k] [-r] [-o OUTPUT] [-s]
                     nessusfile

A script for viewing and filtering Nessus report files.

positional arguments:
  nessusfile            Nessus report file to read

optional arguments:
  -h, --help            show this help message and exit
  -b BOOLOP, --boolop BOOLOP
                        Boolean operator to apply between filter terms. Default is 'or'
  -f FILTER, --filter FILTER
                        Filters to apply
  -k, --keep            Keep (only) findings matched by filter
  -r, --remove          Remove findings matched by filter
  -o OUTPUT, --output OUTPUT
                        File to write output to
  -s, --summary         Print a summary of findings

Filters are input as comma-separated key-value pairs, so for instance to keep all
findings that have severity 4 or 5, or come from the host "host1",do the following:

nessusedit.py -k -f severity=4,severity=5,host=host1 -o newfile.nessus oldfile.nessus

You can also negate a filter using "!=" (for instance severity!=0)
```



### Using nessusedit as a Python module
```python
from nessusedit import NessusFile

n = NessusFile('somefile.nessus')
```

### Useful methods
- `vulns` returns a list of occurring vulnerabilities and a count grouped by vulnerability name, ordered by severity
- `printsummary` prints above data as a pretty table
- `getvulns` returns all vulnerabilities matching the argument list of dictionaries `filter` (or all if empty)
- `filtervulns` removes any vulnerabilities matching the argument list of dictionaries `filter` (or all if empty)
- `stepthrough` provides an interactive 'shell' that can be used for stepping through all vulnerabilities and selectively removing them

### Run standalone
You can also execute it directly with a .nessus file as argument, which is more or less a shortcut for loading a .nessus file and calling `stepthrough()`.
