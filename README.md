# nessusedit
A simple class for editing items in a Nessus report file

Useful when you have a .nessus report file with lots of findings that you want to filter out (false positives, irrelevant informational findings etc). It comes with its own interactive shell for selectively removing findings.

## Dependencies
nessusedit depends on the following modules to work:
- prettytable
- readchar
- lxml

## Usage
### Initialization
```python
from nessusedit import NessusFile

n = NessusFile('somefile.nessus')
```

### Useful methods
- `vulns` returns a list of occurring vulnerabilities and a count grouped by vulnerability name
- `printvulns` prints above data as a pretty table
- `getvulns` returns all vulnerabilities matching the argument dictionary `filter` (or all if empty)
- `removevulns` removes any vulnerabilities matching the argument dictionary `filter` (or all if empty)
- `stepthrough` provides an interactive 'shell' that can be used for stepping through all vulnerabilities and selectively removing them
