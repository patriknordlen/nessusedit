from collections import defaultdict
from prettytable import PrettyTable, ALL
import readchar
import lxml.etree as le
from optparse import OptionParser
from pprint import pprint
import sys

class NessusFile(object):
    def __init__(self, nessusfile):
        self.doc = self.loadnessusfile(nessusfile)

    def loadnessusfile(self, nf):
        with open(nf) as f:
            doc = le.parse(nf)

        return doc

    def vulns(self, filter=None):
        vulns = defaultdict(int)

        for elem in self.doc.xpath("//ReportItem[%s]" % self.buildfilter(filter)):
            vulns[elem.attrib['pluginName']] += 1

        return sorted(vulns.items(), key=lambda(k,v): v, reverse=True)

    def printsummary(self, filter=None):
        t = PrettyTable(['pluginName','count'])

        for k,v in self.vulns(filter):
            t.add_row([k,v])

        print t

    def printvuln(self, elem):
        if self.doc.getpath(elem) == '/ReportItem':
            return False

        t = PrettyTable(['host','port','pluginName','severity','plugin_output'])
        t.add_row([elem.getparent().attrib['name'], elem.attrib['port'], elem.attrib['pluginName'], elem.attrib['severity'], elem.find('plugin_output').text if elem.find('plugin_output') is not None else ""])

        print t
        return True

    def getvulns(self, filter=None, count=-1):
        t = PrettyTable(['host','port','pluginName','path','severity','plugin_output'], hrules=ALL)

        for index,elem in enumerate(self.doc.xpath("//ReportItem[%s]" % self.buildfilter(filter))):
            if index == count:
                break

            t.add_row([elem.getparent().attrib['name'], elem.attrib['port'], elem.attrib['pluginName'], self.doc.getpath(elem), elem.attrib['severity'], elem.find('plugin_output').text if elem.find('plugin_output') is not None else ""])

        print t

    def buildfilter(self, filter):
        filterstr = ''

        if not filter:
            filterstr = '*'
        else:
            # The 'host' field is a special case as it belongs to the parent node rather
            # than the actual ReportItem node. This semi-ugly solution addresses this.
            if 'host' in filter.keys():
                filterstr = '../@name="%s"' % filter.pop('host')

                if filter:
                    filterstr += ' and '

            filterstr += ' and '.join(['@%s="%s"' % (k, v) for k,v in filter.iteritems()])

        return filterstr

    def removevulns(self, filter=None, path=None):
        for count,elem in enumerate(self.doc.xpath("//ReportItem[%s]" % self.buildfilter(filter)), 1):
            elem.getparent().remove(elem)

        return count if count else 0

    def stepthrough(self, filter=None):
        abort = False

        for elem in self.doc.xpath("//ReportHost/ReportItem[%s]" % self.buildfilter(filter)):
            if abort:
                break

            if not self.printvuln(elem):
                continue

            done = False
            while not done:
                done = True

                sys.stdout.write("(n)ext,(r)emove,remove (a)ll,(h)elp,(s)ummary,(q)uit => ")
                cmd = readchar.readkey()
                print cmd

                if cmd == 'n':
                    done = True
                elif cmd == 'r':
                    elem.getparent().remove(elem)
                    print "Finding removed"
                elif cmd == 'a':
                    filter = {}
                    properties = raw_input("Remove all based on which properties? ").split(",")
                    if 'host' in properties:
                        filter['host'] = elem.getparent().attrib['name']
                        properties.remove('host')
                    for property in properties:
                        filter[property] = elem.attrib[property]
                    print "Removed %d matching findings" % self.removevulns(filter=filter)
                elif cmd == 'h':
                    print "\nSome help text\n"
                    done = False
                elif cmd == 's':
                    self.printsummary()
                    done = False
                elif cmd == 'q':
                    abort = True
                else:
                    print "Invalid command"
                    done = False


    def tostring(self):
        return le.tostring(self.doc)

    def save(self, file):
        with open(file,'w') as f:
            f.write(self.tostring())

def main():
    optparser = OptionParser()

    options,args = optparser.parse_args()

    if len(args) != 1:
        optparser.print_usage()
        sys.exit(0)

    n = NessusFile(sys.argv[1])
    n.printsummary()
    print "\nStarting stepthrough.\n"
    n.stepthrough()

    f = raw_input("\nStepthrough done. File to write output to: ")
    n.save(f)

if __name__ == "__main__":
    main()
