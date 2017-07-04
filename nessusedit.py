#!/usr/bin/env python

from argparse import ArgumentParser, RawTextHelpFormatter
from pprint import pprint
from prettytable import PrettyTable, ALL
from textwrap import fill
import lxml.etree as le
import readchar
import sys

class NessusFile(object):
    def __init__(self, nessusfile):
        self.doc = self.loadnessusfile(nessusfile)
        self.filter = '*'

    def loadnessusfile(self, nf):
        with open(nf) as f:
            doc = le.parse(nf)

        return doc

    def vulns(self):
        vulns = {}

        for elem in self.getvulns():
            if not elem.attrib['pluginName'] in vulns:
                vulns[elem.attrib['pluginName']] = {"severity":elem.attrib['severity'],
                                                    "count":1,
                                                    "port":elem.attrib['port'],
                                                    "hosts":[elem.getparent().attrib['name']]}
            else:
                vulns[elem.attrib['pluginName']]['count'] += 1
                if elem.getparent().attrib['name'] not in vulns[elem.attrib['pluginName']]['hosts']:
                    vulns[elem.attrib['pluginName']]['hosts'].append(elem.getparent().attrib['name'])

        return sorted(vulns.items(), key=lambda(k,v): (v['severity'], v['count']), reverse=True)

    def printsummary(self, filter=None):
        t = PrettyTable(['pluginName','port','severity','count','hosts'], hrules=ALL)

        if self.vulns():
            for k,v in self.vulns():
                t.add_row([k, v['port'], v['severity'], v['count'], '\n'.join(v['hosts'])])

            print t


    def printvuln(self, elem):
        if self.doc.getpath(elem) == '/ReportItem':
            return False

        t = PrettyTable(['host','port','pluginName','severity','plugin_output', 'synopsis', 'solution'])
        t.add_row([elem.getparent().attrib['name'],
                   elem.attrib['port'],
                   fill(elem.attrib['pluginName'], width=70),
                   elem.attrib['severity'],
                   fill(elem.findtext('plugin_output') or "", width=70),
                   fill(elem.findtext('synopsis') or "", width=70),
                   fill(elem.findtext('solution') or "", width=70)])

        print t
        return True

    def getvulns(self, filter=None):
        f = filter or self.filter
        return self.doc.xpath("//ReportItem[%s]" % f, namespaces={"re": "http://exslt.org/regular-expressions"})

    def setfilter(self, filter, boolop=None, mode=None):
        self.filter = self.createfilter(filter)

    def createfilter(self, filter, boolop='and', mode='include'):
        filterstr = ''
        boolstr = ' %s ' % boolop

        if not filter:
            filterstr = '*'
        else:
            filterlist = []

            for f in filter:
                k,v = f.items()[0]

                negate = False
                if k.endswith('!'):
                    k = k.replace('!','')
                    negate = True

                if k == 'host':
                    node = '../@name'
                else:
                    node = '@%s' % k

                if '*' in v:
                    v = v.replace('.','\.')
                    v = v.replace('*','.*')
                    fitem = 're:match(%s,"^%s$")' % (node,v)
                else:
                    fitem = '%s="%s"' % (node,v)

                if negate:
                    fitem = 'not(%s)' % fitem

                filterlist.append(fitem)

            filterstr = boolstr.join(filterlist)

        if mode == 'include':
            return filterstr
        elif mode == 'exclude':
            return 'not(%s)' % filterstr

    def filtervulns(self, filter=None):
        count = 0
        for count,elem in enumerate(self.getvulns(filter), 1):
            elem.getparent().remove(elem)

        return count

    def stepthrough(self, filter=None):
        abort = False

        vulncount = len(self.getvulns())
        for count,elem in enumerate(self.getvulns(), 1):
            if abort:
                break

            if not self.printvuln(elem):
                continue

            done = False
            while not done:
                done = True

                sys.stdout.write("%d/%d (n)ext,(r)emove,remove (a)ll,(h)elp,(s)ummary,(q)uit => " % (count, vulncount))
                cmd = readchar.readkey()
                print cmd

                if cmd == 'n' or cmd == '\r':
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
                    print "Removed %d matching findings" % self.filtervulns(self.createfilter([filter]))
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
        if file == '-':
            f = sys.stdout
        else:
            f = open(file,'w')

        f.write(self.tostring() + '\n')
        f.close()


def main():
    argparser = ArgumentParser(description='A script for viewing and filtering Nessus report files.', \
                               epilog='Filters are input as comma-separated key-value pairs, so for instance ' \
                                      'to keep all\nfindings that have severity 4 or 5, or come from the host "host1",' \
                                      'do the following:\n\n' \
                                      'nessusedit.py -k -f severity=4,severity=5,host=host1 -o newfile.nessus oldfile.nessus\n\n' \
                                      'You can also negate a filter using "!=" (for instance severity!=0)',
                               formatter_class=RawTextHelpFormatter)
    argparser.add_argument('-b','--boolop', help="Boolean operator to apply between filter terms. Default is 'or'", default='or')
    argparser.add_argument('-f','--filter', help="Filters to apply")
    argparser.add_argument('-k','--keep', help='Keep (only) findings matched by filter', action='store_true')
    argparser.add_argument('-r','--remove', help='Remove findings matched by filter', action='store_true')
    argparser.add_argument('-o','--output', help="File to write output to")
    argparser.add_argument('-n','--no-output', help="Don't write output to file", action='store_true')
    argparser.add_argument('-s','--summary', help="Print a summary of findings", action='store_true')
    argparser.add_argument('nessusfile', help='Nessus report file to read')
    args = argparser.parse_args()

    if not args.nessusfile:
        optparser.print_usage()
        sys.exit(0)

    n = NessusFile(args.nessusfile)

    if args.filter:
        if args.keep:
            mode = 'exclude'
        else:
            mode = 'include'

        n.setfilter(filter=[dict([arg.split('=')]) for arg in args.filter.split(',')],boolop=args.boolop,mode=mode)
    else:
        filter = None

    if args.summary:
        n.printsummary()
        sys.exit(0)
    elif args.remove or args.keep:
        n.filtervulns()
    else:
        n.printsummary()
        print "\nPress any key to continue...\n"
        readchar.readkey()
        print "\nStarting stepthrough.\n"
        n.stepthrough()

    if not args.no_output:
        if args.output:
            n.save(args.output)
        else:
            f = raw_input("\nFile to write output to: ")
            n.save(f)


if __name__ == "__main__":
    main()
