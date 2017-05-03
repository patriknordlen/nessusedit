#!/usr/bin/env python

from argparse import ArgumentParser
from prettytable import PrettyTable, ALL
import lxml.etree as le
import readchar
import sys

class NessusFile(object):
    def __init__(self, nessusfile):
        self.doc = self.loadnessusfile(nessusfile)

    def loadnessusfile(self, nf):
        with open(nf) as f:
            doc = le.parse(nf)

        return doc

    def vulns(self, filter=None):
        vulns = {}

        for elem in self.doc.xpath("//ReportItem[%s]" % self.buildfilter(filter)):
            if not elem.attrib['pluginName'] in vulns:
                vulns[elem.attrib['pluginName']] = {"severity":elem.attrib['severity'], \
                                                    "count":1}
            else:
                vulns[elem.attrib['pluginName']]['count'] += 1

        return sorted(vulns.items(), key=lambda(k,v): (v['severity'], v['count']), reverse=True)

    def printsummary(self, filter=None):
        t = PrettyTable(['pluginName','severity','count'])

        for k,v in self.vulns(filter):
            t.add_row([k, v['severity'], v['count']])

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

    def buildfilter(self, filter, boolop='and', mode='include'):
        filterstr = ''
        boolstr = ' %s ' % boolop

        if not filter:
            filterstr = '*'
        else:
            filterlist = []

            # The 'host' field is a special case as it belongs to the parent node rather
            # than the actual ReportItem node. This semi-ugly solution addresses this.
            hostfilters = [i.values()[0] for i in filter if 'host' in i]
            if hostfilters:
                filter = [i for i in filter if 'host' not in i]
                filterlist.append(['../@name="%s"' % f for f in hostfilters])

            filterlist += ['@%s="%s"' % i.items()[0] for i in filter]
            filterstr = boolstr.join(filterlist)

        if mode == 'include':
            return filterstr
        elif mode == 'exclude':
            return 'not(%s)' % filterstr
        else:
            return False

    def filtervulns(self, filter=None, boolop='and', mode='include'):
        count = 0
        for count,elem in enumerate(self.doc.xpath("//ReportItem[%s]" % self.buildfilter(filter, boolop=boolop, mode=mode)), 1):
            elem.getparent().remove(elem)

        return count

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
                    print "Removed %d matching findings" % self.filtervulns(filter=filter)
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
    argparser = ArgumentParser()
    argparser.add_argument('-r','--remove', help='Remove findings matched by filter', action='store_true')
    argparser.add_argument('-k','--keep', help='Keep (only) findings matched by filter', action='store_true')
    argparser.add_argument('-s','--summary', help="Print a summary of findings", action='store_true')
    argparser.add_argument('-f','--filter', help="Filters to apply")
    argparser.add_argument('-o','--output', help="File to write output to")
    argparser.add_argument('nessusfile', help='Nessus report file to read')
    args = argparser.parse_args()

    if not args.nessusfile:
        optparser.print_usage()
        sys.exit(0)

    n = NessusFile(args.nessusfile)

    if args.filter:
        filter = [dict([arg.split('=')]) for arg in args.filter.split(',')]
    else:
        filter = None

    if args.summary:
        n.printsummary()
        sys.exit(0)
    elif args.remove:
        n.filtervulns(filter,mode='include',boolop='or')
    elif args.keep:
        n.filtervulns(filter,mode='exclude',boolop='or')
    else:
        n.printsummary()
        print "\nPress any key to continue...\n"
        readchar.readkey()
        print "\nStarting stepthrough.\n"
        n.stepthrough()

    if args.output:
        n.save(args.output)
    else:
        f = raw_input("\nFile to write output to: ")
        n.save(f)


if __name__ == "__main__":
    main()
