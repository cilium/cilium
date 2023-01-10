#!/usr/bin/env python

import sys
from docutils.core import publish_doctree
from datetime import datetime


class ParseSection(object):

    @property
    def date(self):
        return datetime.strptime(self._meta.get("date"), "%Y-%m-%d")

    @property
    def unixtime(self):
        return int(self.date.strftime("%s"))

    def __init__(self, section):
        self._section = section
        self._meta = {}
        self._invalid = False

    def parse(self):
        if self._section.tagname != "section":
            return False

        children = self._section.children

        self._parse_title(children[0])
        self._parse_metadata(children[1])
        self._parse_changelog(children[2:])
        return self

    def _parse_title(self, title):
        try:
            self._meta["version"] = float(
                title.astext().lower().strip("version"))
        except:
            self._invalid = True

    def _parse_metadata(self, metadata):
        for x in metadata:
            self._meta[x.children[0].astext()] = x.children[1].astext()

    def _parse_changelog(self, body):
        self._changelog = ""
        for section in body:
            data = [x for x in section.astext().split("\n") if len(x) > 0]
            self._changelog += "\n    ".join(data)

    def export(self):
        if self._invalid:
            return False
        return """cilium ({1}) zesty; urgency=medium
  * Changes:
    commit: {4}
    {0._changelog}

 -- Cilium Team <info@cilium.io>  {3}
        """.format(
            self,
            self._meta.get("version"),
            self._meta.get("author"),
            self.date.strftime("%a, %d %b %Y %H:%M:%S +0000"),
            self._meta.get("commit"))


def main():
    data = ""
    with open(sys.argv[1], 'r') as f:
        data = f.readlines()

    doctree = publish_doctree("".join(data))

    result = []
    for x in doctree:
        p = ParseSection(x)
        if p.parse():
            result.append(p)

    for section in sorted(result, key=lambda x: x.unixtime, reverse=True):
        log = section.export()
        if log:
            print log


if __name__ == "__main__":
    main()
