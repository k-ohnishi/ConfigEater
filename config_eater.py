import io
import re
import json

__all__ = []

class TreeItem(object):
    def __init__(self, value, branch=None, is_root=False):
        self.value = value
        self.branch = branch
        if self.branch is None:
            self.branch = []
        self.is_root = is_root

    def is_leaf(self):
        if self.branch is None or len(self.branch) == 0:
            return True
        return False

    def is_spine(self):
        return (not self.is_leaf())

    def get(self):
        return self.value

    def add_branch_item(self, branch_item):
        if isinstance(branch_item, TreeItem):
            self.branch.append(branch_item)
        else:
            raise TypeError("branch_item is not a TreeItem instance.")

    def print_tree(self, indent=""):
        print(indent + str(self.value))
        if self.is_spine():
            for t in self.branch:
                t.print_tree(indent=indent+" ")

    def __str__(self):
        return str(self.value)

class StructuredText(object):
    def __init__(self, filename=None, lines=None):
        self.__lines = None
        self.name = None
        if lines is not None and type(lines) is list:
            self.__lines = []
            for i, t in enumerate(lines):
                if type(t) is str:
                    self.__lines.append(t)
                else:
                    raise ValueError("lines has non-string value at line: " + str(i))
            self.origin = "lines"
        elif filename is not None:
            self.name = filename
            with open(filename, "r") as f:
                self.__lines = f.readlines()
            for i, t in enumerate(self.__lines):
                self.__lines[i] = t.replace('\r', '').replace('\n', '')
            self.origin = filename
        self.forest = None
        self.re_root = re.compile('^(?P<value>[^\s]+.*)$')
        self.re_branch = re.compile('^(?P<blank>[\s]+)(?P<value>.*)$')

    def get_forest(self):
        """
           Returns TreeItem list
        """
        if self.forest is not None:
            return self.forest
        d = []
        branch_stack = []
        for i, t in enumerate(self.__lines):
            print("branch_stack: " + str(branch_stack))
            print("i: {}, t: {}".format(i, t))
            g = self.re_root.match(t)
            if g:
                d.append(TreeItem({"line": i, "value": g.group("value"), "blanks": ""}, is_root=True))
                branch_stack = [d[-1]]        # clear stack and set a root
                continue
            
            #print("last_item" + str(branch_stack[-1].get()))
            g = self.re_branch.match(t)
            if g is None:
                # !!?!
                raise ValueError("Unknown: line: " + str(i) + " value: " + t)
            #if len(branch_stack) == 0:
            #    # !!?!
            #    raise ValueError("non-root line without any root")
            blanks = g.group("blank")
            item = TreeItem(g.group("value"), is_root=False)
            p = (TreeItem({"line": i, "value": g.group("value"), "blanks": blanks}, is_root=False))
            d.append(p)

            parent = branch_stack[-1]
            blank_parent = parent.get()["blanks"]

            if blank_parent == "":              # just under the root
                parent.add_branch_item(p)       # add p to parent's branch
                branch_stack.append(p)
                continue
            elif blanks ==  blank_parent:         # if same level of top-of-stack
                branch_stack.pop()              # replace the top-op-stack
                parent = branch_stack[-1]       # parent is one upper level
                parent.add_branch_item(p)       # add p to parent's branch
                branch_stack.append(p)
                continue

            blank_base = branch_stack[1].get()["blanks"]        # branch_stack; the child of root
            blank_num = len(blanks)
            base_num  = len(blank_base)

            # lower level or upper level
            #print("blank_num: {} base_num: {}".format(blank_num, base_num))
            if blank_num % base_num != 0:
                raise ValueError("illegal blank count at line: " + str(i))

            level = blank_num // base_num
            parent_level = len(parent.get()["blanks"]) // base_num
            if level > parent_level:       # some bug there; skip level allowed
                parent.add_branch_item(p)
                branch_stack.append(p)
                continue

            # upper level
            while(parent_level >= level):
                # pop stack whlie find the same level
                print("level: {} parent_level: {}".format(level, parent_level))
                parent = branch_stack.pop()
                parent_level = len(parent.get()["blanks"]) // base_num
            #print(branch_stack)
            #print(parent)
            branch_stack.append(parent)  # re-push because popped at above loop
            parent.add_branch_item(p)
            branch_stack.append(p)

        # create forest
        self.forest = []
        for t in d:
            if t.is_root:
                self.forest.append(t)
        return self.forest


class CatalystL3(StructuredText):
    
    
    def __init__(self, filename=None, lines=None):
        super().__init__(filename=filename, lines=lines)
        self.name = None
        self.get_forest()
        self.interfaces = []
        self.vlans = []
        #self.ips = []
        #self.routes = []
        analyzer_list = [
            {"re": re.compile("^(?P<type>interface)\s(?P<int_name>.*)$"), "analyzer": self.interface},
            {"re": re.compile("^(?P<type>vlan)\s(?P<vlans>.*)$"), "analyzer": self.vlan},
            {"re": re.compile("^(?P<type>hostname)\s(?P<hostname>.*)$"), "analyzer": self.hostname},
            ]
        
        
        for t in self.forest:
            for v in analyzer_list:
                m = v["re"].match(t.get()["value"])
                if m:
                    v["analyzer"](m, t)
        used_vlans = set()
        for t in self.interfaces:
            used_vlans |= set(t["swithcport trunk vlan"])
        self.used_vlans = sorted(list(used_vlans))

    def hostname(self, match, spine):
        self.name = match.group("hostname")


    def vlanlist_to_list(self, vlan_list):
        v = []
        vl = vlan_list.split(',')
        for t in vl:
            if t == "none":
                v = None
                break
            t = t.replace("add ", "")   # remove add
            t2 = t.split("-")
            if len(t2) == 1:  # single vlan
                v.append(int(t2[0]))
            else:             # vlan range
                v.extend(list(range(int(t2[0]),int(t2[1])+1)))
        return v

    def interface(self, match, spine):
        parser = {
            "swithcport trunk vlan": {"re": re.compile("^(?P<type>switchport trunk allowed vlan )(?P<values>.*)$"), "type": "vlan"},
            "swithcport access vlan": {"re": re.compile("^(?P<type>switchport access vlan )(?P<values>.*)$"), "type": "vlan"},
            "switchport mode": {"re": re.compile("^(?P<type>switchport mode )(?P<values>.*)$"), "type": "mode"},
            "shutdown": {"re": re.compile("^(?P<values>(no |)shutdown)$"), "type": "shut"},
            }
        d = {}
        for t in spine.branch:
            value = t.get()["value"]
            print(value)
            for k, v in parser.items():
                g = v["re"].match(value)
                if g:
                    print(k)
                    if v["type"] == "vlan":
                        if k not in d:
                            d[k] = []
                        d[k].extend(self.vlanlist_to_list(g["values"]))
                    else:
                        d[k] = g["values"]
        d["name"] = match.group("int_name")
        self.interfaces.append(d)

    def vlan(self, match, spine):
        self.vlans.extend(self.vlanlist_to_list(match.group("vlans")))
