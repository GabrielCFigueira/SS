import sys
import json
import copy

program = sys.argv[1]
pattern = sys.argv[2]

global vardict
vardict = {}
global flows
flows = []


class Taint:
    def __init__(self, state, source, sans):
        self.state = state
        self.source = source
        self.sans = sans

    def __eq__(self, other):
        return self.state == other.state and self.source == other.source and self.sans == other.sans

    def setValues(self, state, source, sans):
        self.source = source
        self.state = state
        self.sans = sans

class Node:
    def __init__(self):
        self.taints = []

    def state(self):
        state = "u"
        for s in self.taints:
            if s.state == "t" or s.state == "s" and state == "u":
                state = s.state
        return state

    def merge(self, taints1, taints2):
        result = taints1
        for t in taints2:
            if t not in taints1:
                result += [t]
        self.taints = results

    def sanitize(self, function):
        for t in self.taints:
            t.setValues("s", t.source, t.sans + [function])

class VarObj(Node):
    def __init__(self, name, taints):
        super().__init__()
        self.name = name
        self.taints = taints


class Literal(Node):

    def __init__(self, node):
        super().__init__()
        self.value = node['value']

    def parse(self, pattern):
        pass

class Variable(Node):

    def __init__(self, node):
        super().__init__()
        self.name = node['name']

    def parse(self, pattern):
        if self.name not in vardict.keys():
            if self.name in pattern['sources']:
                taint = Taint("t", self.name, [])
                vardict[self.name] = VarObj(self.name, [taint])
            else:
                vardict[self.name] = VarObj(self.name, [])
        
        self.taints = copy.deepcopy(vardict[self.name].taints)


class ExpressionStatement(Node):

    def __init__(self, node):
        super().__init__()
        if node['type'] == 'AssignmentExpression':
            self.expression = AssignmentExpression(node)
        elif node['type'] == 'CallExpression':
            self.expression = CallExpression(node)
        elif node['type'] == "Identifier":
            self.expression = Variable(node)
        elif node['type'] == "Literal":
            self.expression = Literal(node)
        else:
            raise ValueError("Shoud have never come here")

    def parse(self, pattern):
        self.expression.parse(pattern)
        self.taints = self.expression.taints


class AssignmentExpression(Node):

    def __init__(self, node):
        super().__init__()
        left = node['left']
        right = node['right']
        
        if left['type'] == "Identifier": #FIXME can left be anything else?
            self.left = Variable(left)
        else:
            raise ValueError("Shoud have never come here")

        self.right = ExpressionStatement(right)

    def parse(self, pattern):
        global flows
        self.left.parse(pattern)
        self.right.parse(pattern)

        self.taints = self.right.taints
        vardict[self.left.name].taints = copy.deepcopy(self.right.taints)

        if self.left.name in pattern['sinks']:
            for taint in self.taints:
                if taint.state == "t":
                    flows += [pattern['vulnerability'], taint.source, taint.sans, self.left.name]
                elif taint.state == "s":
                    flows += [str(pattern['vulnerability']) + " -> Sanitized, but migh still be compromised", taint.source, taint.sans, self.left.name]

            
class CallExpression(Node):

    def __init__(self, node):
        super().__init__()
        callee = node['callee']

        if callee['type'] == "Identifier": #FIXME can left be anything else?
            self.callee = Variable(callee)
        else:
            raise ValueError("Shoud have never come here")

        self.arguments = []
        for arg in node['arguments']:
            self.arguments += [ExpressionStatement(arg)]

    def parse(self, pattern):
        global flows
        self.callee.parse(pattern)
        self.taints = self.callee.taints

        for arg in self.arguments:
            arg.parse(pattern)
            if arg.state() == "t" or arg.state() == "s" and self.state() == "u":
                self.taints = arg.taints #FIXME several sources tainted?

        if self.state() == "t" and self.callee.name in pattern['sanitizers'] and vardict[self.callee.name].state() != "t": 
            self.sanitize(self.callee.name)


        if self.callee.name in pattern['sinks']:
            for taint in self.taints:
                if taint.state == "t":
                    flows += [pattern['vulnerability'], taint.source, taint.sans, self.callee.name]
                elif taint.state == "s":
                    flows += [str(pattern['vulnerability']) + " -> Sanitized, but migh still be compromised", taint.source, taint.sans, self.callee.name]



filename = str(program.split(".")[0])

f = open(pattern, "r")
pattern_str = f.read()
f.close()
pattern_list = json.loads(pattern_str)

f = open(program, "r")
program_str = f.read()
f.close()
program_json = json.loads(program_str)



def analyseSlice(pattern_list, program_json):
    global vardict
    for pat in pattern_list:
        program = []
        for var_json in program_json['body']:
            program += [ExpressionStatement(var_json["expression"])]
        for p in program:
            p.parse(pat)

        #vardict = {}
        print("afin:", vardict['a'].name, vardict['a'].state())
        print("bfin:", vardict['b'].name, vardict['b'].state())
        print("dfin:", vardict['d'].name, vardict['d'].state())   
        vardict = {}
    print(flows)


'''
f = open(filename + ".json.output", "w")
content = "[{\"vulnerability\":" + vuln + ",\n\"source\":" + str(sources) + ",\n\"sink\":" + str(sinks) + ",\n\"sanitizer\":" + str(sanitizers) + "}]"
f.write(content)
f.close()
'''


analyseSlice(pattern_list, program_json)

