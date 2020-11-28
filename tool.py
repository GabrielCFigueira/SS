import sys
import json

program = sys.argv[1]
pattern = sys.argv[2]

global vardict
vardict = {}
global flows
flows = []

class VarObj:
    def __init__(self, name, taint):
        self.name = name
        self.taint = taint
    """
    def setSources(self, taint, sources):
        self.taint = taint
        for s in sources:
            if s not in self.sources:
                self.sources.append(s)
   
    def setSans(self, taint, sans):
        self.taint = taint
        for s in sans:
            if s not in self.sans:
                self.sans.appen(s)
      
    def setValues(self, taint, sources, sans):
        self.setSources(taint, sources)
        self.setSans(taint, sans)
    """

class Taint:
    def __init__(self, state, sources, sans):
        self.state = state
        self.sources = sources
        self.sans = sans

class Node:
    def __init__(self):
        self.taint = Taint("u", [], [])


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
                taint = Taint("t", [self.name], [])
                vardict[self.name] = VarObj(self.name, taint)
            else:
                vardict[self.name] = VarObj(self.name, Taint("u", [], []))
        
        self.taint = vardict[self.name].taint


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
        self.taint = self.expression.taint


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

        self.taint = self.right.taint
        vardict[self.left.name].taint = self.right.taint

        if self.taint.state == "t" and self.left.name in pattern['sinks']: #FIXME sans
            flows += [pattern['vulnerability'], self.taint.sources, self.taint.sans, self.left.name]

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

        self.taint = self.callee.taint
        for arg in self.arguments:
            arg.parse(pattern)
            if arg.taint.state == "t" or arg.taint.state == "s" and self.taint.state == "u":
                self.taint = arg.taint

        if self.taint.state == "t" and self.callee.name in pattern['sanitizers'] and vardict[self.callee.name].taint.state != "t": 
            self.taint = Taint("s", self.taint.sources, self.taint.sans + [self.callee.name])


        if self.taint.state == "t" and self.callee.name in pattern['sinks']: #FIXME sans
            flows += [pattern['vulnerability'], self.taint.sources, self.taint.sans, self.callee.name]




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
        print("afin:", vardict['a'].name, vardict['a'].taint.state)
        print("bfin:", vardict['b'].name, vardict['b'].taint.state)
        print("dfin:", vardict['d'].name, vardict['d'].taint.state)   
        vardict = {}
    print(flows)


'''
f = open(filename + ".json.output", "w")
content = "[{\"vulnerability\":" + vuln + ",\n\"source\":" + str(sources) + ",\n\"sink\":" + str(sinks) + ",\n\"sanitizer\":" + str(sanitizers) + "}]"
f.write(content)
f.close()
'''


analyseSlice(pattern_list, program_json)

