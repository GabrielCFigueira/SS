import sys
import json
import copy

program = sys.argv[1]
pattern = sys.argv[2]

global vardict
vardict = {}
global flows
flows = []

global stack, programs
programs = []

class Program:
    def __init__(self, json):
        self.statements = []
        for i in range(len(json['body'])):
            self.statements += [Statement(json['body'][i], ['body', i], json)]

    def parse(self, pattern):
        for s in self.statements:
            s.parse(pattern)


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

class Vuln:
    def __init__(self, name, source, sans, sink):
        self.name = name
        self.source = source
        self.sans = sans
        self.sink = sink

    def toString(self):
        return "\t{\"vulnerability\": \"" + self.name + "\",\n\
\t\"sources\": [\"" + self.source + "\"],\n\
\t\"sanitizers\": " + str(self.sans) + ",\n\
\t\"sinks\": [\"" + self.sink + "\"]}"

    def __eq__(self, other):
        return self.name == other.name and self.source == other.source and self.sans == other.sans and self.sink == other.sink


class Stack:
    def __init__(self):
        self.contexts = []

    def push(self, context):
        self.contexts += [context]

    def pop(self):
        return self.contexts.pop()

    def taints(self):
        result = []
        for context in self.contexts:
            for taint in context:
                if taint not in result:
                    result += [taint]
        return result


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
        self.taints = result

    def sanitize(self, function):
        for t in self.taints:
            t.setValues("s", t.source, t.sans + [function])

    def parse(self):
        global stack
        self.merge(self.taints, copy.deepcopy(stack.taints()))

class VarObj(Node):
    def __init__(self, name, taints):
        super().__init__()
        self.name = name
        self.taints = taints


class Literal(Node):

    def __init__(self, node, keys, program_json):
        super().__init__()
        self.value = node['value']

    def parse(self, pattern):
        super().parse()

class Variable(Node):

    def __init__(self, node, keys, program_json):
        super().__init__()
        self.name = node['name']

    def parse(self, pattern):
        super().parse()
        if self.name not in vardict.keys():
            match = self.match(self.name, pattern['sources'])
            if match:
                taint = Taint("t", match, [])
                vardict[self.name] = VarObj(self.name, [taint])
            else:
                vardict[self.name] = VarObj(self.name, [])
        
        self.merge(self.taints, copy.deepcopy(vardict[self.name].taints))

    def match(self, name, sources):
        for source in sources: 
            if name == source.split(".")[0]:
                return source #FIXME return only works if pattern only has one source (document.cenas, document.cenas2 both have the same beginning)
        return None

class Statement(Node):

    def __init__(self, node, keys, program_json):
        super().__init__()
        if node['type'] == 'AssignmentExpression':
            self.expression = AssignmentExpression(node, keys, program_json)
        elif node['type'] == 'CallExpression':
            self.expression = CallExpression(node, keys, program_json)
        elif node['type'] == "Identifier":
            self.expression = Variable(node, keys, program_json)
        elif node['type'] == "Literal":
            self.expression = Literal(node, keys, program_json)
        elif node['type'] == "BinaryExpression":
            self.expression = BinaryExpression(node, keys, program_json)
        elif node['type'] == "ExpressionStatement":
            self.expression = Statement(node['expression'], keys + ['expression'], program_json)
        elif node['type'] == "IfStatement":
            self.expression = IfStatement(node, keys, program_json)
        elif node['type'] == "BlockStatement":
            self.expression = BlockStatement(node, keys, program_json)
        elif node['type'] == "WhileStatement":
            self.expression = WhileStatement(node, keys, program_json)
        elif node['type'] == "MemberExpression":
            self.expression = MemberExpression(node, keys, program_json)
        elif node['type'] == "ArrayExpression":
            self.expression = ArrayExpression(node, keys, program_json)  
        elif node['type'] == "LogicalExpression": #FIXME check
            self.expression = BinaryExpression(node, keys, program_json)  
        elif node['type'] == "NewExpression": #FIXME check
            self.expression = CallExpression(node, keys, program_json)
        elif node['type'] == "UnaryExpression": #FIXME check
            self.expression = UnaryExpression(node, keys, program_json)
        elif node['type'] == "UpdateExpression": #FIXME check
            self.expression = UnaryExpression(node, keys, program_json)
        else:
            raise ValueError("Shoud have never come here")

    def parse(self, pattern):
        super().parse()
        self.expression.parse(pattern)
        self.merge(self.taints, self.expression.taints)


class AssignmentExpression(Node):

    def __init__(self, node, keys, program_json):
        super().__init__()
        left = node['left']
        right = node['right']
        
        if left['type'] == "Identifier": #FIXME can left be anything else?
            self.left = Variable(left, keys + ['left'], program_json)
        elif left['type'] == "MemberExpression":    
            self.left = MemberExpression(left, keys + ['left'], program_json)
        else:
            raise ValueError("Shoud have never come here")

        self.right = Statement(right, keys + ['right'], program_json)

    def parse(self, pattern):
        global flows, stack
        super().parse()
        self.left.parse(pattern)
        self.right.parse(pattern)

        self.merge(self.taints, self.right.taints)
        vardict[self.left.name].taints = copy.deepcopy(self.taints) #FIXME name of memberexpression

        if self.left.name in pattern['sinks']:
            for taint in self.taints:
                v = None
                if taint.state == "t":
                    v = Vuln(pattern['vulnerability'], taint.source, taint.sans, self.left.name)
                elif taint.state == "s":
                    v = Vuln(str(pattern['vulnerability']) + " -> Sanitized, but might still be compromised", taint.source, taint.sans, self.left.name)
                if v and v not in flows:
                    flows += [v]

            
class CallExpression(Node): #FIXME: also accepting NewExpressions

    def __init__(self, node, keys, program_json):
        super().__init__()
        callee = node['callee']

        if callee['type'] == "Identifier": #FIXME can left be anything else?
            self.callee = Variable(callee, keys + ['callee'], program_json)
        elif callee['type'] == "MemberExpression":
            self.callee = MemberExpression(callee, keys + ['callee'], program_json)
        else:
            raise ValueError("Shoud have never come here")

        self.arguments = []
        for i in range(len(node['arguments'])):
            self.arguments += [Statement(node['arguments'][i], keys + ['arguments', i], program_json)]

    def parse(self, pattern):
        global flows, stack
        super().parse()
        self.callee.parse(pattern)
        self.merge(self.taints, self.callee.taints)

        for arg in self.arguments:
            arg.parse(pattern)
            self.merge(self.taints, arg.taints)

        if self.state() != "u" and self.callee.name in pattern['sanitizers']: #and vardict[self.callee.name].state() != "t": #FIXME sanitize inside tainted block 
            self.sanitize(self.callee.name)


        if self.callee.name in pattern['sinks']:
            for taint in self.taints:
                v = None
                if taint.state == "t":
                    v = Vuln(pattern['vulnerability'], taint.source, taint.sans, self.callee.name)
                elif taint.state == "s":
                    v = Vuln(str(pattern['vulnerability']) + " -> Sanitized, but might still be compromised", taint.source, taint.sans, self.callee.name)
                if v and v not in flows:
                    flows += [v]


class BinaryExpression(Node): #FIXME also accepting logicalExp ( ||, &&)

    def __init__(self, node, keys, program_json):
        super().__init__()
        left = node['left']
        right = node['right']
        
        self.left = Statement(left, keys + ['left'], program_json)
        self.right = Statement(right, keys + ['right'], program_json)

    def parse(self, pattern):
        global flows
        super().parse()
        self.left.parse(pattern)
        self.right.parse(pattern)

        self.merge(self.right.taints,self.left.taints)

class UnaryExpression(Node): #FIXME not tested

    def __init__(self, node, keys, program_json):
        super().__init__()
        argument = node['argument']
        
        self.argument = Statement(argument, keys + ['argument'], program_json)

    def parse(self, pattern):
        global flows
        super().parse()
        self.argument.parse(pattern)
        self.merge(self.taints, self.argument.taints)





class ArrayExpression(Node): #FIXME not tested

    def __init__(self, node, keys, program_json):
        super().__init__()
        elements = node['elements']
        
        for i in range(len(elements)):
            self.elements += [Statement(elements[i], keys + ['elements', i], program_json)]


    def parse(self, pattern):
        global flows
        super().parse()
        for e in self.elements:
            e.parse(pattern)
            self.merge(self.taints, self.e.taints)

class IfStatement(Node):

    def __init__(self, node, keys, program_json):
        global programs
        super().__init__()
        test = node['test']
        consequent = node['consequent']
        alternate = node['alternate']
        
        if alternate != "passed":
            original_json = copy.deepcopy(program_json)
            json = original_json
            for key in keys:
                json = json[key]

            json['consequent'] = json['alternate']
            json['alternate'] = 'passed'

            node['alternate'] = 'passed'
        
            programs += [Program(original_json)]

        self.test = Statement(test, keys + ['test'], program_json)
        
        if consequent:
            self.consequent = Statement(consequent, keys + ['consequent'], program_json)
        else:
            self.consequent = None


    def parse(self, pattern):
        super().parse()
        self.test.parse(pattern)

        if self.consequent:
            if self.test.state() != "u":
                stack.push(self.test.taints)
            
            self.consequent.parse(pattern)

            if self.test.state() != "u":
                stack.pop()
        

class BlockStatement(Node):

    def __init__(self, node, keys, program_json):
        super().__init__()
        self.statements = []
        for i in range(len(node['body'])):
            self.statements += [Statement(node['body'][i], keys + ['body', i], program_json)]
      
    def parse(self, pattern):
        super().parse()
        for s in self.statements:
            s.parse(pattern)



class WhileStatement(Node): #TODO

    def __init__(self, node, keys, program_json):
        super().__init__()
        test = node['test']
        body = node['body']

        self.test = Statement(test, keys + ['test'], program_json)
        self.body = Statement(body, keys + ['body'], program_json)

    def parse(self, pattern):
        super().parse()
        self.test.parse(pattern)

        if self.test.state() != "u":
            stack.push(self.test.taints)
        
        self.body.parse(pattern)

        if self.test.state() != "u":
            stack.pop()


class MemberExpression(Node): #TOCHECK

    def __init__(self, node, keys, program_json):
        super().__init__()
        obj = node['object']
        prop = node['property']
        
        if obj['type'] == 'CallExpression':
            self.obj = CallExpression(obj, keys + ['object'], program_json)
        elif obj['type'] == 'MemberExpression':
            self.obj = MemberExpression(obj, keys + ['object'], program_json)
        elif obj['type'] == 'Identifier':
            self.obj = Variable(obj, keys + ['object'], program_json)
        else:
            raise ValueError("Shoud have never come here")

        self.name = self.obj.name + "." + prop['name'] #FIXME prop is always identifier

    def parse(self, pattern):
        global flows
        super().parse()
        self.obj.parse(pattern)

        self.merge(self.taints, self.obj.taints)

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
    global vardict, programs
    for pat in pattern_list:
        programs += [Program(copy.deepcopy(program_json))]
        for p in programs:
            p.parse(pat)
            vardict = {}
        programs = []

    result = "[\n" + flows[0].toString()
    for i in range(1, len(flows)):
        result += ",\n\n" + flows[i].toString()
    result += "\n]"
    print(result)

    #print("afin:", vardict['a'].name, vardict['a'].state())
    #print("bfin:", vardict['b'].name, vardict['b'].state())
    #print("dfin:", vardict['d'].name, vardict['d'].state())   

stack = Stack()
analyseSlice(pattern_list, program_json)

