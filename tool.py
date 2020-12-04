import sys
import json
import copy

program = sys.argv[1]
pattern = sys.argv[2]

global flows
flows = []

class Universe:
    def __init__(self):
        self.programs = []
        self.vardict = {}
        self.stack = None
        self.breakloop = False

    def mergeVardict(self, vardict):

        for var in vardict.keys():
            if var not in self.vardict:
                self.vardict[var] = copy.deepcopy(vardict[var])
            else:
                for taint in vardict[var].taints:
                    if taint not in self.vardict[var].taints:
                        self.vardict[var].taints += [copy.deepcopy(taint)]


class Program:
    def __init__(self, program_json, universe):
        self.statements = []
        self.universe = universe
        self.json = program_json

    def construct(self):
        for i in range(len(self.json['body'])):
            self.statements += [Statement(self.json['body'][i], ['body', i], self.json, self.universe)]

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
    def __init__(self, universe):
        self.universe = universe
        self.taints = []
        self.sink = None

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
        self.merge(self.taints, copy.deepcopy(self.universe.stack.taints()))


class VarObj(Node):#FIXME name varobj? useless
    def __init__(self, name, taints):
        super().__init__(None)
        self.name = name
        self.taints = taints

    def __eq__(self, other):
        return self.name == other.name


class Literal(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        self.value = node['value']

    def parse(self, pattern):
        super().parse()

class Variable(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        self.name = node['name']

    def parse(self, pattern):
        super().parse()
        if self.name not in self.universe.vardict.keys():
            match = self.match(self.name, pattern['sources'])
            if match:
                taint = Taint("t", match, [])
                self.universe.vardict[self.name] = VarObj(self.name, [taint])
            else:
                self.universe.vardict[self.name] = VarObj(self.name, [])

            #assuming that a source is not a sink at the same time
            self.universe.vardict[self.name].sink = self.match(self.name, pattern['sinks'])

        self.sink = self.universe.vardict[self.name].sink
        self.merge(self.taints, copy.deepcopy(self.universe.vardict[self.name].taints))


    def match(self, name, sources):
        for source in sources: 
            if name == source.split(".")[0]:
                return source #FIXME return only works if pattern only has one source (document.cenas, document.cenas2 both have the same beginning)
        return None

    def rootName(self):
        return self.name


class Statement(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        if universe.breakloop:
            self.expression = None
        elif node['type'] == 'AssignmentExpression':
            self.expression = AssignmentExpression(node, keys, program_json, universe)
        elif node['type'] == 'CallExpression':
            self.expression = CallExpression(node, keys, program_json, universe)
        elif node['type'] == "Identifier":
            self.expression = Variable(node, keys, program_json, universe)
        elif node['type'] == "Literal":
            self.expression = Literal(node, keys, program_json, universe)
        elif node['type'] == "BinaryExpression":
            self.expression = BinaryExpression(node, keys, program_json, universe)
        elif node['type'] == "ExpressionStatement":
            self.expression = Statement(node['expression'], keys + ['expression'], program_json, universe)
        elif node['type'] == "IfStatement":
            self.expression = IfStatement(node, keys, program_json, universe)
        elif node['type'] == "BlockStatement":
            self.expression = BlockStatement(node, keys, program_json, universe)
        elif node['type'] == "WhileStatement":
            self.expression = WhileStatement(node, keys, program_json, universe)
        elif node['type'] == "MemberExpression":
            self.expression = MemberExpression(node, keys, program_json, universe)
        elif node['type'] == "ArrayExpression":
            self.expression = ArrayExpression(node, keys, program_json, universe)  
        elif node['type'] == "LogicalExpression":
            self.expression = BinaryExpression(node, keys, program_json, universe)  
        elif node['type'] == "NewExpression":
            self.expression = CallExpression(node, keys, program_json, universe)
        elif node['type'] == "UnaryExpression": #FIXME check
            self.expression = UnaryExpression(node, keys, program_json, universe)
        elif node['type'] == "UpdateExpression":
            self.expression = UnaryExpression(node, keys, program_json, universe)
        elif node['type'] == "BreakStatement":
            universe.breakloop = True
            self.expression = None
        elif node['type'] == "SequenceExpression": #FIXME check
            self.expression = SequenceExpression(node, keys, program_json, universe)
       
        elif node['type'] == "ForStatement":
            self.expression = ForStatement(node, keys, program_json, universe)
        elif node['type'] == "VariableDeclarator": #FIXME check
            self.expression = VariableDeclarator(node, keys, program_json, universe)
        elif node['type'] == "VariableDeclaration": #FIXME check
            self.expression = VariableDeclaration(node, keys, program_json, universe)
        elif node['type'] == "ConditionalExpression": #FIXME check
            self.expression = ConditionalExpression(node, keys, program_json, universe)
        else:
            raise ValueError("Shoud have never come here")

    def parse(self, pattern):
        super().parse()
        if self.expression:
            self.expression.parse(pattern)
            self.sink = self.expression.sink
            self.merge(self.taints, self.expression.taints)


class AssignmentExpression(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        left = node['left']
        right = node['right']
        
        if left['type'] == "Identifier": #FIXME can left be anything else?
            self.left = Variable(left, keys + ['left'], program_json, universe)
        elif left['type'] == "MemberExpression":
            self.left = MemberExpression(left, keys + ['left'], program_json, universe)
        else:
            raise ValueError("Shoud have never come here")

        self.right = Statement(right, keys + ['right'], program_json, universe)

    def parse(self, pattern):
        global flows
        super().parse()
        self.left.parse(pattern)
        self.right.parse(pattern)

        self.merge(self.taints, self.right.taints)
        self.universe.vardict[self.left.rootName()].taints = copy.deepcopy(self.taints)

        if self.left.sink:
            for taint in self.taints:
                v = None
                if taint.state == "t":
                    v = Vuln(pattern['vulnerability'], taint.source, taint.sans, self.left.sink)
                elif taint.state == "s":
                    v = Vuln(str(pattern['vulnerability']) + " -> Sanitized, but might still be compromised", taint.source, taint.sans, self.left.sink)
                if v and v not in flows:
                    flows += [v]

        self.sink = self.right.sink
        self.universe.vardict[self.left.rootName()].sink = self.sink



class VariableDeclarator(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        identifier = node['id']
        init = node['init']
        self.statement = None

        if init:
            json = node
            json['left'] = json['id'] 
            json['right'] = json['init'] 
            json['type'] = "AssignmentExpression" 

            self.statement = AssignmentExpression(json, keys, program_json, universe)
        else:
            self.statement = Variable(identifier, keys + ['id'], program_json, universe)

    def parse(self, pattern):
        super().parse()
        self.statement.parse(pattern)



class VariableDeclaration(Node): #FIXME not tested

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        declarations = node['declarations']
        self.declarations = []
        
        for i in range(len(declarations)):
            self.declarations += [Statement(declarations[i], keys + ['declarations', i], program_json, universe)]


    def parse(self, pattern):
        global flows
        super().parse()
        for d in self.declarations:
            d.parse(pattern)
            ##self.merge(self.taints, d.taints)


class ConditionalExpression(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe) 
        test = node['test']
        consequent = node['consequent']
        alternate = node['alternate']


        node['consequent'] = {"type": "BlockStatement", "body": [node['consequent']]} 
        node['alternate'] = {"type": "BlockStatement", "body": [node['alternate']]} 
        node['type'] = "IfStatement"
      
        self.statement = IfStatement(node, keys, program_json, universe)

    def parse(self, pattern):
        super().parse()
        self.statement.parse(pattern)
        self.merge(self.taints, self.statement.taints)


class CallExpression(Node): #FIXME: also accepting NewExpressions

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        callee = node['callee']

        if callee['type'] == "Identifier": #FIXME can left be anything else?
            self.callee = Variable(callee, keys + ['callee'], program_json, universe)
        elif callee['type'] == "MemberExpression":
            self.callee = MemberExpression(callee, keys + ['callee'], program_json, universe)
        else:
            raise ValueError("Shoud have never come here")

        self.arguments = []
        for i in range(len(node['arguments'])):
            self.arguments += [Statement(node['arguments'][i], keys + ['arguments', i], program_json, universe)]

    def parse(self, pattern):
        global flows
        self.callee.parse(pattern)
        self.merge(self.taints, self.callee.taints)

        for arg in self.arguments:
            arg.parse(pattern)
            self.merge(self.taints, arg.taints)

        if self.state() != "u" and self.callee.name in pattern['sanitizers'] and self.universe.vardict[self.callee.name].state() != "t":
            self.sanitize(self.callee.name)

        super().parse() #sanitization does not save if implicit leaks
        
        if self.callee.sink:
            for taint in self.taints:
                v = None
                if taint.state == "t":
                    v = Vuln(pattern['vulnerability'], taint.source, taint.sans, self.callee.sink)
                elif taint.state == "s":
                    v = Vuln(str(pattern['vulnerability']) + " -> Sanitized, but might still be compromised", taint.source, taint.sans, self.callee.sink)
                if v and v not in flows:
                    flows += [v]


class BinaryExpression(Node): #FIXME also accepting logicalExp ( ||, &&)

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        left = node['left']
        right = node['right']
        
        self.left = Statement(left, keys + ['left'], program_json, universe)
        self.right = Statement(right, keys + ['right'], program_json, universe)

    def parse(self, pattern):
        global flows
        super().parse()
        self.left.parse(pattern)
        self.right.parse(pattern)

        self.merge(self.right.taints,self.left.taints)

class UnaryExpression(Node): #FIXME not tested

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        argument = node['argument']
        
        self.argument = Statement(argument, keys + ['argument'], program_json, universe)

    def parse(self, pattern):
        global flows
        super().parse()
        self.argument.parse(pattern)
        self.merge(self.taints, self.argument.taints)


class ArrayExpression(Node): #FIXME not tested

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        elements = node['elements']
        self.elements = []
        
        for i in range(len(elements)):
            self.elements += [Statement(elements[i], keys + ['elements', i], program_json, universe)]


    def parse(self, pattern):
        global flows
        super().parse()
        for e in self.elements:
            e.parse(pattern)
            self.merge(self.taints, e.taints)


class SequenceExpression(Node): #FIXME not tested

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        expressions = node['expressions']
        self.expressions = []
        
        for i in range(len(expressions)):
            self.expressions += [Statement(expressions[i], keys + ['expressions', i], program_json, universe)]


    def parse(self, pattern):
        global flows
        super().parse()
        for e in self.expressions:
            e.parse(pattern)
            self.merge(self.taints, e.taints)

class IfStatement(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
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
            
            p = Program(original_json, universe)
            universe.programs += [p]
            p.construct()

        self.test = Statement(test, keys + ['test'], program_json, universe)
        
        if consequent:
            self.consequent = Statement(consequent, keys + ['consequent'], program_json, universe)
        else:
            self.consequent = None


    def parse(self, pattern):
        super().parse()
        self.test.parse(pattern)
        self.merge(self.taints, self.test.taints)

        if self.consequent:
            if self.test.state() != "u":
                self.universe.stack.push(self.test.taints)
            
            self.consequent.parse(pattern)

            if self.test.state() != "u":
                self.universe.stack.pop()

            self.merge(self.taints, self.consequent.taints)
            self.sink = self.consequent.sink
        

class BlockStatement(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        self.statements = []
        for i in range(len(node['body'])):
            self.statements += [Statement(node['body'][i], keys + ['body', i], program_json, universe)]
      
    def parse(self, pattern):
        super().parse()
        for s in self.statements:
            s.parse(pattern)
            self.merge(self.taints, s.taints)
            self.sink = s.sink



class WhileStatement(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        test = node['test']
        body = node['body']
        self.node_json = copy.deepcopy(node)

        original_json = copy.deepcopy(program_json)
        json = original_json
        for key in keys:
            json = json[key]

        json['consequent'] = None
        json['alternate'] = "passed"
        json['type'] = "IfStatement"
        
        p = Program(original_json, universe)
        universe.programs += [p]
        p.construct()
    

    def parse(self, pattern):
        super().parse()
        
        json = self.node_json
        json['type'] = "IfStatement"
        json['consequent'] = json['body']
        json['alternate'] = "passed"
        loops = 1

        
        antevardict = copy.deepcopy(self.universe.vardict)
        antestack = copy.deepcopy(self.universe.stack)
        
        varlist = []
        for var in self.universe.vardict:
            if self.universe.vardict[var].state() == "t":
                varlist += [self.universe.vardict[var].name]
        
        allTimeTainted = len(varlist)
        oldSanitized = 0

        while True:
            
            uni = Universe()
            uni.vardict = copy.deepcopy(antevardict)
            uni.stack = copy.deepcopy(antestack)
            
            whilejson = {'body': []}
            for i in range(loops):
                whilejson['body'] += [copy.deepcopy(json)]
            
            p = Program(whilejson, uni)
            uni.programs += [p]
            p.construct()

            
            for program in uni.programs:
                program.parse(pattern)
                uni.breakloop = False

            sanitizedVariables = 0
            for var in uni.vardict.keys():
                if uni.vardict[var].state() == "t":
                    if var not in varlist:
                        varlist += [var]
                elif uni.vardict[var].state() == "s":
                    sanitizedVariables += 1
            

            self.universe.mergeVardict(uni.vardict)
            
            if oldSanitized >= sanitizedVariables and len(varlist) == allTimeTainted:
                break

            loops += 1
            oldSanitized = sanitizedVariables
            allTimeTainted = len(varlist)

class ForStatement(Node):
    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe) 
        init = node['init']
        test = node['test']
        body = node['body']
        update = node['update']
        self.node_json = copy.deepcopy(node)

        #original_json = copy.deepcopy(program_json)
        #json = original_json
        json = program_json
        for key in keys:
            json = json[key]

        json['test'] = {"type": "SequenceExpression", "expressions": [json['init'], json['test'], json['update']]} 
        json['type'] = "WhileStatement"
      
        self.statement = WhileStatement(json, keys, program_json, universe)

    def parse(self, pattern):
        super().parse()
        self.statement.parse(pattern)

class MemberExpression(Node):

    def __init__(self, node, keys, program_json, universe):
        super().__init__(universe)
        obj = node['object']
        prop = node['property']
        
        if obj['type'] == 'CallExpression':
            self.obj = CallExpression(obj, keys + ['object'], program_json, universe)
        elif obj['type'] == 'MemberExpression':
            self.obj = MemberExpression(obj, keys + ['object'], program_json, universe)
        elif obj['type'] == 'Identifier':
            self.obj = Variable(obj, keys + ['object'], program_json, universe)
        else:
            raise ValueError("Shoud have never come here")

        self.name = self.obj.name + "." + prop['name'] #assuming prop is always identifier

    def parse(self, pattern):
        global flows
        super().parse()
        self.obj.parse(pattern)
        self.sink = self.obj.sink

        self.merge(self.taints, self.obj.taints)

    def rootName(self):
        return self.name.split(".")[0]


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

    universe = Universe()
    universe.stack = Stack()

    for pat in pattern_list:
        p = Program(copy.deepcopy(program_json), universe)
        universe.programs += [p]
        p.construct()

        for p in universe.programs:
            p.parse(pat)
            universe.vardict = {}
        universe.programs = []
    
    result = "["
    if flows:
        result += "\n" + flows[0].toString()
        for i in range(1, len(flows)):
            result += ",\n\n" + flows[i].toString()
        result += "\n"
    result += "]"
    print(result)

    #print("afin:", vardict['a'].name, vardict['a'].state())
    #print("bfin:", vardict['b'].name, vardict['b'].state())
    #print("dfin:", vardict['d'].name, vardict['d'].state())   

analyseSlice(pattern_list, program_json)

