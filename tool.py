import sys
import json

program = sys.argv[1]
pattern = sys.argv[2]

vuln = "default_vuln"
sources = []
sinks = []
sanitizers = []
output = []
vardict = {}
global flows #FIXME: just testing if list works 
flows = []

class VarObj:
    def __init__(self, name, taint, sources, sans):
        self.name = name
        self.taint = taint
        self.sources = sources
        self.sans = sans

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


print("program.json:\n", program)
print("\npattern.json:\n", pattern)

filename = str(program.split(".")[0])

f = open(pattern, "r")
pattern_str = f.read()
f.close()
pattern_list = json.loads(pattern_str)
#print(pattern_str)
#print(json.loads(pattern_str))
#print(json.loads(pattern_str)[0]['vulnerability'])

f = open(program, "r")
program_str = f.read()
f.close()
program_json = json.loads(program_str)
print(program_str)

'''
for pat in pattern_list:
    sources = pat['sources']
    sinks = pat['sinks']
    sanitizers = pat['sanitizers']
    for var_json in program_json['body']:
        expr = var_json['expression']
        if expr['type'] == 'CallExpression':
            callee = expr['callee']['name']
            args = expr['arguments']['name']
            if callee in sources:
                
            for arg in args:
                if arg in sinks:
                    vardict[callee] += [arg]
                if var in sinks: #might be source and sink? otherwise elif
                    
                if vardict[expr['argument']['name']] == "t":
                    output.append(pat['name'])


            else:
                vardict[var] =""
            

        elif expr['type'] == 'AssignmentExpression':
            print("left: ", expr['left']['name'])
            var = expr['left']['name']
            if var in sources:
                varlist.append(VarObj(var, "t"))
            else:
                varlist.append(VarObj(var, "u"))
            
'''              


for i in range(0, len(program_json['body'])):
    
    print("\n\n", program_json['body'][i])
    print("\n\n",program_json.keys())


def analyseSlice(pattern_list, program_json):
    global flows #FIXME remove this
    for pat in pattern_list:
        for var_json in program_json['body']:
            stmt = var_json    
            parser(stmt, pat)
    print(flows)    

def parser(exprstmt, pattern):
# types: expressionStmt -> assignment,call,bin
# ifStmt -> test
    if exprstmt['type'] == 'ExpressionStatement':
        exprStmtParser(exprstmt['expression'], pattern)


def exprStmtParser(expr, pattern):
    if expr['type'] == 'AssignmentExpression':
        assignExprParser(expr, pattern)
    elif expr['type'] == 'CallExpression':
        callExprParser(expr, pattern)


def assignExprParser(expr, pattern):
    left = expr['left']
    right = expr['right']
    if right['type'] == 'Literal':
        if left['name'] not in vardict.keys():
            vardict[left['name']] = VarObj(left['name'], 'u', [], [])
    elif right['type'] == 'CallExpression':
        callExprParser(right, pattern)

# dict = {varname : [taintedness, list of sources]
def callExprParser(expr, pat):
    global flows #FIXME: remove this
    callee = expr['callee']['name']
    if callee not in vardict.keys():
        vardict[callee] = VarObj(callee, 'u', [], [])
    if callee in pat['sources']:
        #vardict[callee] = ['t', [callee]]
        vardict[callee].setSources('t', [callee])
    for arg in expr['arguments']:
        #if callExpression...
        if arg['name'] not in vardict.keys():
            vardict[arg['name']] = VarObj(arg['name'], 't', [arg['name']], []) #FIXME: check if default should be tainted
        if arg['name'] in pat['sources']:
            #vardict[arg['name']] = ['t', [arg['name']]
            vardict[arg['name']].setSources('t', [arg['name']])
            vardict[callee].setSources('t', [arg['name']]) 
        elif vardict[arg['name']].taint == 't':
            vardict[callee].setSources('t', vardict[arg['name']].sources)
   
    if callee in pat['sinks']:
        for arg in expr['arguments']:
            if vardict[arg['name']].taint == 't':
                #vardict[callee].setFlow(pat.vuln, vardict[callee].sources, vardict[callee].name, [])
                flows += [[pat['vulnerability'], vardict[callee].sources, vardict[callee].name, []]]
            #elif vardict[arg['name'].taint == 's':
                #todo



    elif callee in pat['sanitizers']:
        for arg in expr['arguments']:
            if arg['name'] not in vardict.keys():
                vardict[arg['name']] = VarObj('s', [arg['name']], [callee])

            else:
                vardict[arg['name']].setValues('s', vardict[arg['name']].sources, [callee]) 








f = open(filename + ".json.output", "w")
content = "[{\"vulnerability\":" + vuln + ",\n\"source\":" + str(sources) + ",\n\"sink\":" + str(sinks) + ",\n\"sanitizer\":" + str(sanitizers) + "}]"
f.write(content)
f.close()



analyseSlice(pattern_list, program_json)

