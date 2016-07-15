function RecordType(obligatoryFields, optionalFields, tokens) {
    this.obligatoryFields = obligatoryFields;
    this.optionalFields = optionalFields;
    this.tokens = tokens;
}

function Field(type) {
	this.type = type;
}

function Token(functionName) {
	this.functionName = functionName;
}

const ALPHANUMERIC = 'alphanumeric';
const ENCODED = 'encoded';
const NUMERIC = 'numeric';

var linuxAudit = {};
linuxAudit.fields = {};
linuxAudit.recordTypes = {};
linuxAudit.tokens = {};

var fields = linuxAudit.fields;
var tokens = linuxAudit.tokens;

fields.auid = {
	name: 'auid',
	type: NUMERIC,
}
fields.cwd = {
	name: 'cwd',
	type: ENCODED,
	notes: [
		"The current working directory.",
	],
}
fields.egid = {
	name: 'egid',
	type: NUMERIC,
}
fields.euid = {
	name: 'euid',
	type: NUMERIC,
}
fields.msg = {
	name: 'msg',
	type: ALPHANUMERIC,
	notes: [
		"The payload of the audit record.",
		"It seems to store additional fields inside its value.",
	],
	fields: [
		fields.cwd,
		fields.cmd,
		fields.terminal,
		fields.res
	],
}
fields.pid = {
	name: 'pid',
	type: NUMERIC,
}
fields.ses = {
	name: 'ses',
	type: NUMERIC,
}

tokens.process32 = {
	functionName: 'au_to_process32',
}

linuxAudit.recordTypes.USER_CMD = {
	obligatoryFields: [
		fields.auid,
		fields.egid,
		fields.euid,
		fields.pid,
		fields.ses
	],
	optionalFields: {
	},
	tokens: [
		tokens.process32,
	]
};

console.log(JSON.stringify(linuxAudit));
