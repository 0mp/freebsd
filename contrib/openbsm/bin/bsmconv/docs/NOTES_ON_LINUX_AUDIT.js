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

/*
 * Basic fields declarations.
 */
fields.audit_backlog_limit = {
	name: 'audit_backlog_limit',
	type: NUMERIC,
}
fields.auid = {
	name: 'auid',
	type: NUMERIC,
}
fields.cmd = {
	name: 'cmd',
	type: ENCODED,
}
fields.cwd = {
	name: 'cwd',
	type: ENCODED,
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
}
fields.op = {
	name: 'op',
	type: ALPHANUMERIC,
}
fields.pid = {
	name: 'pid',
	type: NUMERIC,
}
fields.res = {
	name: 'res',
	type: ALPHANUMERIC,
}
fields.ses = {
	name: 'ses',
	type: NUMERIC,
}
fields.terminal = {
	name: 'terminal',
	type: ALPHANUMERIC,
}

/*
 * Additional information about fields.
 */
fields.audit_backlog_limit.notes = [
    [
        'What is it?',
        'https://www.redhat.com/archives/rhl-beta-list/2007-December/msg00449.html',
    ],
];
fields.cwd.notes = [
	'The current working directory.',
];
fields.msg.fields = [
	fields.cwd.name,
	fields.cmd.name,
	fields.terminal.name,
	fields.res.name,
];
fields.msg.notes = [
	'The payload of the audit record.',
	'It seems to store additional fields inside its value.',
];
fields.op.notes = [
	'The operation being performed that is audited.',
];
fields.op.values = [
	'open',
]
fields.res.values = [
    'success',
    'failed',
];
fields.res.notes = [
    [
        'Inconsistency',
        'According to what was posted on the linux-audit redhat com mailing ' +
        'list the only valid values are success and fail.',
    ],
];

/*
 * Tokens declarations
 */
tokens.process32 = {
	functionName: 'au_to_process32',
}

/*
 * Record types.
 */
linuxAudit.recordTypes.USER_CMD = {
	obligatoryFields: [
		fields.auid.name,
		fields.egid.name,
		fields.euid.name,
		fields.pid.name,
		fields.ses.name,
	],
	optionalFields: {
	},
	tokens: [
		tokens.process32,
	]
};


console.log(JSON.stringify(linuxAudit));
