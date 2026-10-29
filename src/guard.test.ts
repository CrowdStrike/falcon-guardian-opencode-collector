import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Agent } from '@opencode/schema/agent';
import { Model } from '@opencode/schema/model';
import { Provider } from '@opencode/schema/provider';
import { Session } from '@opencode/schema/session';
import { SessionMessage } from '@opencode/schema/session-message';
import { Tool } from '@opencode/schema/tool';
import * as guard from './guard.ts';

const meta: guard.Meta = {
  user: 'dennis',
  directory: '/w',
  version: '2.0.26',
  processID: 4242,
  model: {
    providerID: Provider.ID.make('anthropic'),
    id: Model.ID.make('claude-sonnet-5'),
  },
  sensorAID: 'd4208f3f3cf544f196bfe612aa8035fe',
};

const ids = {
  sessionID: Session.ID.make('ses_1'),
  agent: Agent.ID.make('build'),
  messageID: SessionMessage.ID.make('msg_1'),
  id: Tool.CallID.make('call_1'),
};

const prompt = (): guard.PromptEvent => ({
  sessionID: ids.sessionID,
  messageID: ids.messageID,
  prompt: {
    text: 'read @notes.md, my SSN is 900-12-3456',
    files: [
      {
        uri: 'file:///w/notes.md',
        mention: { start: 5, end: 14, text: '@notes.md' },
      },
    ],
  },
  delivery: 'steer',
});

const toolInput = (): guard.ToolInputEvent => ({
  ...ids,
  tool: 'write',
  input: { filePath: '/w/a.txt', content: '900-12-3456' },
});

const toolOutput = (result: Tool.Result): guard.ToolOutputEvent => ({
  ...ids,
  tool: 'shell',
  input: { command: 'cat a.txt' },
  status: 'completed',
  result,
});

/** A request as sent on the wire. */
const wire = (req: object): unknown => JSON.parse(JSON.stringify(req));

const blocked = {
  summary: 'SSN was detected and blocked.',
  result: { blocked: true },
};
const redacted = (...messages: object[]) => ({
  result: { transformed: true, guard_output: { messages } },
});

test('token comes from the environment, base URL from options, then the environment', () => {
  const env = {
    CS_AIDR_TOKEN: 'env-token',
    CS_AIDR_BASE_URL: 'https://api.us-2.crowdstrike.com/aidr/aiguard',
  };
  assert.deepEqual(guard.config({}, env), {
    token: 'env-token',
    baseURL: 'https://api.us-2.crowdstrike.com/aidr/aiguard',
    timeoutMillis: 30_000,
    failureMode: 'closed',
  });
  assert.deepEqual(
    guard.config(
      {
        baseURL: 'https://api.collector-crowdstrike.com',
        timeout: 5,
        failureMode: 'open',
      },
      env
    ),
    {
      token: 'env-token',
      baseURL: 'https://api.collector-crowdstrike.com',
      timeoutMillis: 5_000,
      failureMode: 'open',
    }
  );
});

test('a base URL off CrowdStrike HTTPS hosts leaves no token', () => {
  for (const baseURL of [
    'https://evil.com',
    'https://evilcrowdstrike.com',
    'https://crowdstrike.com.evil.com',
    'https://api.crowdstrike.com@evil.com',
    'https://evil.com\\.crowdstrike.com',
    'http://api.crowdstrike.com',
    'not a url',
  ])
    assert.ok(
      guard.config({ baseURL }, { CS_AIDR_TOKEN: 't' }).token instanceof Error,
      baseURL
    );
});

test('a missing token or invalid options leave no token', () => {
  assert.ok(guard.config({}, {}).token instanceof Error);
  const invalid = guard.config(
    { timeout: 'soon', failureMode: 'open' },
    { CS_AIDR_TOKEN: 't' }
  );
  assert.ok(invalid.token instanceof Error);
  assert.equal(invalid.failureMode, 'closed');
  assert.equal(
    guard.config({ failureMode: 'shut' }, { CS_AIDR_TOKEN: 't' }).failureMode,
    'closed'
  );
});

test('prompt is sent as input', () => {
  assert.deepEqual(wire(guard.promptRequest(prompt(), meta)), {
    guard_input: {
      messages: [
        { role: 'user', content: 'read @notes.md, my SSN is 900-12-3456' },
      ],
    },
    event_type: 'input',
    llm_provider: 'anthropic',
    model: 'claude-sonnet-5',
    session_id: 'ses_1',
    user_id: 'dennis',
    agent_type: 'code-assistant',
    is_agent: true,
    process_id: '4242',
    process_tags: ['213584428666668'],
    extra_info: {
      app_name: 'OpenCode',
      app_version: '2.0.26',
      user_name: 'dennis',
      opencode_hook_name: 'session.prompt',
      opencode_directory: '/w',
      sensor_aid: 'd4208f3f3cf544f196bfe612aa8035fe',
    },
  });
});

test('Windows sensor AID is the AG value as lowercase hex', () => {
  const sim =
    'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\services\\CSAgent\\Sim\r\n';
  assert.equal(
    guard.windowsSensorAID(
      `\r\n${sim}    AFLAGS    REG_BINARY    00000000\r\n` +
        '    AG    REG_BINARY    D4208F3F3CF544F196BFE612AA8035FE\r\n\r\n' +
        'End of search: 2 match(es) found.\r\n'
    ),
    'd4208f3f3cf544f196bfe612aa8035fe'
  );
  assert.equal(
    guard.windowsSensorAID(`${sim}    AG    REG_BINARY    D4208F3F\r\n`),
    undefined
  );
  assert.equal(guard.windowsSensorAID(''), undefined);
});

test('macOS sensor AID is the plist aid as lowercase hex', () => {
  const info = (aid: string) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>aid</key>
    ${aid}
    <key>cid</key>
    <string>6CB9530D078E415F96CE34BE06631A37</string>
    <key>sensor_loaded</key>
    <true/>
</dict>
</plist>
`;
  assert.equal(
    guard.macSensorAID(
      info('<string>D4208F3F3CF544F196BFE612AA8035FE</string>')
    ),
    'd4208f3f3cf544f196bfe612aa8035fe'
  );
  assert.equal(
    guard.macSensorAID(info('<string>D4208F3F</string>')),
    undefined
  );
  assert.equal(guard.macSensorAID(info('<true/>')), undefined);
  assert.equal(guard.macSensorAID('falconctl: permission denied'), undefined);
  assert.equal(guard.macSensorAID(''), undefined);
});

test('tool input is sent as JSON-encoded arguments', () => {
  const bare = { ...meta, model: undefined, sensorAID: undefined };
  const req = guard.toolInputRequest(toolInput(), bare);
  assert.deepEqual(wire(req), {
    ...(wire(guard.promptRequest(prompt(), bare)) as object),
    event_type: 'tool_input',
    guard_input: {
      messages: [
        {
          role: 'assistant',
          content: null,
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: {
                name: 'write',
                arguments: '{"filePath":"/w/a.txt","content":"900-12-3456"}',
              },
            },
          ],
        },
      ],
    },
    extra_info: {
      app_name: 'OpenCode',
      app_version: '2.0.26',
      user_name: 'dennis',
      opencode_hook_name: 'tool.execute.before',
      opencode_directory: '/w',
      opencode_tool_name: 'write',
      opencode_agent: 'build',
    },
  });
});

test('tool output is sent as the text the model reads', () => {
  const sent = (result: Tool.Result) =>
    (
      wire(guard.toolOutputRequest(toolOutput(result), meta)) as {
        guard_input: { messages: unknown[] };
      }
    ).guard_input.messages[1];
  const message = (content: string) => ({
    role: 'tool',
    tool_call_id: 'call_1',
    content,
  });
  assert.deepEqual(
    sent({ content: '900-12-3456\n' }),
    message('900-12-3456\n')
  );
  assert.deepEqual(
    sent({
      content: [
        { type: 'text', text: 'a' },
        { type: 'file', uri: 'data:image/png;base64,', mime: 'image/png' },
        { type: 'text', text: 'b' },
      ],
    }),
    message('a\nb')
  );
  assert.deepEqual(
    sent({ output: { exitCode: 0 } }),
    message('{"exitCode":0}')
  );
});

test('verdicts', () => {
  assert.deepEqual(
    guard.verdict({ result: { blocked: false, transformed: false } }),
    { type: 'allow' }
  );
  assert.deepEqual(guard.verdict(blocked), {
    type: 'block',
    reason: 'Falcon Guardian: SSN was detected and blocked.',
  });
  assert.throws(() => guard.verdict({ result: { transformed: true } }));
  assert.throws(() => guard.verdict(redacted()));
});

test('failure mode decides when there is no verdict', () => {
  assert.deepEqual(guard.failure('open', 'timeout'), { type: 'allow' });
  assert.deepEqual(guard.failure('closed', 'timeout'), {
    type: 'block',
    reason: 'Falcon Guardian: timeout',
  });
});

test('allowed events are unchanged', () => {
  const allow = { type: 'allow' } as const;
  const [p, i, o] = [prompt(), toolInput(), toolOutput({ content: 'x' })];
  assert.equal(guard.applyToPrompt(p, allow), undefined);
  assert.equal(guard.applyToToolInput(i, allow), undefined);
  assert.equal(guard.applyToToolOutput(o, allow), undefined);
  assert.deepEqual(
    [p, i, o],
    [prompt(), toolInput(), toolOutput({ content: 'x' })]
  );
});

test('blocked events are rejected with the reason, unchanged', () => {
  const block = guard.verdict(blocked);
  const reason = 'Falcon Guardian: SSN was detected and blocked.';
  const [p, i, o] = [prompt(), toolInput(), toolOutput({ content: 'x' })];
  assert.equal(guard.applyToPrompt(p, block), reason);
  assert.equal(guard.applyToToolInput(i, block), reason);
  assert.equal(guard.applyToToolOutput(o, block), reason);
  assert.deepEqual(
    [p, i, o],
    [prompt(), toolInput(), toolOutput({ content: 'x' })]
  );
});

test('redacted prompt keeps attachments without mentions', () => {
  const event = prompt();
  guard.applyToPrompt(
    event,
    guard.verdict(
      redacted({ role: 'user', content: 'read @notes.md, my SSN is <US_SSN>' })
    )
  );
  assert.deepEqual(wire(event.prompt), {
    text: 'read @notes.md, my SSN is <US_SSN>',
    files: [{ uri: 'file:///w/notes.md' }],
  });
});

test('redacted tool input rewrites the call', () => {
  const event = toolInput();
  const res = redacted({
    role: 'assistant',
    content: null,
    tool_calls: [
      {
        id: 'call_1',
        type: 'function',
        function: {
          name: 'write',
          arguments: '{"filePath":"/w/a.txt","content":"<US_SSN>"}',
        },
      },
    ],
  });
  assert.equal(guard.applyToToolInput(event, guard.verdict(res)), undefined);
  assert.deepEqual(event.input, { filePath: '/w/a.txt', content: '<US_SSN>' });
});

test('redacted tool output replaces the output', () => {
  const event = toolOutput({
    output: { stdout: '900-12-3456' },
    content: '900-12-3456',
  });
  const res = redacted(
    { role: 'assistant', tool_calls: [] },
    { role: 'tool', tool_call_id: 'call_1', content: '<US_SSN>' }
  );
  guard.applyToToolOutput(event, guard.verdict(res));
  assert.deepEqual(event.result, { content: '<US_SSN>' });
});

test('redaction of the wrong message kind is an error', () => {
  const user = guard.verdict(redacted({ role: 'user', content: 'x' }));
  assert.throws(() => guard.applyToToolInput(toolInput(), user));
  assert.throws(() =>
    guard.applyToToolOutput(toolOutput({ content: 'x' }), user)
  );
  const tool = guard.verdict(
    redacted({ role: 'tool', tool_call_id: 'call_1', content: 'x' })
  );
  assert.throws(() => guard.applyToPrompt(prompt(), tool));
});
