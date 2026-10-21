import type {
  AidrPostV1GuardChatCompletionsResponses,
  ChatCompletionsGuard,
} from '@crowdstrike/aidr';
import type { Model } from '@opencode/plugin/effect';
import type { SessionPrompt } from '@opencode/plugin/effect/session';
import type { ToolHooks } from '@opencode/plugin/effect/tool';
import type { Tool } from '@opencode/schema/tool';
import { Exit, Schema } from 'effect';
import * as plist from 'plist';

export type FailureMode = 'open' | 'closed';

const OPENCODE_PROCESS_TAG = '213584428666668';

/**
 * Plugin options from `opencode.json`.
 */
const Options = Schema.Struct({
  token: Schema.optional(Schema.String),
  baseURL: Schema.optional(Schema.String),
  /** Seconds to wait for a verdict, including polling. */
  timeout: Schema.optional(Schema.Number),
  failureMode: Schema.optional(Schema.Literals(['open', 'closed'])),
});

export interface Config {
  /** Collector token, or why there is none. */
  readonly token: string | Error;
  readonly baseURL: string;
  readonly timeoutMillis: number;
  readonly failureMode: FailureMode;
}

/**
 * The collector config from plugin `options` and `env`.
 */
export function config(
  options: unknown,
  env: Readonly<Record<string, string | undefined>>
): Config {
  const decoded = Schema.decodeUnknownExit(Options)(options);
  const opts = Exit.isSuccess(decoded) ? decoded.value : {};
  const token = opts.token ?? env.CS_AIDR_TOKEN;
  return {
    token: Exit.isFailure(decoded)
      ? new Error(`invalid plugin options: ${decoded.cause}`)
      : (token ?? new Error('CS_AIDR_TOKEN is not set')),
    baseURL:
      opts.baseURL ??
      env.CS_AIDR_BASE_URL ??
      'https://api.crowdstrike.com/aidr/aiguard',
    timeoutMillis: (opts.timeout ?? 30) * 1000,
    failureMode: opts.failureMode ?? 'closed',
  };
}

const ToolCall = Schema.Struct({
  id: Schema.String,
  type: Schema.Literal('function'),
  function: Schema.Struct({
    name: Schema.String,
    /** JSON-encoded arguments. */
    arguments: Schema.String,
  }),
});

/** An OpenAI Chat Completions message. */
const Message = Schema.Union([
  Schema.Struct({ role: Schema.Literal('user'), content: Schema.String }),
  Schema.Struct({
    role: Schema.Literal('assistant'),
    content: Schema.optional(Schema.NullOr(Schema.String)),
    tool_calls: Schema.Array(ToolCall),
  }),
  Schema.Struct({
    role: Schema.Literal('tool'),
    tool_call_id: Schema.String,
    content: Schema.String,
  }),
]);
type Message = typeof Message.Type;

/**
 * `guard_input` as sent, and `guard_output` as returned with redactions
 * applied.
 */
const GuardInput = Schema.Struct({ messages: Schema.Array(Message) });

/**
 * What the collector knows about the OpenCode process and session beyond the
 * hook event.
 */
export interface Meta {
  readonly user: string | undefined;
  /** Directory of the plugin's OpenCode location. */
  readonly directory: string;
  readonly version: string;
  readonly processID: number;
  /** Model of the session's latest model request, if any. */
  readonly model: Model.Ref | undefined;
  readonly sensorAID: string | undefined;
}

/**
 * The Falcon sensor agent ID in `reg query <CSAgent\Sim> /v AG` output, as
 * lowercase hex. `undefined` unless `AG` holds exactly 16 bytes.
 */
export function windowsSensorAID(regOutput: string): string | undefined {
  return /^\s*AG\s+REG_BINARY\s+([0-9A-F]{32})\s*$/im
    .exec(regOutput)?.[1]
    ?.toLowerCase();
}

/**
 * The Falcon sensor agent ID in `falconctl info` output, as lowercase hex.
 * `undefined` unless the plist's `aid` holds 32 hex digits.
 */
export function macSensorAID(falconctlOutput: string): string | undefined {
  let info: plist.PlistValue;
  try {
    info = plist.parse(falconctlOutput);
  } catch {
    return undefined;
  }
  const aid =
    typeof info === 'object' && info !== null && 'aid' in info
      ? info.aid
      : undefined;
  return typeof aid === 'string' && /^[0-9A-F]{32}$/i.test(aid)
    ? aid.toLowerCase()
    : undefined;
}

export type PromptEvent = SessionPrompt;
export type ToolInputEvent = ToolHooks['execute.before'];
export type ToolOutputEvent = ToolHooks['execute.after'] & {
  readonly status: 'completed';
};

export function promptRequest(
  event: PromptEvent,
  meta: Meta
): ChatCompletionsGuard {
  return request(
    'input',
    'session.prompt',
    event.sessionID,
    [{ role: 'user', content: event.prompt.text }],
    meta
  );
}

export function toolInputRequest(
  event: ToolInputEvent,
  meta: Meta
): ChatCompletionsGuard {
  return request(
    'tool_input',
    'tool.execute.before',
    event.sessionID,
    [toolCall(event)],
    meta,
    event
  );
}

export function toolOutputRequest(
  event: ToolOutputEvent,
  meta: Meta
): ChatCompletionsGuard {
  const output = {
    role: 'tool',
    tool_call_id: event.id,
    content: outputText(event.result),
  } as const;
  return request(
    'tool_output',
    'tool.execute.after',
    event.sessionID,
    [toolCall(event), output],
    meta,
    event
  );
}

function request(
  eventType: 'input' | 'tool_input' | 'tool_output',
  hook: 'session.prompt' | 'tool.execute.before' | 'tool.execute.after',
  sessionID: string,
  messages: readonly Message[],
  meta: Meta,
  tool?: { readonly tool: string; readonly agent: string }
): ChatCompletionsGuard {
  return {
    guard_input: { messages },
    event_type: eventType,
    llm_provider: meta.model?.providerID,
    model: meta.model?.id,
    session_id: sessionID,
    user_id: meta.user,
    agent_type: 'code-assistant',
    is_agent: true,
    process_id: String(meta.processID),
    process_tags: [OPENCODE_PROCESS_TAG],
    extra_info: {
      app_name: 'OpenCode',
      app_version: meta.version,
      user_name: meta.user,
      opencode_hook_name: hook,
      opencode_directory: meta.directory,
      opencode_tool_name: tool?.tool,
      opencode_agent: tool?.agent,
      sensor_aid: meta.sensorAID,
    },
  };
}

function toolCall(event: ToolInputEvent | ToolOutputEvent): Message {
  return {
    role: 'assistant',
    content: null,
    tool_calls: [
      {
        id: event.id,
        type: 'function',
        function: {
          name: event.tool,
          arguments: JSON.stringify(event.input) ?? 'null',
        },
      },
    ],
  };
}

function outputText({ content, output }: Tool.Result): string {
  if (typeof content === 'string') return content;
  if (content !== undefined && content.length > 0)
    return content
      .flatMap((part) => (part.type === 'text' ? [part.text] : []))
      .join('\n');
  return typeof output === 'string' ? output : (JSON.stringify(output) ?? '');
}

export type Verdict =
  | { readonly type: 'allow' }
  | { readonly type: 'block'; readonly reason: string }
  /** The redacted copy of the last message sent. */
  | { readonly type: 'redact'; readonly message: Message };

type GuardResult = AidrPostV1GuardChatCompletionsResponses[200]['result'];

/**
 * The verdict in a successful Falcon Guardian response. Throws if a redaction
 * has no usable `guard_output`.
 */
export function verdict(res: {
  readonly summary?: string;
  readonly result?: GuardResult;
}): Verdict {
  if (res.result?.blocked)
    return {
      type: 'block',
      reason: `Falcon Guardian: ${res.summary ?? 'blocked by policy'}`,
    };
  if (!res.result?.transformed) return { type: 'allow' };
  const message = Schema.decodeUnknownSync(GuardInput)(
    res.result.guard_output
  ).messages.at(-1);
  if (message === undefined) throw new Error('guard_output has no messages');
  return { type: 'redact', message };
}

/** The verdict when Falcon Guardian can't give one because of `error`. */
export function failure(mode: FailureMode, error: unknown): Verdict {
  return mode === 'open'
    ? { type: 'allow' }
    : { type: 'block', reason: `Falcon Guardian: ${error}` };
}

/**
 * Rewrite the prompt for `verdict`. Returns the reason to reject the prompt
 * with, if any.
 */
export function applyToPrompt(
  event: PromptEvent,
  verdict: Verdict
): string | undefined {
  if (verdict.type === 'allow') return undefined;
  if (verdict.type === 'block') return verdict.reason;
  if (verdict.message.role !== 'user')
    throw new Error("guard_output doesn't end with a user message");
  const { files, agents, skills } = event.prompt;
  // Mention offsets point into the original text.
  event.prompt = {
    text: verdict.message.content,
    files: files?.map(({ mention: _, ...file }) => file),
    agents: agents?.map(({ mention: _, ...agent }) => agent),
    skills: skills?.map(({ mention: _, ...skill }) => skill),
  };
  return undefined;
}

/**
 * Rewrite the tool input for `verdict`. Returns the reason to reject the call
 * with, if any.
 */
export function applyToToolInput(
  event: ToolInputEvent,
  verdict: Verdict
): string | undefined {
  if (verdict.type === 'allow') return undefined;
  if (verdict.type === 'block') return verdict.reason;
  const call =
    verdict.message.role === 'assistant'
      ? verdict.message.tool_calls[0]
      : undefined;
  if (call === undefined)
    throw new Error("guard_output doesn't end with a tool call");
  event.input = JSON.parse(call.function.arguments);
  return undefined;
}

/**
 * Rewrite the tool output for `verdict`. Returns the reason to reject the
 * output with, if any.
 */
export function applyToToolOutput(
  event: ToolOutputEvent,
  verdict: Verdict
): string | undefined {
  if (verdict.type === 'allow') return undefined;
  if (verdict.type === 'block') return verdict.reason;
  if (verdict.message.role !== 'tool')
    throw new Error("guard_output doesn't end with a tool message");
  event.result = { content: verdict.message.content };
  return undefined;
}
