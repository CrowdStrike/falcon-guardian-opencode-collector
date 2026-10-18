/** Falcon Guardian collector for OpenCode. */

import { AIGuard, type ChatCompletionsGuard } from '@crowdstrike/aidr';
import { type Model, Plugin } from '@opencode/plugin/effect';
import { Tool } from '@opencode/schema/tool';
import { Cause, Effect } from 'effect';
import { safeExeca } from 'safe-execa';
import * as guard from './guard.ts';

/** Keep the thrown error, so its message reaches the log and closed reasons. */
const unwrap = (error: unknown) => error;
const attempt = <A>(f: () => A) => Effect.try({ try: f, catch: unwrap });

const REG_KEY = 'HKLM\\System\\CurrentControlSet\\services\\CSAgent\\Sim';
const FALCONCTL = '/Applications/Falcon.app/Contents/Resources/falconctl';

/** `parse` of the command's stdout. `undefined` on any failure. */
const readCommand = (
  file: string,
  args: readonly string[],
  parse: (stdout: string) => string | undefined
): Effect.Effect<string | undefined> =>
  Effect.tryPromise(() => safeExeca(file, args, { timeout: 5000 })).pipe(
    Effect.map(({ stdout }) =>
      typeof stdout === 'string' ? parse(stdout) : undefined
    ),
    Effect.orElseSucceed(() => undefined)
  );

/**
 * The Falcon sensor agent ID from the Windows registry or macOS `falconctl`.
 * `undefined` on other platforms or on any failure.
 */
const readSensorAID: Effect.Effect<string | undefined> =
  process.platform === 'win32'
    ? readCommand('reg', ['query', REG_KEY, '/v', 'AG'], guard.windowsSensorAID)
    : process.platform === 'darwin'
      ? readCommand(FALCONCTL, ['info'], guard.macSensorAID)
      : Effect.succeed(undefined);

export default Plugin.define({
  id: 'falcon-guardian',
  effect: Effect.fn(function* (ctx) {
    const config = guard.config(ctx.options, process.env);
    if (config.token instanceof Error)
      yield* Effect.logError(`Falcon Guardian: ${config.token.message}`);
    const client =
      typeof config.token === 'string'
        ? new AIGuard({
            token: config.token,
            baseURLTemplate: config.baseURL,
            timeout: config.timeoutMillis,
          })
        : undefined;
    const user = process.env.USER ?? process.env.USERNAME;
    const sensorAID = yield* readSensorAID;
    const models = new Map<string, Model.Ref>();
    const meta = (sessionID: string): guard.Meta => ({
      user,
      directory: ctx.location.directory,
      version: ctx.app.version,
      processID: process.pid,
      model: models.get(sessionID),
      sensorAID,
    });

    const ask = (request: ChatCompletionsGuard) =>
      client === undefined
        ? Effect.fail(config.token)
        : Effect.tryPromise({
            try: (signal) => client.guardChatCompletions(request, { signal }),
            catch: unwrap,
          }).pipe(
            Effect.timeoutOrElse({
              duration: config.timeoutMillis,
              orElse: () =>
                Effect.fail(
                  new Error(
                    `AIDR gave no verdict within ${config.timeoutMillis} ms`
                  )
                ),
            }),
            Effect.flatMap((res) =>
              res.status === 'Success'
                ? attempt(() => guard.verdict(res))
                : Effect.fail(
                    new Error(
                      `AIDR returned ${res.status}: ${res.summary ?? ''}`
                    )
                  )
            )
          );

    /** Build the request, get the verdict, and apply it. */
    const guarded = <A>(
      build: () => ChatCompletionsGuard,
      apply: (verdict: guard.Verdict) => A
    ) =>
      attempt(build).pipe(
        Effect.flatMap(ask),
        Effect.flatMap((verdict) => attempt(() => apply(verdict))),
        Effect.catchCause((cause) => {
          const error = Cause.squash(cause);
          return Effect.logWarning('Falcon Guardian: no verdict', cause).pipe(
            Effect.as(
              apply(
                guard.failure(
                  config.failureMode,
                  error instanceof Error ? error.message : error
                )
              )
            )
          );
        })
      );

    // The prompt and execute.after hooks have no error channel, so a block is a
    // defect. OpenCode then fails the prompt request or the turn.
    const die = (reason: string | undefined) =>
      reason === undefined ? Effect.void : Effect.die(new Error(reason));

    yield* ctx.session.hook('context', (event) =>
      Effect.sync(() => void models.set(event.sessionID, event.model))
    );

    yield* ctx.session.hook('prompt', (event) =>
      guarded(
        () => guard.promptRequest(event, meta(event.sessionID)),
        (verdict) => guard.applyToPrompt(event, verdict)
      ).pipe(Effect.flatMap(die))
    );

    yield* ctx.tool.hook('execute.before', (event) =>
      guarded(
        () => guard.toolInputRequest(event, meta(event.sessionID)),
        (verdict) => guard.applyToToolInput(event, verdict)
      ).pipe(
        Effect.flatMap((reason) =>
          reason === undefined
            ? Effect.void
            : Effect.fail(new Tool.Error({ message: reason }))
        )
      )
    );

    yield* ctx.tool.hook('execute.after', (event) =>
      event.status === 'completed'
        ? guarded(
            () => guard.toolOutputRequest(event, meta(event.sessionID)),
            (verdict) => guard.applyToToolOutput(event, verdict)
          ).pipe(Effect.flatMap(die))
        : Effect.void
    );
  }),
});
