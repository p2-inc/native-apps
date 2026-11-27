import { useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from 'react';
import {
  errorMessage,
  type Challenge,
  type ChallengeAnswer,
  type LoginControllerOptions,
  type LoginParameters,
  type LoginResult,
  type LoginState,
  type LoginStrings,
  type StepUpRequest,
} from '@p2-inc/keycloak-web';
import { defaultChallengeComponents, type ChallengeComponents, type ChallengeProps } from './challenges';
import { useKeycloakContext } from './context';
import { useLogin, type UseLoginResult } from './useLogin';

export interface LoginViewProps {
  /** Replaces the default component of some challenge types. */
  components?: Partial<ChallengeComponents>;
  /** Replaces some default strings for this component only. */
  strings?: Partial<LoginStrings>;
  /** Called once with the outcome. Authorized credentials are already stored. */
  onResult?: (result: LoginResult) => void;
  /** Shown above the challenge: defaults to "Sign in" / the signing-in-as line. */
  title?: ReactNode;
  /** Rendered instead of the built-in layout, with everything it would use. */
  render?: (props: LoginRenderProps) => ReactNode;
  /** Run the passkey prompt as soon as a passkey is offered. Default `false`. */
  autoSelectPasskey?: boolean;
  /** Offer discoverable passkeys in the username field's autofill. Default `true`. */
  passkeyAutofill?: boolean;
  /** Show the cancel button. Default `true` for step-ups and actions, `false` for a login. */
  showCancel?: boolean;
  className?: string;
}

export interface LoginRenderProps extends UseLoginResult {
  strings: LoginStrings;
  /** The component for the selected challenge, ready to render. */
  challengeView: ReactNode;
  /** The other entries of the set ("Try another way"). */
  alternatives: Challenge[];
}

/**
 * The sign-in UI with no styles: semantic HTML and `data-kc-part` attributes to style, every
 * challenge type replaceable through `components`. Renders the flow Keycloak sends; change the flow
 * in the admin console and this follows without a release.
 */
export function SignIn(props: LoginViewProps & { parameters?: LoginParameters }) {
  return <LoginView {...props} options={{ mode: { kind: 'login', ...(props.parameters && { parameters: props.parameters }) } }} />;
}

/**
 * A step-up inside the current session (spec/03 §5): asks only for what `acrValues` still needs, or
 * every factor again with `maxAge: 0`.
 */
export function StepUp(props: LoginViewProps & { acrValues?: string; maxAge?: number; parameters?: LoginParameters }) {
  const parameters: LoginParameters = {
    ...props.parameters,
    ...(props.acrValues !== undefined && { acrValues: props.acrValues }),
    ...(props.maxAge !== undefined && { maxAge: props.maxAge }),
  };
  return <LoginView showCancel {...props} options={{ mode: { kind: 'stepUp', parameters } }} />;
}

/**
 * An application-initiated action (spec/21): `UPDATE_PASSWORD`, `VERIFY_EMAIL`,
 * `webauthn-register-passwordless`, `phasetwo-configure-pin`… The user proves who they are first when
 * the last authentication is too old; `onResult` carries `kcActionStatus`.
 */
export function RequiredAction(props: LoginViewProps & { alias: string; parameters?: LoginParameters }) {
  return (
    <LoginView
      showCancel
      {...props}
      options={{ mode: { kind: 'requiredAction', alias: props.alias, ...(props.parameters && { parameters: props.parameters }) } }}
    />
  );
}

function LoginView(props: LoginViewProps & { options: LoginControllerOptions }) {
  const context = useKeycloakContext();
  const strings = useMemo(() => ({ ...context.strings, ...props.strings }), [context.strings, props.strings]);
  const login = useLogin({
    ...props.options,
    ...(props.autoSelectPasskey !== undefined && { autoSelectPasskey: props.autoSelectPasskey }),
    ...(props.passkeyAutofill !== undefined && { passkeyAutofill: props.passkeyAutofill }),
    ...(props.onResult && { onResult: props.onResult }),
  });
  const { controller, state } = login;
  const components = useMemo(() => ({ ...defaultChallengeComponents, ...props.components }), [props.components]);
  const submit = useCallback(
    (answer: ChallengeAnswer) => {
      const phase = controller.state.phase;
      return phase.kind === 'challenges' ? controller.submit(answer, phase.selected) : Promise.resolve();
    },
    [controller]
  );

  const phase = state.phase;
  let challengeView: ReactNode = null;
  let alternatives: Challenge[] = [];
  if (phase.kind === 'challenges') {
    const Component = components[phase.selected.type] as ComponentType<ChallengeProps>;
    challengeView = (
      <Component
        key={`${phase.selected.id}:${phase.selected.wireType}`}
        challenge={phase.selected as ChallengeProps['challenge']}
        challenges={phase.challenges}
        context={phase.context}
        controller={controller}
        strings={strings}
        isSubmitting={state.isSubmitting}
        submit={submit}
      />
    );
    // A username field already offers its passkey: don't list that passkey again.
    const combined = phase.selected.type === 'username';
    alternatives = phase.challenges.filter(
      (c) => c !== phase.selected && c.supported && !(combined && c.type === 'passkey')
    );
  }
  if (props.render) return <>{props.render({ ...login, strings, challengeView, alternatives })}</>;

  const showCancel = props.showCancel ?? props.options.mode?.kind !== 'login';
  return (
    <div data-kc-root="" data-kc-phase={phase.kind} data-kc-submitting={state.isSubmitting ? '' : undefined} className={props.className} aria-busy={state.isSubmitting}>
      <Header state={state} strings={strings} title={props.title} />
      {state.messageCode && (
        <p data-kc-part="message" role="alert">
          {errorMessage(strings, state.messageCode, state.message)}
        </p>
      )}
      {phase.kind === 'starting' && <p data-kc-part="status">{strings.contactingServer}</p>}
      {challengeView}
      {phase.kind === 'redirectToWeb' && (
        <div data-kc-part="form" data-kc-challenge="redirect_to_web">
          <p data-kc-part="description">{strings.completeInPopup}</p>
          <button data-kc-part="submit" type="button" disabled={state.isSubmitting} onClick={() => void controller.openBrowser()}>
            {strings.openWindow}
          </button>
        </div>
      )}
      {alternatives.length > 0 && (
        <div data-kc-part="alternatives" role="group" aria-label={strings.tryAnotherWay}>
          <p data-kc-part="alternatives-title">{strings.tryAnotherWay}</p>
          {alternatives.map((c) => (
            <button key={`${c.id}:${c.wireType}`} data-kc-part="alternative" data-kc-challenge={c.wireType} type="button" disabled={state.isSubmitting} onClick={() => controller.select(c)}>
              {c.label ?? strings.alternative(c.wireType)}
            </button>
          ))}
        </div>
      )}
      {/* A skippable required action has its own "Not now"/"Cancel": don't show a second one. */}
      {showCancel && phase.kind !== 'finished' && !(phase.kind === 'challenges' && phase.selected.skippable) && (
        <button data-kc-part="cancel" type="button" onClick={() => void controller.cancel()}>
          {strings.cancel}
        </button>
      )}
    </div>
  );
}

function Header({ state, strings, title }: { state: LoginState; strings: LoginStrings; title: ReactNode }) {
  const phase = state.phase;
  const name = phase.kind === 'challenges' ? (phase.context.displayName ?? phase.context.username) : undefined;
  return (
    <div data-kc-part="header">
      <h2 data-kc-part="title">{title ?? strings.signIn}</h2>
      {name && <p data-kc-part="subtitle">{strings.signingInAs(name)}</p>}
    </div>
  );
}

export interface StepUpBoundaryProps {
  /**
   * Renders the step-up UI when `kc.fetch` meets an RFC 9470 challenge. Default: a modal `<dialog>`
   * with `<StepUp>`. Call `done(true)` when it succeeded (the request is retried), `done(false)`
   * otherwise.
   */
  renderStepUp?: (request: StepUpRequest, done: (succeeded: boolean) => void) => ReactNode;
  children: ReactNode;
}

/**
 * Lets `kc.fetch` step up: when a resource server answers `insufficient_user_authentication`, this
 * shows a step-up for the requested level and retries the request once it succeeded.
 */
export function StepUpBoundary({ renderStepUp, children }: StepUpBoundaryProps) {
  const { kc } = useKeycloakContext();
  const [pending, setPending] = useState<{ request: StepUpRequest; resolve: (ok: boolean) => void } | undefined>();
  const pendingRef = useRef(pending);
  pendingRef.current = pending;
  useEffect(() => {
    kc.setStepUpHandler(
      (request) =>
        new Promise<boolean>((resolve) => {
          // One step-up at a time: a second request waits for the first's outcome.
          if (pendingRef.current !== undefined) {
            const previous = pendingRef.current.resolve;
            pendingRef.current.resolve = (ok) => {
              previous(ok);
              resolve(ok);
            };
            return;
          }
          setPending({ request, resolve });
        })
    );
    return () => kc.setStepUpHandler(undefined);
  }, [kc]);
  const done = useCallback((ok: boolean) => {
    const current = pendingRef.current;
    setPending(undefined);
    current?.resolve(ok);
  }, []);
  return (
    <>
      {children}
      {pending &&
        (renderStepUp ? (
          renderStepUp(pending.request, done)
        ) : (
          <DialogStepUp request={pending.request} done={done} />
        ))}
    </>
  );
}

function DialogStepUp({ request, done }: { request: StepUpRequest; done: (ok: boolean) => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (dialog && typeof dialog.showModal === 'function' && !dialog.open) dialog.showModal();
  }, []);
  return (
    <dialog ref={ref} data-kc-part="step-up-dialog" onCancel={() => done(false)}>
      <StepUp
        {...(request.acrValues !== undefined && { acrValues: request.acrValues })}
        {...(request.maxAge !== undefined && { maxAge: request.maxAge })}
        onResult={(r) => done(r.kind === 'authorized')}
      />
    </dialog>
  );
}
