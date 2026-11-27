import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { LoginController, type LoginControllerOptions, type LoginState } from '@p2-inc/keycloak-web';
import { useKeycloakContext } from './context';

export interface UseLoginResult {
  controller: LoginController;
  state: LoginState;
}

/**
 * A `LoginController` for this component, started on mount, plus its state. The building block of
 * `<SignIn>`, `<StepUp>` and `<RequiredAction>`, and of any login UI you build yourself.
 * `onResult` is read when the result arrives, so it may change between renders.
 */
export function useLogin(options: LoginControllerOptions = {}): UseLoginResult {
  const { kc } = useKeycloakContext();
  const onResult = useRef(options.onResult);
  onResult.current = options.onResult;
  const [controller] = useState(
    () => new LoginController(kc, { ...options, onResult: (r) => onResult.current?.(r) })
  );
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  useEffect(() => {
    void controller.start();
    controller.resume();
    return () => controller.dispose();
  }, [controller]);
  return { controller, state };
}
