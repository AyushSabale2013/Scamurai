import "@testing-library/jest-dom/vitest";

const NativeRequest = globalThis.Request;
// @ts-ignore
globalThis.Request = class Request extends NativeRequest {
  constructor(input: any, init?: any) {
    if (init && init.signal) {
      try {
        super(input, init);
      } catch {
        const { signal, ...rest } = init;
        super(input, rest);
      }
    } else {
      super(input, init);
    }
  }
};



