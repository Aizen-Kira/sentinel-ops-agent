import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { TextDecoder, TextEncoder } from "util";
import { afterEach, vi } from "vitest";

Object.defineProperty(globalThis, "TextEncoder", {
  writable: true,
  value: TextEncoder,
});

Object.defineProperty(globalThis, "TextDecoder", {
  writable: true,
  value: TextDecoder,
});

afterEach(() => {
  cleanup();
});

if (typeof window !== "undefined") {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });

  Object.defineProperty(window, "scrollTo", {
    writable: true,
    value: vi.fn(),
  });
}
