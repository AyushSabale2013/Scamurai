import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "../app/router";
import { RecentProvider } from "../hooks/recent";
import { prediction, summary } from "./fixtures";

const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));

function mockApi(predict: () => Promise<Response>) {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/health")) return json({ status: "ok", model_loaded: true, model_version: "1.0.0-test", detail: null });
    if (url.endsWith("/api/analytics/summary")) return json(summary);
    if (url.endsWith("/api/model-info")) return json({ feature_definitions: {} });
    if (url.endsWith("/api/predict")) return predict();
    if (url.endsWith("/api/predict/batch")) return json({ model_version: "v", threshold: 0.3, total: 0, ok: 0, invalid: 0, results: [], disclaimer: "" });
    return json({ error: { code: "not_found", message: "nope" } }, 404);
  }));
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><RecentProvider><RouterProvider router={router} /></RecentProvider></QueryClientProvider>);
}

beforeEach(() => mockApi(() => json(prediction)));
afterEach(() => vi.unstubAllGlobals());

describe("navigation", () => {
  it("shows every page in the sidebar and navigates between them", async () => {
    const user = userEvent.setup();
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "Security Overview" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    for (const name of ["Overview", "URL Analyzer", "Batch Analysis", "Model Lab", "Dataset Explorer", "About & Methodology"]) {
      expect(nav).toHaveTextContent(name);
    }
    await user.click(screen.getAllByRole("link", { name: "URL Analyzer" })[0]);
    expect(await screen.findByRole("heading", { name: "URL Analyzer" })).toBeInTheDocument();
    await user.click(screen.getAllByRole("link", { name: "Batch Analysis" })[0]);
    expect(await screen.findByRole("heading", { name: "Batch Analysis" })).toBeInTheDocument();
  });

  it("opens and closes the mobile menu with correct aria state", async () => {
    const user = userEvent.setup();
    renderAt("/about");
    const open = await screen.findByRole("button", { name: "Open menu" });
    expect(open).toHaveAttribute("aria-expanded", "false");
    await user.click(open);
    expect(screen.getByRole("dialog", { name: "Navigation" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});

describe("URL analyzer", () => {
  it("validates input before calling the API", async () => {
    const user = userEvent.setup();
    renderAt("/analyzer");
    await user.click(await screen.findByRole("button", { name: /analyze/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/enter a url/i);
    await user.type(screen.getByLabelText("URL to analyze"), "ftp://x.com");
    await user.click(screen.getByRole("button", { name: /analyze/i }));
    expect(screen.getByRole("alert")).toHaveTextContent(/http/i);
    expect((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.some(([u]) => String(u).endsWith("/api/predict"))).toBe(false);
  });

  it("shows a loading state, then the real response, and submits with Enter", async () => {
    let release!: () => void;
    mockApi(() => new Promise((res) => { release = () => res(new Response(JSON.stringify(prediction), { status: 200 })); }));
    const user = userEvent.setup();
    renderAt("/analyzer");
    await user.type(await screen.findByLabelText("URL to analyze"), "http://secure-login.xyz/verify/account.php?id=7{Enter}");
    expect(await screen.findByRole("button", { name: /analyzing/i })).toBeDisabled();
    release();
    expect(await screen.findByText("Potential phishing URL")).toBeInTheDocument();
    expect(screen.getByText("98.7%")).toBeInTheDocument();
    expect(screen.getByText("Uses HTTPS")).toBeInTheDocument();
    expect(screen.getAllByText(/estimates, not guarantees|are estimates/i).length).toBeGreaterThan(0);
    expect(screen.getByText("This URL has a path or query")).toBeInTheDocument(); // dataset-driven caution
  });

  it("shows an error and never fabricates a result when the API fails", async () => {
    mockApi(() => json({ error: { code: "invalid_url", message: "URL has no hostname." } }, 422));
    const user = userEvent.setup();
    renderAt("/analyzer");
    await user.type(await screen.findByLabelText("URL to analyze"), "http://x.com");
    await user.click(screen.getByRole("button", { name: /analyze/i }));
    expect(await screen.findByText("URL has no hostname.")).toBeInTheDocument();
    expect(screen.queryByText("Potential phishing URL")).not.toBeInTheDocument();
  });

  it("explains an unreachable backend", async () => {
    mockApi(() => Promise.reject(new TypeError("Failed to fetch")));
    const user = userEvent.setup();
    renderAt("/analyzer");
    await user.type(await screen.findByLabelText("URL to analyze"), "http://x.com");
    await user.click(screen.getByRole("button", { name: /analyze/i }));
    expect(await screen.findByText(/cannot reach the phishguard api/i)).toBeInTheDocument();
  });
});

describe("batch analysis", () => {
  it("shows an empty state before any run", async () => {
    renderAt("/batch");
    expect(await screen.findByText("No results yet")).toBeInTheDocument();
  });

  it("rejects empty input, oversized lists, bad files and empty files", async () => {
    const user = userEvent.setup({ applyAccept: false });
    renderAt("/batch");
    await user.click(await screen.findByRole("button", { name: "Analyze URLs" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/no urls found/i);

    const box = screen.getByLabelText("URLs, one per line");
    await user.click(box);
    await user.paste(Array.from({ length: 101 }, (_, i) => `https://e${i}.com`).join("\n"));
    await user.click(screen.getByRole("button", { name: "Analyze URLs" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/limited to 100/i);

    const input = document.getElementById("batch-file") as HTMLInputElement;
    await user.upload(input, new File(["x"], "pic.png", { type: "image/png" }));
    expect(await screen.findByText(/unsupported file type/i)).toBeInTheDocument();
    await user.upload(input, new File([""], "empty.csv", { type: "text/csv" }));
    expect(await screen.findByText(/contains no urls/i)).toBeInTheDocument();
  });
});

describe("overview empty state", () => {
  it("shows a helpful empty state for recent analyses", async () => {
    renderAt("/");
    expect(await screen.findByText("Nothing analyzed in this session")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Start an analysis" })).toBeInTheDocument();
  });
});
